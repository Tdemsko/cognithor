"""SQLite index management · FTS5 + entities + relations + vectors. [B§4.7]

Central database for all memory indexes.
Everything derivable from the Markdown source-of-truth files.

Thread-Safety:
SQLite im WAL-Modus unterstuetzt gleichzeitige Reads, aber nur einen
Writer. Bei Multi-Channel-Betrieb (z.B. Telegram + CLI + Cron) koennen
gleichzeitige Writes zu "database is locked" Fehlern fuehren.

Loesung: Alle Write-Operationen werden ueber ein threading.RLock
serialisiert. Reads benoetigen kein Lock (WAL erlaubt concurrent reads).
RLock statt Lock, da manche Write-Methoden intern andere Write-Methoden
aufrufen (z.B. delete_entity → DELETE relations + DELETE entities).
"""

from __future__ import annotations

import json
import sqlite3
import struct
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from cognithor.db import SQLITE_BUSY_TIMEOUT_MS
from cognithor.memory.trust import resolve_project_id, validate_chunk_provenance
from cognithor.models import Chunk, Entity, MemoryTier, Relation
from cognithor.security.encrypted_db import encrypted_connect

try:
    from cognithor.security.encrypted_db import compatible_row_factory
except ImportError:

    def compatible_row_factory() -> Any:
        return sqlite3.Row


def _serialize_vector(vec: list[float]) -> bytes:
    """Serialisiert einen Float-Vektor zu Bytes (fuer sqlite-vec Kompatibilitaet)."""
    return struct.pack(f"{len(vec)}f", *vec)


def _deserialize_vector(data: bytes) -> list[float]:
    """Deserialisiert Bytes zurueck zu Float-Vektor."""
    n = len(data) // 4
    return list(struct.unpack(f"{n}f", data))


class MemoryIndex:
    """SQLite-basierter Index fuer das Memory-System.

    Schema:
    - chunks: Alle Text-Chunks mit Metadaten
    - chunks_fts: FTS5 Volltextsuche (BM25)
    - embeddings: Vektor-Embeddings (content_hash → vector)
    - entities: Wissens-Graph Entitaeten
    - relations: Beziehungen zwischen Entitaeten
    """

    def __init__(self, db_path: str | Path) -> None:
        """Initialisiert den Memory-Index mit SQLite-Datenbank."""
        self._db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None
        self._write_lock = threading.RLock()

    @property
    def db_path(self) -> Path:
        """Return the path to the SQLite database."""
        return self._db_path

    @property
    def conn(self) -> sqlite3.Connection:
        """Lazy connection. Create DB on first access.

        Thread-safe: Connection-Erstellung ist ueber das Write-Lock geschuetzt,
        da _init_schema() Schreiboperationen ausfuehrt.
        """
        if self._conn is None:
            with self._write_lock:
                # Double-check nach Lock-Erwerb (ein anderer Thread
                # koennte die Connection inzwischen erstellt haben)
                if self._conn is None:
                    self._db_path.parent.mkdir(parents=True, exist_ok=True)
                    self._conn = encrypted_connect(str(self._db_path), check_same_thread=False)
                    self._conn.row_factory = compatible_row_factory()
                    self._conn.execute("PRAGMA journal_mode=WAL")
                    self._conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
                    self._conn.execute("PRAGMA foreign_keys=ON")
                    self._init_schema()
        return self._conn

    def _init_schema(self) -> None:
        """Create all tables and indexes."""
        c = self.conn
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS chunks (
                id TEXT PRIMARY KEY,
                text TEXT NOT NULL,
                source_path TEXT NOT NULL,
                line_start INTEGER DEFAULT 0,
                line_end INTEGER DEFAULT 0,
                content_hash TEXT NOT NULL,
                memory_tier TEXT NOT NULL,
                timestamp REAL,
                token_count INTEGER DEFAULT 0,
                entities_json TEXT DEFAULT '[]',
                project_id TEXT NOT NULL DEFAULT 'default',
                source_type TEXT NOT NULL DEFAULT 'legacy',
                source_id TEXT NOT NULL DEFAULT '',
                source_trust TEXT NOT NULL DEFAULT 'legacy_unscoped',
                instruction_authority INTEGER NOT NULL DEFAULT 0,
                provenance_hash TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL
            )
            """
        )
        migrated_chunks = self._ensure_chunk_trust_schema()
        c.executescript(
            """
            -- Chunks (alle Memory-Tiers)
            CREATE INDEX IF NOT EXISTS idx_chunks_source ON chunks(source_path);
            CREATE INDEX IF NOT EXISTS idx_chunks_tier ON chunks(memory_tier);
            CREATE INDEX IF NOT EXISTS idx_chunks_hash ON chunks(content_hash);
            CREATE INDEX IF NOT EXISTS idx_chunks_created_at ON chunks(created_at);
            CREATE INDEX IF NOT EXISTS idx_chunks_tier_created ON chunks(memory_tier, created_at);

            -- FTS5 Volltextsuche (BM25)
            CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
                text,
                content='chunks',
                content_rowid='rowid',
                tokenize='unicode61 remove_diacritics 2'
            );

            -- Trigger fuer FTS5 Sync
            CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
                INSERT INTO chunks_fts(rowid, text) VALUES (new.rowid, new.text);
            END;

            CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
                INSERT INTO chunks_fts(chunks_fts, rowid, text)
                VALUES('delete', old.rowid, old.text);
            END;

            CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
                INSERT INTO chunks_fts(chunks_fts, rowid, text)
                VALUES('delete', old.rowid, old.text);
                INSERT INTO chunks_fts(rowid, text)
                VALUES (new.rowid, new.text);
            END;

            -- Embeddings (content_hash → Vektor)
            CREATE TABLE IF NOT EXISTS embeddings (
                content_hash TEXT PRIMARY KEY,
                vector BLOB NOT NULL,
                model_name TEXT NOT NULL,
                dimensions INTEGER NOT NULL,
                created_at REAL NOT NULL
            );

            -- Entitaeten (Wissens-Graph)
            CREATE TABLE IF NOT EXISTS entities (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                attributes_json TEXT DEFAULT '{}',
                source_file TEXT DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                confidence REAL DEFAULT 1.0,
                project_id TEXT NOT NULL DEFAULT 'default'
            );

            CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);
            CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(name);
            CREATE INDEX IF NOT EXISTS idx_entities_source ON entities(source_file);

            -- Relationen
            CREATE TABLE IF NOT EXISTS relations (
                id TEXT PRIMARY KEY,
                source_entity TEXT NOT NULL REFERENCES entities(id),
                relation_type TEXT NOT NULL,
                target_entity TEXT NOT NULL REFERENCES entities(id),
                attributes_json TEXT DEFAULT '{}',
                source_file TEXT DEFAULT '',
                created_at REAL NOT NULL,
                confidence REAL DEFAULT 1.0,
                project_id TEXT NOT NULL DEFAULT 'default'
            );

            CREATE INDEX IF NOT EXISTS idx_relations_type ON relations(relation_type);
            CREATE INDEX IF NOT EXISTS idx_relations_source ON relations(source_entity);
            CREATE INDEX IF NOT EXISTS idx_relations_target ON relations(target_entity);
        """
        )
        self._ensure_graph_project_schema()
        if migrated_chunks:
            c.execute("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')")
            c.commit()

    def _ensure_graph_project_schema(self) -> None:
        """Idempotently bind graph entities and relations to projects."""
        for table in ("entities", "relations"):
            columns = {
                row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if "project_id" not in columns:
                self.conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default'"
                )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_entities_project_name
            ON entities(project_id, name)
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_relations_project_source
            ON relations(project_id, source_entity)
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_relations_project_target
            ON relations(project_id, target_entity)
            """
        )
        self.conn.commit()

    def _ensure_chunk_trust_schema(self) -> bool:
        """Idempotently migrate legacy indexes to the project/trust contract."""
        columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(chunks)").fetchall()}
        additions = {
            "project_id": "TEXT NOT NULL DEFAULT 'default'",
            "source_type": "TEXT NOT NULL DEFAULT 'legacy'",
            "source_id": "TEXT NOT NULL DEFAULT ''",
            "source_trust": "TEXT NOT NULL DEFAULT 'legacy_unscoped'",
            "instruction_authority": "INTEGER NOT NULL DEFAULT 0",
            "provenance_hash": "TEXT NOT NULL DEFAULT ''",
        }
        migrated = False
        for name, declaration in additions.items():
            if name not in columns:
                self.conn.execute(f"ALTER TABLE chunks ADD COLUMN {name} {declaration}")
                migrated = True
        self.conn.execute(
            """
            UPDATE chunks
            SET source_id = source_path
            WHERE source_id IS NULL OR source_id = ''
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_chunks_project_source
            ON chunks(project_id, source_path)
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_chunks_project_tier
            ON chunks(project_id, memory_tier)
            """
        )
        self.conn.commit()
        return migrated

    # ── Chunk Operations ─────────────────────────────────────────

    def upsert_chunk(
        self,
        chunk: Chunk,
        *,
        provenance_source_type: str | None = None,
        provenance_source_id: str | None = None,
        provenance_notes: str = "",
    ) -> None:
        """Fuegt einen Chunk ein oder aktualisiert ihn und committet.

        Thread-safe: Geschuetzt ueber Write-Lock.

        Optional TRUST-9 provenance: when both
        ``provenance_source_type`` and ``provenance_source_id`` are
        passed, a tag is written to the canonical
        ``PROVENANCE_LEDGER`` keyed by ``chunk:<chunk.id>``. Lets
        the operational-trust receipt answer "where did the
        knowledge in this chunk come from?" — owner-uploaded PDF,
        agent-fetched URL, scheduled cron import — for every chunk
        that opted into provenance at indexing time.
        """
        with self._write_lock:
            self._upsert_chunk_impl(chunk)
            self.conn.commit()
        if provenance_source_type and provenance_source_id:
            self._tag_provenance(
                item_id=f"chunk:{chunk.id}",
                source_type_value=provenance_source_type,
                source_id=provenance_source_id,
                notes=provenance_notes,
            )

    @staticmethod
    def _tag_provenance(
        *,
        item_id: str,
        source_type_value: str,
        source_id: str,
        notes: str,
    ) -> None:
        """Best-effort TRUST-9 provenance tag — failures swallowed.

        Unknown ``source_type_value`` is coerced to
        :data:`SourceType.UNKNOWN`. Indexing NEVER fails because of
        provenance tagging.
        """
        from cognithor.memory.provenance import (
            PROVENANCE_LEDGER,
            ProvenanceTag,
            SourceType,
        )

        try:
            try:
                source_type = SourceType(source_type_value)
            except ValueError:
                source_type = SourceType.UNKNOWN
            PROVENANCE_LEDGER.tag(
                item_id,
                ProvenanceTag(
                    source_type=source_type,
                    source_id=source_id,
                    notes=notes,
                ),
            )
        except ValueError:
            pass

    def _upsert_chunk_impl(self, chunk: Chunk) -> None:
        """Internal: insert/update ohne Lock und ohne Commit (fuer Batch-Nutzung)."""
        if chunk.instruction_authority:
            raise ValueError("Durable memory chunks cannot carry instruction authority")
        validate_chunk_provenance(chunk)
        project = resolve_project_id(chunk.project_id)
        existing = self.conn.execute(
            "SELECT project_id FROM chunks WHERE id = ?",
            (chunk.id,),
        ).fetchone()
        if existing is not None and existing["project_id"] != project:
            raise ValueError("Chunk id is already owned by another project")
        now = datetime.now().timestamp()
        ts = chunk.timestamp.timestamp() if chunk.timestamp else None

        self.conn.execute(
            """
            INSERT INTO chunks (id, text, source_path, line_start, line_end,
                              content_hash, memory_tier, timestamp, token_count,
                              entities_json, project_id, source_type, source_id,
                              source_trust, instruction_authority, provenance_hash,
                              created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                text=excluded.text,
                source_path=excluded.source_path,
                line_start=excluded.line_start,
                line_end=excluded.line_end,
                content_hash=excluded.content_hash,
                memory_tier=excluded.memory_tier,
                timestamp=excluded.timestamp,
                token_count=excluded.token_count,
                entities_json=excluded.entities_json,
                project_id=excluded.project_id,
                source_type=excluded.source_type,
                source_id=excluded.source_id,
                source_trust=excluded.source_trust,
                instruction_authority=excluded.instruction_authority,
                provenance_hash=excluded.provenance_hash
            """,
            (
                chunk.id,
                chunk.text,
                chunk.source_path,
                chunk.line_start,
                chunk.line_end,
                chunk.content_hash,
                chunk.memory_tier.value,
                ts,
                chunk.token_count,
                json.dumps(chunk.entities),
                project,
                chunk.source_type,
                chunk.source_id or chunk.source_path,
                chunk.source_trust,
                int(chunk.instruction_authority),
                chunk.provenance_hash,
                now,
            ),
        )

    def upsert_chunks(self, chunks: list[Chunk]) -> int:
        """Batch-Insert von Chunks. Returns Anzahl eingefuegt.

        Thread-safe: Geschuetzt ueber Write-Lock.
        """
        now = datetime.now().timestamp()
        rows = []
        for c in chunks:
            if c.instruction_authority:
                raise ValueError("Durable memory chunks cannot carry instruction authority")
            validate_chunk_provenance(c)
            ts = c.timestamp.timestamp() if c.timestamp else None
            rows.append(
                (
                    c.id,
                    c.text,
                    c.source_path,
                    c.line_start,
                    c.line_end,
                    c.content_hash,
                    c.memory_tier.value,
                    ts,
                    c.token_count,
                    json.dumps(c.entities),
                    resolve_project_id(c.project_id),
                    c.source_type,
                    c.source_id or c.source_path,
                    c.source_trust,
                    int(c.instruction_authority),
                    c.provenance_hash,
                    now,
                )
            )

        with self._write_lock:
            for chunk in chunks:
                existing = self.conn.execute(
                    "SELECT project_id FROM chunks WHERE id = ?",
                    (chunk.id,),
                ).fetchone()
                if existing is not None and existing["project_id"] != resolve_project_id(
                    chunk.project_id
                ):
                    raise ValueError("Chunk id is already owned by another project")
            self.conn.executemany(
                """
                INSERT INTO chunks (id, text, source_path, line_start, line_end,
                                  content_hash, memory_tier, timestamp, token_count,
                                  entities_json, project_id, source_type, source_id,
                                  source_trust, instruction_authority, provenance_hash,
                                  created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    text=excluded.text,
                    source_path=excluded.source_path,
                    line_start=excluded.line_start,
                    line_end=excluded.line_end,
                    content_hash=excluded.content_hash,
                    memory_tier=excluded.memory_tier,
                    timestamp=excluded.timestamp,
                    token_count=excluded.token_count,
                    entities_json=excluded.entities_json,
                    project_id=excluded.project_id,
                    source_type=excluded.source_type,
                    source_id=excluded.source_id,
                    source_trust=excluded.source_trust,
                    instruction_authority=excluded.instruction_authority,
                    provenance_hash=excluded.provenance_hash
                """,
                rows,
            )
            self.conn.commit()
        return len(rows)

    def delete_chunks_by_source(
        self,
        source_path: str,
        *,
        project_id: str | None = None,
    ) -> int:
        """Delete one source only within the resolved project boundary."""
        project = resolve_project_id(project_id)
        with self._write_lock:
            cursor = self.conn.execute(
                "DELETE FROM chunks WHERE source_path = ? AND project_id = ?",
                (source_path, project),
            )
            self.conn.commit()
            return cursor.rowcount

    def get_chunk_by_id(
        self,
        chunk_id: str,
        *,
        project_id: str | None = None,
    ) -> Chunk | None:
        """Load a chunk only inside the resolved project boundary."""
        project = resolve_project_id(project_id)
        row = self.conn.execute(
            "SELECT * FROM chunks WHERE id = ? AND project_id = ?",
            (chunk_id, project),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_chunk(row)

    def get_chunks_by_ids(
        self,
        chunk_ids: list[str],
        *,
        project_id: str | None = None,
    ) -> dict[str, Chunk]:
        """Laedt mehrere Chunks anhand ihrer IDs in einem Batch.

        Nutzt SELECT ... WHERE id IN (...) statt einzelner Queries (N+1 vermeiden).
        Beachtet SQLite's Parameter-Limit von 999 und splittet bei Bedarf.

        Args:
            chunk_ids: Liste von Chunk-IDs.

        Returns:
            Dict mapping chunk_id → Chunk. Fehlende IDs werden ausgelassen.
        """
        if not chunk_ids:
            return {}
        project = resolve_project_id(project_id)

        result: dict[str, Chunk] = {}
        # SQLite hat ein Standard-Limit von 999 Parametern pro Query
        batch_size = 998

        for i in range(0, len(chunk_ids), batch_size):
            batch = chunk_ids[i : i + batch_size]
            placeholders = ",".join("?" for _ in batch)
            rows = self.conn.execute(
                f"SELECT * FROM chunks WHERE id IN ({placeholders}) AND project_id = ?",
                [*batch, project],
            ).fetchall()
            for row in rows:
                result[row["id"]] = self._row_to_chunk(row)

        return result

    def get_chunks_by_source(
        self,
        source_path: str,
        *,
        project_id: str | None = None,
    ) -> list[Chunk]:
        """Return one source only inside the resolved project boundary."""
        project = resolve_project_id(project_id)
        rows = self.conn.execute(
            """
            SELECT * FROM chunks
            WHERE source_path = ? AND project_id = ?
            ORDER BY line_start
            """,
            (source_path, project),
        ).fetchall()
        return [self._row_to_chunk(r) for r in rows]

    def get_chunk_ids_by_hash(
        self,
        content_hash: str,
        *,
        project_id: str | None = None,
    ) -> list[str]:
        """Chunk-IDs fuer einen Content-Hash (fuer inkrementelle Hash-Map-Updates)."""
        project = resolve_project_id(project_id)
        rows = self.conn.execute(
            "SELECT id FROM chunks WHERE content_hash = ? AND project_id = ?",
            (content_hash, project),
        ).fetchall()
        return [r["id"] for r in rows]

    def get_all_content_hashes(self, *, project_id: str | None = None) -> set[str]:
        """Alle content_hashes im Index (fuer Embedding-Cache)."""
        project = resolve_project_id(project_id)
        rows = self.conn.execute(
            "SELECT DISTINCT content_hash FROM chunks WHERE project_id = ?",
            (project,),
        ).fetchall()
        return {r["content_hash"] for r in rows}

    def count_chunks(
        self,
        tier: MemoryTier | None = None,
        *,
        project_id: str | None = None,
    ) -> int:
        """Zaehlt Chunks, optional gefiltert nach Tier."""
        project = resolve_project_id(project_id)
        if tier:
            row = self.conn.execute(
                """
                SELECT COUNT(*) as cnt FROM chunks
                WHERE memory_tier = ? AND project_id = ?
                """,
                (tier.value, project),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM chunks WHERE project_id = ?",
                (project,),
            ).fetchone()
        return row["cnt"] if row else 0

    def list_chunks(
        self,
        *,
        tier: MemoryTier | None = None,
        project_id: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[Chunk]:
        """List recent chunks inside one project boundary.

        This is intentionally not a global administrative iterator.  Model
        tools use it for project-scoped episodic/procedural reads without
        falling back to the legacy shared filesystem stores.
        """
        project = resolve_project_id(project_id)
        conditions = ["project_id = ?"]
        params: list[Any] = [project]
        if tier is not None:
            conditions.append("memory_tier = ?")
            params.append(tier.value)
        if since is not None:
            conditions.append("COALESCE(timestamp, created_at) >= ?")
            params.append(since.timestamp())
        bounded_limit = max(1, min(limit, 1000))
        params.append(bounded_limit)
        rows = self.conn.execute(
            "SELECT * FROM chunks "
            f"WHERE {' AND '.join(conditions)} "
            "ORDER BY COALESCE(timestamp, created_at) DESC, id ASC LIMIT ?",
            params,
        ).fetchall()
        return [self._row_to_chunk(row) for row in rows]

    # ── BM25 Search ──────────────────────────────────────────────

    def search_bm25(
        self,
        query: str,
        top_k: int = 10,
        *,
        project_id: str | None = None,
    ) -> list[tuple[str, float]]:
        """FTS5 BM25 Suche.

        Args:
            query: Suchbegriffe.
            top_k: Maximale Ergebnisse.

        Returns:
            Liste von (chunk_id, bm25_score) Tupeln.
            Score ist negativ (FTS5 Konvention), wird hier positiv gemacht.
        """
        if not query.strip():
            return []
        project = resolve_project_id(project_id)

        # FTS5 Query: Woerter mit OR verbinden, Prefix-Match fuer deutsche Komposita
        # Sanitize: strip FTS5 operators/special chars to prevent query injection
        import re

        _fts_clean = re.compile(r'["\(\)\*\:\^]')
        words = [_fts_clean.sub("", w) for w in query.strip().split()]
        words = [w for w in words if w and w.upper() not in ("AND", "OR", "NOT", "NEAR")]
        if not words:
            return []
        # Jedes Wort bekommt Prefix-Match (*) fuer bessere Treffer bei Komposita
        fts_query = " OR ".join(f'"{w}"*' for w in words)

        try:
            rows = self.conn.execute(
                """
                SELECT c.id, rank
                FROM chunks_fts fts
                JOIN chunks c ON c.rowid = fts.rowid
                WHERE chunks_fts MATCH ? AND c.project_id = ?
                ORDER BY rank
                LIMIT ?
                """,
                (fts_query, project, top_k),
            ).fetchall()
        except sqlite3.OperationalError:
            # Fallback bei ungueltiger FTS-Query
            return []

        # FTS5 rank ist negativ (kleiner = besser), wir machen ihn positiv
        return [(r["id"], -r["rank"]) for r in rows]

    # ── Embedding Operations ─────────────────────────────────────

    def store_embedding(
        self,
        content_hash: str,
        vector: list[float],
        model_name: str = "qwen3-embedding:0.6b",
    ) -> None:
        """Save an embedding. Thread-safe."""
        now = datetime.now().timestamp()
        with self._write_lock:
            self.conn.execute(
                """
                INSERT INTO embeddings (content_hash, vector, model_name, dimensions, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(content_hash) DO UPDATE SET
                    vector=excluded.vector,
                    model_name=excluded.model_name,
                    dimensions=excluded.dimensions
                """,
                (content_hash, _serialize_vector(vector), model_name, len(vector), now),
            )
            self.conn.commit()

    def get_embedding(self, content_hash: str) -> list[float] | None:
        """Laedt ein Embedding anhand des Content-Hash."""
        row = self.conn.execute(
            "SELECT vector FROM embeddings WHERE content_hash = ?",
            (content_hash,),
        ).fetchone()
        if row is None:
            return None
        return _deserialize_vector(row["vector"])

    def get_all_embeddings(self) -> dict[str, list[float]]:
        """Laedt alle Embeddings. Returns {content_hash: vector}."""
        rows = self.conn.execute("SELECT content_hash, vector FROM embeddings").fetchall()
        return {r["content_hash"]: _deserialize_vector(r["vector"]) for r in rows}

    def get_embeddings_by_hashes(
        self,
        content_hashes: set[str],
    ) -> dict[str, list[float]]:
        """Laedt nur Embeddings fuer die angegebenen Hashes (statt alle).

        Deutlich RAM-effizienter als get_all_embeddings() wenn nur wenige
        Hashes geprueft werden muessen.
        """
        if not content_hashes:
            return {}
        result: dict[str, list[float]] = {}
        # SQLite hat ein SQLITE_MAX_VARIABLE_NUMBER Limit (default 999).
        # Batch in Gruppen von 900 um sicher zu bleiben.
        hash_list = list(content_hashes)
        for i in range(0, len(hash_list), 900):
            batch = hash_list[i : i + 900]
            placeholders = ",".join("?" * len(batch))
            rows = self.conn.execute(
                f"SELECT content_hash, vector FROM embeddings "
                f"WHERE content_hash IN ({placeholders})",
                batch,
            ).fetchall()
            for r in rows:
                result[r["content_hash"]] = _deserialize_vector(r["vector"])
        return result

    def get_embedding_hashes(self) -> set[str]:
        """Return all content_hashes that have an embedding (without loading vectors)."""
        rows = self.conn.execute("SELECT content_hash FROM embeddings").fetchall()
        return {r["content_hash"] for r in rows}

    def count_embeddings(self) -> int:
        """Anzahl gespeicherter Embeddings."""
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM embeddings").fetchone()
        return row["cnt"] if row else 0

    # ── Entity Operations ────────────────────────────────────────

    def upsert_entity(self, entity: Entity) -> None:
        """Fuegt eine Entitaet ein oder aktualisiert sie. Thread-safe."""
        project = resolve_project_id(entity.project_id or None)
        with self._write_lock:
            existing = self.conn.execute(
                "SELECT project_id FROM entities WHERE id = ?",
                (entity.id,),
            ).fetchone()
            if existing is not None and existing["project_id"] != project:
                raise ValueError("Entity id is already owned by another project")
            self.conn.execute(
                """
                INSERT INTO entities (id, type, name, attributes_json, source_file,
                                    created_at, updated_at, confidence, project_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    type=excluded.type,
                    name=excluded.name,
                    attributes_json=excluded.attributes_json,
                    source_file=excluded.source_file,
                    updated_at=excluded.updated_at,
                    confidence=excluded.confidence,
                    project_id=excluded.project_id
                """,
                (
                    entity.id,
                    entity.type,
                    entity.name,
                    json.dumps(entity.attributes, default=str),
                    entity.source_file,
                    entity.created_at.timestamp(),
                    entity.updated_at.timestamp(),
                    entity.confidence,
                    project,
                ),
            )
            self.conn.commit()

    def get_entity_by_id(
        self,
        entity_id: str,
        *,
        project_id: str | None = None,
    ) -> Entity | None:
        """Laedt eine Entitaet."""
        project = resolve_project_id(project_id)
        row = self.conn.execute(
            "SELECT * FROM entities WHERE id = ? AND project_id = ?",
            (entity_id, project),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_entity(row)

    def search_entities(
        self,
        name: str | None = None,
        entity_type: str | None = None,
        *,
        project_id: str | None = None,
    ) -> list[Entity]:
        """Sucht Entitaeten nach Name und/oder Typ."""
        conditions: list[str] = ["project_id = ?"]
        params: list[Any] = [resolve_project_id(project_id)]

        if name:
            # Escape LIKE wildcards to prevent injection
            escaped = name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append("name LIKE ? ESCAPE '\\'")
            params.append(f"%{escaped}%")
        if entity_type:
            conditions.append("type = ?")
            params.append(entity_type)

        where = " AND ".join(conditions)
        rows = self.conn.execute(
            f"SELECT * FROM entities WHERE {where} ORDER BY name", params
        ).fetchall()
        return [self._row_to_entity(r) for r in rows]

    def delete_entity(
        self,
        entity_id: str,
        *,
        project_id: str | None = None,
    ) -> bool:
        """Loescht eine Entitaet und ihre Relationen. Thread-safe."""
        project = resolve_project_id(project_id)
        with self._write_lock:
            self.conn.execute(
                """
                DELETE FROM relations
                WHERE project_id = ? AND (source_entity = ? OR target_entity = ?)
                """,
                (project, entity_id, entity_id),
            )
            cursor = self.conn.execute(
                "DELETE FROM entities WHERE id = ? AND project_id = ?",
                (entity_id, project),
            )
            self.conn.commit()
            return cursor.rowcount > 0

    def count_entities(self, *, project_id: str | None = None) -> int:
        """Zaehlt die Anzahl der Entitaeten im Index."""
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM entities WHERE project_id = ?",
            (resolve_project_id(project_id),),
        ).fetchone()
        return row["cnt"] if row else 0

    def update_entity_confidence(
        self,
        entity_id: str,
        new_confidence: float,
        *,
        project_id: str | None = None,
    ) -> bool:
        """Update the confidence score of an entity. Returns True if found.

        Thread-safe: Geschuetzt ueber Write-Lock.
        """
        with self._write_lock:
            cur = self.conn.execute(
                """
                UPDATE entities SET confidence = ?, updated_at = ?
                WHERE id = ? AND project_id = ?
                """,
                (
                    new_confidence,
                    datetime.now().timestamp(),
                    entity_id,
                    resolve_project_id(project_id),
                ),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def update_relation_confidence(
        self,
        relation_id: str,
        new_confidence: float,
        *,
        project_id: str | None = None,
    ) -> bool:
        """Update the confidence score of a relation.

        Thread-safe: Geschuetzt ueber Write-Lock.
        """
        with self._write_lock:
            cur = self.conn.execute(
                """
                UPDATE relations SET confidence = ?
                WHERE id = ? AND project_id = ?
                """,
                (new_confidence, relation_id, resolve_project_id(project_id)),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def list_entities_for_decay(
        self,
        limit: int = 500,
        *,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return entities with their confidence and updated_at for decay processing."""
        rows = self.conn.execute(
            "SELECT id, confidence, updated_at FROM entities "
            "WHERE project_id = ? AND confidence > 0.05 "
            "ORDER BY updated_at ASC LIMIT ?",
            (resolve_project_id(project_id), limit),
        ).fetchall()
        return [
            {"id": r["id"], "confidence": r["confidence"], "updated_at": r["updated_at"]}
            for r in rows
        ]

    # ── Relation Operations ──────────────────────────────────────

    def upsert_relation(self, relation: Relation) -> None:
        """Fuegt eine Relation ein oder aktualisiert sie. Thread-safe."""
        project = resolve_project_id(relation.project_id or None)
        with self._write_lock:
            endpoints = self.conn.execute(
                """
                SELECT id FROM entities
                WHERE project_id = ? AND id IN (?, ?)
                """,
                (project, relation.source_entity, relation.target_entity),
            ).fetchall()
            if {row["id"] for row in endpoints} != {
                relation.source_entity,
                relation.target_entity,
            }:
                raise ValueError("Relation endpoints must exist in the same project")
            existing = self.conn.execute(
                "SELECT project_id FROM relations WHERE id = ?",
                (relation.id,),
            ).fetchone()
            if existing is not None and existing["project_id"] != project:
                raise ValueError("Relation id is already owned by another project")
            self.conn.execute(
                """
                INSERT INTO relations (id, source_entity, relation_type, target_entity,
                                     attributes_json, source_file, created_at, confidence,
                                     project_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    relation_type=excluded.relation_type,
                    attributes_json=excluded.attributes_json,
                    confidence=excluded.confidence,
                    project_id=excluded.project_id
                """,
                (
                    relation.id,
                    relation.source_entity,
                    relation.relation_type,
                    relation.target_entity,
                    json.dumps(relation.attributes, default=str),
                    relation.source_file,
                    relation.created_at.timestamp(),
                    relation.confidence,
                    project,
                ),
            )
            self.conn.commit()

    def get_relations_for_entity(
        self,
        entity_id: str,
        relation_type: str | None = None,
        *,
        project_id: str | None = None,
    ) -> list[Relation]:
        """Alle Relationen einer Entitaet (als Quelle oder Ziel)."""
        project = resolve_project_id(project_id)
        if relation_type:
            rows = self.conn.execute(
                """SELECT * FROM relations
                   WHERE project_id = ?
                   AND (source_entity = ? OR target_entity = ?)
                   AND relation_type = ?""",
                (project, entity_id, entity_id, relation_type),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT * FROM relations
                WHERE project_id = ? AND (source_entity = ? OR target_entity = ?)
                """,
                (project, entity_id, entity_id),
            ).fetchall()
        return [self._row_to_relation(r) for r in rows]

    def delete_relation(
        self,
        source_entity: str,
        relation_type: str,
        target_entity: str,
        *,
        project_id: str | None = None,
    ) -> int:
        """Delete one relation shape inside the active project only."""
        project = resolve_project_id(project_id)
        with self._write_lock:
            cursor = self.conn.execute(
                """
                DELETE FROM relations
                WHERE project_id = ?
                  AND source_entity = ?
                  AND relation_type = ?
                  AND target_entity = ?
                """,
                (project, source_entity, relation_type, target_entity),
            )
            self.conn.commit()
            return cursor.rowcount

    def graph_traverse(
        self,
        entity_id: str,
        max_depth: int = 2,
        *,
        project_id: str | None = None,
    ) -> list[Entity]:
        """Traversiert den Wissens-Graph ab einer Entitaet.

        Verwendet eine iterative BFS-Suche (statt rekursiver CTE) um
        Zyklen im Graphen sicher zu handhaben und exponentielle Blowups
        bei dicht vernetzten Entitaeten zu vermeiden.

        Args:
            entity_id: Start-Entitaet.
            max_depth: Maximale Tiefe.

        Returns:
            Alle erreichbaren Entitaeten (ohne Start-Entitaet).
        """
        project = resolve_project_id(project_id)
        if self.get_entity_by_id(entity_id, project_id=project) is None:
            return []
        visited: set[str] = {entity_id}
        frontier: set[str] = {entity_id}

        for _ in range(max_depth):
            if not frontier:
                break
            # Alle Nachbarn der aktuellen Frontier in einem Query laden
            frontier_list = list(frontier)
            next_frontier: set[str] = set()
            for i in range(0, len(frontier_list), 450):
                batch = frontier_list[i : i + 450]
                placeholders = ",".join("?" * len(batch))
                rows = self.conn.execute(
                    f"SELECT source_entity, target_entity FROM relations "
                    f"WHERE project_id = ? AND (source_entity IN ({placeholders}) "
                    f"OR target_entity IN ({placeholders}))",
                    [project, *batch, *batch],
                ).fetchall()
                for r in rows:
                    for neighbor in (r["source_entity"], r["target_entity"]):
                        if neighbor not in visited:
                            visited.add(neighbor)
                            next_frontier.add(neighbor)
            frontier = next_frontier

        # Start-Entitaet entfernen
        visited.discard(entity_id)
        if not visited:
            return []

        # Entitaeten laden
        result_list = list(visited)
        entities: list[Entity] = []
        for i in range(0, len(result_list), 900):
            batch = result_list[i : i + 900]
            placeholders = ",".join("?" * len(batch))
            rows = self.conn.execute(
                f"SELECT * FROM entities WHERE project_id = ? AND id IN ({placeholders})",
                [project, *batch],
            ).fetchall()
            entities.extend(self._row_to_entity(r) for r in rows)
        return entities

    def count_relations(self, *, project_id: str | None = None) -> int:
        """Zaehlt die Anzahl der Relationen im Index."""
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM relations WHERE project_id = ?",
            (resolve_project_id(project_id),),
        ).fetchone()
        return row["cnt"] if row else 0

    def get_chunks_with_entity_overlap(
        self,
        entity_ids: set[str],
        *,
        project_id: str | None = None,
    ) -> list[tuple[str, list[str]]]:
        """Find chunks whose entities_json contains any of the given entity IDs.

        Uses SQL LIKE filtering to avoid loading all chunks into Python.

        Args:
            entity_ids: Set of entity IDs to search for.

        Returns:
            List of (chunk_id, entity_list) tuples for chunks that have
            at least one entity in *entity_ids*.
        """
        if not entity_ids:
            return []
        project = resolve_project_id(project_id)

        # Build a WHERE clause using LIKE for each entity ID.
        # entities_json is a JSON array of strings, e.g. '["e1","e2"]'.
        # We use LIKE with the quoted entity ID to filter at the DB level.
        conditions = []
        params: list[str] = [project]
        for eid in entity_ids:
            # Escape LIKE wildcards in entity IDs
            escaped = eid.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append("entities_json LIKE ? ESCAPE '\\'")
            params.append(f"%{escaped}%")

        where_clause = " OR ".join(conditions)
        query = (
            "SELECT id, entities_json FROM chunks "
            f"WHERE project_id = ? AND entities_json != '[]' AND ({where_clause})"
        )
        rows = self.conn.execute(query, params).fetchall()

        results: list[tuple[str, list[str]]] = []
        for row in rows:
            chunk_entities = json.loads(row["entities_json"]) if row["entities_json"] else []
            results.append((row["id"], chunk_entities))
        return results

    # ── Maintenance ──────────────────────────────────────────────

    def rebuild_fts(self) -> None:
        """Baut den FTS5 Index komplett neu auf. Thread-safe."""
        with self._write_lock:
            self.conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')")
            self.conn.commit()

    def vacuum(self) -> None:
        """Komprimiert die Datenbank. Thread-safe."""
        with self._write_lock:
            self.conn.execute("VACUUM")

    def stats(self) -> dict[str, int]:
        """Statistiken ueber den Index."""
        return {
            "chunks": self.count_chunks(),
            "embeddings": self.count_embeddings(),
            "entities": self.count_entities(),
            "relations": self.count_relations(),
        }

    def close(self) -> None:
        """Schliesst die Datenbankverbindung. Thread-safe."""
        with self._write_lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    # ── Row Conversion ───────────────────────────────────────────

    @staticmethod
    def _row_to_chunk(row: sqlite3.Row) -> Chunk:
        """Konvertiert eine SQLite-Row in ein Chunk-Objekt."""
        ts = datetime.fromtimestamp(row["timestamp"]) if row["timestamp"] is not None else None
        entities = json.loads(row["entities_json"]) if row["entities_json"] else []
        return Chunk(
            id=row["id"],
            text=row["text"],
            source_path=row["source_path"],
            line_start=row["line_start"],
            line_end=row["line_end"],
            content_hash=row["content_hash"],
            memory_tier=MemoryTier(row["memory_tier"]),
            timestamp=ts,
            token_count=row["token_count"],
            entities=entities,
            project_id=row["project_id"],
            source_type=row["source_type"],
            source_id=row["source_id"] or row["source_path"],
            source_trust=row["source_trust"],
            instruction_authority=bool(row["instruction_authority"]),
            provenance_hash=row["provenance_hash"],
        )

    @staticmethod
    def _row_to_entity(row: sqlite3.Row) -> Entity:
        """Konvertiert eine SQLite-Row in ein Entity-Objekt."""
        attrs = json.loads(row["attributes_json"]) if row["attributes_json"] else {}
        return Entity(
            id=row["id"],
            type=row["type"],
            name=row["name"],
            attributes=attrs,
            source_file=row["source_file"],
            created_at=datetime.fromtimestamp(row["created_at"]),
            updated_at=datetime.fromtimestamp(row["updated_at"]),
            confidence=row["confidence"],
            project_id=row["project_id"],
        )

    @staticmethod
    def _row_to_relation(row: sqlite3.Row) -> Relation:
        """Konvertiert eine SQLite-Row in ein Relation-Objekt."""
        attrs = json.loads(row["attributes_json"]) if row["attributes_json"] else {}
        return Relation(
            id=row["id"],
            source_entity=row["source_entity"],
            relation_type=row["relation_type"],
            target_entity=row["target_entity"],
            attributes=attrs,
            source_file=row["source_file"],
            created_at=datetime.fromtimestamp(row["created_at"]),
            confidence=row["confidence"],
            project_id=row["project_id"],
        )
