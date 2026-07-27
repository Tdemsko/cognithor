"""Tests für security/credentials.py – Verschlüsselter Credential-Store."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from cognithor.security.credentials import (
    CredentialMappingError,
    CredentialStore,
    CredentialStoreIntegrityError,
    CredentialStoreUnavailableError,
)

if TYPE_CHECKING:
    from pathlib import Path

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def store_path(tmp_path: Path) -> Path:
    return tmp_path / "creds.enc"


@pytest.fixture
def store(store_path: Path) -> CredentialStore:
    return CredentialStore(
        store_path=store_path,
        passphrase="test_master_key_42",
    )


# ============================================================================
# Store & Retrieve
# ============================================================================


class TestStoreRetrieve:
    def test_store_and_retrieve(self, store: CredentialStore):
        entry = store.store("telegram", "bot_token", "123456:ABC-DEF")
        assert entry.service == "telegram"
        assert entry.key == "bot_token"

        value = store.retrieve("telegram", "bot_token")
        assert value == "123456:ABC-DEF"

    def test_retrieve_nonexistent(self, store: CredentialStore):
        assert store.retrieve("nonexistent", "key") is None

    def test_overwrite(self, store: CredentialStore):
        store.store("svc", "key", "value1")
        store.store("svc", "key", "value2")
        assert store.retrieve("svc", "key") == "value2"
        assert store.count == 1

    def test_multiple_services(self, store: CredentialStore):
        store.store("telegram", "token", "t1")
        store.store("searxng", "url", "http://localhost:8080")
        store.store("brave", "api_key", "brave_key_123")

        assert store.retrieve("telegram", "token") == "t1"
        assert store.retrieve("searxng", "url") == "http://localhost:8080"
        assert store.retrieve("brave", "api_key") == "brave_key_123"
        assert store.count == 3

    def test_special_characters(self, store: CredentialStore):
        value = "p@$$w0rd!#%^&*()_+={}\n\ttabs"
        store.store("svc", "pw", value)
        assert store.retrieve("svc", "pw") == value

    def test_unicode_values(self, store: CredentialStore):
        value = "Schlüssel_für_Tür_🔑"
        store.store("svc", "key", value)
        assert store.retrieve("svc", "key") == value


class TestDelete:
    def test_delete_existing(self, store: CredentialStore):
        store.store("svc", "key", "value")
        assert store.delete("svc", "key") is True
        assert store.retrieve("svc", "key") is None
        assert store.count == 0

    def test_delete_nonexistent(self, store: CredentialStore):
        assert store.delete("nope", "key") is False


class TestListEntries:
    def test_list_empty(self, store: CredentialStore):
        assert store.list_entries() == []

    def test_list_all(self, store: CredentialStore):
        store.store("a", "key1", "v1")
        store.store("b", "key2", "v2")
        entries = store.list_entries()
        assert len(entries) == 2
        services = {e.service for e in entries}
        assert services == {"a", "b"}

    def test_list_excludes_values(self, store: CredentialStore):
        store.store("svc", "secret", "super_secret_value")
        entries = store.list_entries()
        # CredentialEntry has no 'value' field
        for e in entries:
            assert not hasattr(e, "value") or getattr(e, "value", None) is None


class TestHas:
    def test_has_existing(self, store: CredentialStore):
        store.store("svc", "key", "val")
        assert store.has("svc", "key") is True

    def test_has_nonexistent(self, store: CredentialStore):
        assert store.has("nope", "key") is False


# ============================================================================
# Persistence
# ============================================================================


class TestPersistence:
    def test_survives_reload(self, store_path: Path):
        store1 = CredentialStore(store_path=store_path, passphrase="test_key")
        store1.store("svc", "token", "my_secret")

        # Neues Objekt, gleicher Pfad + Key
        store2 = CredentialStore(store_path=store_path, passphrase="test_key")
        assert store2.retrieve("svc", "token") == "my_secret"

    def test_wrong_passphrase_fails(self, store_path: Path):
        store1 = CredentialStore(store_path=store_path, passphrase="correct")
        store1.store("svc", "token", "secret")

        store2 = CredentialStore(store_path=store_path, passphrase="wrong")
        with pytest.raises(CredentialStoreIntegrityError):
            store2.retrieve("svc", "token")

    def test_corrupt_store_fails_closed(self, store_path: Path):
        store_path.write_text("{not-json", encoding="utf-8")
        store = CredentialStore(store_path=store_path, passphrase="correct")
        with pytest.raises(CredentialStoreIntegrityError):
            _ = store.count


class TestFilePermissions:
    def test_store_file_created(self, store: CredentialStore):
        store.store("svc", "key", "val")
        assert store._store_path.exists()

    def test_salt_file_created(self, store: CredentialStore):
        salt_path = store._store_path.parent / ".credential_salt"
        assert salt_path.exists()


# ============================================================================
# Inject Credentials
# ============================================================================


class TestInjectCredentials:
    def test_inject_single(self, store: CredentialStore):
        store.store("searxng", "api_key", "brave_123")
        params = {"query": "test", "api_key": ""}
        mapping = {"api_key": "searxng:api_key"}

        result = store.inject_credentials(params, mapping)
        assert result["api_key"] == "brave_123"
        assert result["query"] == "test"

    def test_inject_missing_credential(self, store: CredentialStore):
        params = {"key": ""}
        mapping = {"key": "nonexistent:nope"}
        with pytest.raises(CredentialMappingError):
            store.inject_credentials(params, mapping)

    def test_inject_missing_can_be_non_strict_for_legacy_callers(self, store: CredentialStore):
        params = {"key": ""}
        mapping = {"key": "nonexistent:nope"}
        result = store.inject_credentials(params, mapping, strict=False)
        assert result["key"] == ""

    def test_inject_multiple(self, store: CredentialStore):
        store.store("api", "key", "k1")
        store.store("api", "secret", "s1")
        params = {"key": "", "secret": "", "other": "keep"}
        mapping = {"key": "api:key", "secret": "api:secret"}

        result = store.inject_credentials(params, mapping)
        assert result["key"] == "k1"
        assert result["secret"] == "s1"
        assert result["other"] == "keep"

    def test_inject_preserves_original(self, store: CredentialStore):
        store.store("svc", "key", "val")
        original = {"key": "old", "other": "data"}
        mapping = {"key": "svc:key"}
        result = store.inject_credentials(original, mapping)
        # Original unchanged
        assert original["key"] == "old"
        assert result["key"] == "val"

    def test_scoped_injection_does_not_use_global_secret_by_default(self, store: CredentialStore):
        store.store("svc", "key", "global-value")
        with pytest.raises(CredentialMappingError):
            store.inject_credentials(
                {"key": ""},
                {"key": "svc:key"},
                agent_id="worker-capability",
            )

    def test_scoped_injection_requires_explicit_global_fallback(self, store: CredentialStore):
        store.store("svc", "key", "global-value")
        result = store.inject_credentials(
            {"key": ""},
            {"key": "svc:key"},
            agent_id="worker-capability",
            allow_global_fallback=True,
        )
        assert result["key"] == "global-value"


class TestEncryptionStatus:
    def test_fernet_encryption(self, store: CredentialStore):
        # Fernet-Verschlüsselung funktioniert mit gültiger Passphrase
        store.store("svc", "key", "test_value")
        val = store.retrieve("svc", "key")
        assert val == "test_value"

    def test_empty_passphrase_fails_when_keyring_unavailable(
        self, store_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(CredentialStore, "_try_keyring", staticmethod(lambda: ""))
        with pytest.raises(CredentialStoreUnavailableError):
            CredentialStore(store_path=store_path, passphrase="")
