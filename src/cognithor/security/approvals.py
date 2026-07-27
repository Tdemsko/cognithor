"""Exact-payload, one-time approval bindings for Thomas AI.

The communication channel is allowed to collect a human yes/no response, but
it never decides what that response authorizes.  This deterministic module
binds a response to one session, one risk class, one canonical action payload,
and one short validity window.  Every resolution is one-shot, including
rejections and invalid attempts, so replay fails closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from cognithor.models import PlannedAction
    from cognithor.security.home_lab import ActionRiskClass

APPROVAL_SCHEMA_VERSION = "thomas-ai.approval.v1"


class ApprovalBindingError(ValueError):
    """The proposed action cannot be represented as a stable approval payload."""


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ApprovalBindingError("Non-finite numbers are not valid approval payloads")
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, Enum):
        return _canonical_value(value.value)
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ApprovalBindingError("Approval payload keys must be strings")
        return {key: _canonical_value(value[key]) for key in sorted(value)}
    if isinstance(value, list | tuple):
        return [_canonical_value(item) for item in value]
    raise ApprovalBindingError(
        f"Unsupported approval payload type: {type(value).__module__}.{type(value).__qualname__}"
    )


def canonical_action_payload(action: PlannedAction) -> bytes:
    """Return the canonical execution payload covered by an approval."""
    payload = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "tool": action.tool,
        "params": _canonical_value(action.params),
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def action_payload_hash(action: PlannedAction) -> str:
    """SHA-256 of the exact tool and parameters that would execute."""
    return hashlib.sha256(canonical_action_payload(action)).hexdigest()


@dataclass(frozen=True, slots=True)
class ApprovalIntent:
    approval_id: str
    session_id: str
    tool: str
    payload_hash: str
    risk_class: ActionRiskClass
    issued_at: float
    expires_at: float

    def prompt_suffix(self) -> str:
        expires = datetime.fromtimestamp(self.expires_at, tz=UTC).isoformat()
        return (
            f"\n\nApproval ID: {self.approval_id}"
            f"\nRisk class: {self.risk_class.value}"
            f"\nPayload SHA-256: {self.payload_hash}"
            f"\nExpires: {expires}"
        )


@dataclass(frozen=True, slots=True)
class ApprovalResolution:
    authorized: bool
    reason: str
    intent: ApprovalIntent | None = None


class ExactPayloadApprovalAuthority:
    """Issues and consumes bounded, non-replayable approval intents."""

    def __init__(
        self,
        *,
        ttl_seconds: float = 300.0,
        max_pending: int = 1024,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_pending <= 0:
            raise ValueError("max_pending must be positive")
        self._ttl_seconds = ttl_seconds
        self._max_pending = max_pending
        self._clock = clock
        self._pending: dict[str, ApprovalIntent] = {}

    def _prune_expired(self, now: float) -> None:
        for approval_id, intent in list(self._pending.items()):
            if now >= intent.expires_at:
                self._pending.pop(approval_id, None)

    def issue(
        self,
        *,
        session_id: str,
        action: PlannedAction,
        risk_class: ActionRiskClass,
    ) -> ApprovalIntent:
        now = self._clock()
        self._prune_expired(now)
        if len(self._pending) >= self._max_pending:
            raise RuntimeError("Approval queue capacity exceeded")
        intent = ApprovalIntent(
            approval_id=f"apr_{uuid.uuid4().hex}",
            session_id=session_id,
            tool=action.tool,
            payload_hash=action_payload_hash(action),
            risk_class=risk_class,
            issued_at=now,
            expires_at=now + self._ttl_seconds,
        )
        self._pending[intent.approval_id] = intent
        return intent

    def resolve(
        self,
        *,
        approval_id: str,
        approved: bool,
        session_id: str,
        action: PlannedAction,
        risk_class: ActionRiskClass,
    ) -> ApprovalResolution:
        """Consume an intent once and authorize only an exact, unexpired match."""
        intent = self._pending.pop(approval_id, None)
        if intent is None:
            return ApprovalResolution(False, "approval_missing_or_replayed")
        now = self._clock()
        if now >= intent.expires_at:
            return ApprovalResolution(False, "approval_expired", intent)
        if not approved:
            return ApprovalResolution(False, "approval_rejected", intent)
        if not hmac.compare_digest(intent.session_id, session_id):
            return ApprovalResolution(False, "approval_session_mismatch", intent)
        if intent.risk_class != risk_class:
            return ApprovalResolution(False, "approval_risk_changed", intent)
        try:
            current_hash = action_payload_hash(action)
        except ApprovalBindingError:
            return ApprovalResolution(False, "approval_payload_uncanonicalizable", intent)
        if not hmac.compare_digest(intent.payload_hash, current_hash):
            return ApprovalResolution(False, "approval_payload_changed", intent)
        return ApprovalResolution(True, "approval_exact_match", intent)

    @property
    def pending_count(self) -> int:
        return len(self._pending)
