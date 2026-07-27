"""Thomas AI secret and pre-execution security-boundary invariants."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from cognithor.audit import AuditLogger
from cognithor.config import CognithorConfig
from cognithor.core.executor import Executor
from cognithor.core.tool_hooks import HookEvent
from cognithor.security.audit import AuditTrail, mask_dict
from cognithor.security.credentials import (
    CredentialMappingError,
    CredentialStore,
    CredentialStoreIntegrityError,
)

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.security_contract


@dataclass
class _ToolResult:
    content: str = "ok"
    is_error: bool = False


def test_nested_sensitive_keys_are_fully_redacted() -> None:
    raw = "not-a-recognized-token-shape"
    masked = mask_dict(
        {
            "request": {
                "service_access_token": raw,
                "nested": [{"client_secret": raw}],
            }
        }
    )
    assert masked["request"]["service_access_token"] == "***REDACTED***"
    assert masked["request"]["nested"][0]["client_secret"] == "***REDACTED***"
    assert raw not in repr(masked)


def test_authoritative_audit_masks_error_text(tmp_path: Path) -> None:
    from .conftest import make_audit_entry

    raw = "Bearer secret-token-value-123456"
    trail = AuditTrail(log_path=tmp_path / "audit.jsonl")
    trail.record(make_audit_entry(error=raw))
    persisted = trail.log_path.read_text(encoding="utf-8")
    assert raw not in persisted
    assert "Bearer ***" in persisted


def test_operational_audit_masks_nested_params_and_results() -> None:
    raw = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    audit = AuditLogger()
    entry = audit.log_tool_call(
        "api_call",
        {"nested": {"access_token": raw}},
        result=f"remote returned {raw}",
    )
    assert raw not in repr(entry.parameters)
    assert raw not in entry.result


def test_credential_store_corruption_never_becomes_empty_store(tmp_path: Path) -> None:
    path = tmp_path / "credentials.enc"
    path.write_text('{"broken": {"service": "x"}}', encoding="utf-8")
    store = CredentialStore(store_path=path, passphrase="test-key")
    with pytest.raises(CredentialStoreIntegrityError):
        _ = store.count


def test_missing_scoped_credential_never_leaves_model_value_in_place(
    tmp_path: Path,
) -> None:
    store = CredentialStore(
        store_path=tmp_path / "credentials.enc",
        passphrase="test-key",
    )
    model_supplied = "attacker-controlled-value"
    with pytest.raises(CredentialMappingError):
        store.inject_credentials(
            {"authorization": model_supplied},
            {"authorization": "github:token"},
            agent_id="github.read",
        )


@pytest.mark.asyncio
async def test_required_pre_execution_control_failure_never_calls_tool(
    tmp_path: Path,
) -> None:
    config = CognithorConfig(cognithor_home=tmp_path)
    mcp = AsyncMock()
    mcp.call_tool = AsyncMock(return_value=_ToolResult())
    executor = Executor(config, mcp)
    assert executor._tool_hook_runner is not None
    executor._tool_hook_runner.register(
        HookEvent.PRE_TOOL_USE,
        "injected_failure",
        lambda _tool, _params: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    result = await executor._execute_single("read_file", {"path": "README.md"})

    assert result.is_error
    assert result.error_type == "HookDenied"
    mcp.call_tool.assert_not_called()


@pytest.mark.asyncio
async def test_missing_required_pre_execution_controls_never_call_tool(
    tmp_path: Path,
) -> None:
    config = CognithorConfig(cognithor_home=tmp_path)
    mcp = AsyncMock()
    mcp.call_tool = AsyncMock(return_value=_ToolResult())
    executor = Executor(config, mcp)
    executor._tool_hook_runner = None

    result = await executor._execute_single("read_file", {"path": "README.md"})

    assert result.is_error
    assert result.error_type == "SecurityControlFailure"
    mcp.call_tool.assert_not_called()
