"""Thomas AI exact-payload approval and R0-R5 security contracts."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from cognithor.mcp.media import MediaPipeline
from cognithor.models import PlannedAction, RiskLevel
from cognithor.security.approvals import (
    ApprovalBindingError,
    ExactPayloadApprovalAuthority,
    action_payload_hash,
)
from cognithor.security.home_lab import ActionRiskClass, action_risk_class, risk_floor

pytestmark = pytest.mark.security_contract


def _email(**params: object) -> PlannedAction:
    return PlannedAction(
        tool="email_send",
        params={"to": "recipient@example.com", "body": "hello", **params},
    )


def _issue(
    authority: ExactPayloadApprovalAuthority,
    action: PlannedAction,
    *,
    session_id: str = "session-1",
    risk_class: ActionRiskClass = ActionRiskClass.R4_PRODUCTION_EXTERNAL,
):
    return authority.issue(
        session_id=session_id,
        action=action,
        risk_class=risk_class,
    )


def test_canonical_hash_is_key_order_independent() -> None:
    first = PlannedAction(tool="email_send", params={"to": "a", "body": "b"})
    second = PlannedAction(tool="email_send", params={"body": "b", "to": "a"})
    assert action_payload_hash(first) == action_payload_hash(second)


def test_payload_change_invalidates_approval() -> None:
    authority = ExactPayloadApprovalAuthority()
    intent = _issue(authority, _email())
    changed = _email(body="different")

    result = authority.resolve(
        approval_id=intent.approval_id,
        approved=True,
        session_id="session-1",
        action=changed,
        risk_class=ActionRiskClass.R4_PRODUCTION_EXTERNAL,
    )

    assert result.authorized is False
    assert result.reason == "approval_payload_changed"


def test_target_change_invalidates_approval() -> None:
    authority = ExactPayloadApprovalAuthority()
    intent = _issue(authority, _email())

    result = authority.resolve(
        approval_id=intent.approval_id,
        approved=True,
        session_id="session-1",
        action=_email(to="attacker@example.com"),
        risk_class=ActionRiskClass.R4_PRODUCTION_EXTERNAL,
    )

    assert result.authorized is False
    assert result.reason == "approval_payload_changed"


def test_risk_change_invalidates_approval() -> None:
    authority = ExactPayloadApprovalAuthority()
    action = _email()
    intent = _issue(authority, action)

    result = authority.resolve(
        approval_id=intent.approval_id,
        approved=True,
        session_id="session-1",
        action=action,
        risk_class=ActionRiskClass.R5_DESTRUCTIVE_SECURITY,
    )

    assert result.authorized is False
    assert result.reason == "approval_risk_changed"


def test_session_change_invalidates_approval() -> None:
    authority = ExactPayloadApprovalAuthority()
    action = _email()
    intent = _issue(authority, action)

    result = authority.resolve(
        approval_id=intent.approval_id,
        approved=True,
        session_id="session-2",
        action=action,
        risk_class=ActionRiskClass.R4_PRODUCTION_EXTERNAL,
    )

    assert result.authorized is False
    assert result.reason == "approval_session_mismatch"


def test_expired_approval_fails_closed() -> None:
    now = [100.0]
    authority = ExactPayloadApprovalAuthority(ttl_seconds=30, clock=lambda: now[0])
    action = _email()
    intent = _issue(authority, action)
    now[0] = 130.0

    result = authority.resolve(
        approval_id=intent.approval_id,
        approved=True,
        session_id="session-1",
        action=action,
        risk_class=ActionRiskClass.R4_PRODUCTION_EXTERNAL,
    )

    assert result.authorized is False
    assert result.reason == "approval_expired"


def test_approval_is_one_shot_and_cannot_be_replayed() -> None:
    authority = ExactPayloadApprovalAuthority()
    action = _email()
    intent = _issue(authority, action)
    first = authority.resolve(
        approval_id=intent.approval_id,
        approved=True,
        session_id="session-1",
        action=action,
        risk_class=ActionRiskClass.R4_PRODUCTION_EXTERNAL,
    )
    replay = authority.resolve(
        approval_id=intent.approval_id,
        approved=True,
        session_id="session-1",
        action=action,
        risk_class=ActionRiskClass.R4_PRODUCTION_EXTERNAL,
    )
    assert first.authorized is True
    assert replay.authorized is False
    assert replay.reason == "approval_missing_or_replayed"


def test_rejected_approval_is_also_consumed() -> None:
    authority = ExactPayloadApprovalAuthority()
    action = _email()
    intent = _issue(authority, action)
    rejected = authority.resolve(
        approval_id=intent.approval_id,
        approved=False,
        session_id="session-1",
        action=action,
        risk_class=ActionRiskClass.R4_PRODUCTION_EXTERNAL,
    )
    replay = authority.resolve(
        approval_id=intent.approval_id,
        approved=True,
        session_id="session-1",
        action=action,
        risk_class=ActionRiskClass.R4_PRODUCTION_EXTERNAL,
    )
    assert rejected.reason == "approval_rejected"
    assert replay.reason == "approval_missing_or_replayed"


def test_uncanonicalizable_payload_fails_before_prompt() -> None:
    authority = ExactPayloadApprovalAuthority()
    action = PlannedAction(tool="email_send", params={"bad": object()})
    with pytest.raises(ApprovalBindingError):
        _issue(authority, action)


def test_prompt_receipt_contains_binding_and_expiry() -> None:
    authority = ExactPayloadApprovalAuthority()
    intent = _issue(authority, _email())
    suffix = intent.prompt_suffix()
    assert intent.approval_id in suffix
    assert intent.payload_hash in suffix
    assert "Risk class: R4" in suffix
    assert "Expires:" in suffix


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        (PlannedAction(tool="read_file", params={"path": "x"}), ActionRiskClass.R0_READ_ONLY),
        (
            PlannedAction(tool="write_file", params={"path": "project/x"}),
            ActionRiskClass.R2_PROJECT_WRITE,
        ),
        (
            PlannedAction(tool="save_to_memory", params={"content": "x"}),
            ActionRiskClass.R3_STAGING_INTEGRATION,
        ),
        (
            PlannedAction(tool="email_send", params={"to": "x"}),
            ActionRiskClass.R4_PRODUCTION_EXTERNAL,
        ),
        (
            PlannedAction(tool="exec_command", params={"command": "id"}),
            ActionRiskClass.R5_DESTRUCTIVE_SECURITY,
        ),
        (
            PlannedAction(tool="delete_file", params={"path": "x"}),
            ActionRiskClass.R5_DESTRUCTIVE_SECURITY,
        ),
    ],
)
def test_r0_to_r5_classification(
    action: PlannedAction,
    expected: ActionRiskClass,
    tmp_path: Path,
) -> None:
    assert action_risk_class(action, tmp_path) == expected


def test_bounded_disposable_execution_is_r1() -> None:
    action = PlannedAction(
        tool="run_python",
        params={
            "code": "print('ok')",
            "timeout": 60,
            "working_dir": "demo",
        },
    )
    assert action_risk_class(action, Path.cwd()) == ActionRiskClass.R1_DISPOSABLE_SANDBOX


@pytest.mark.parametrize(
    "tool",
    [
        "exec_command",
        "shell_exec",
        "shell",
        "remote_exec",
        "docker_run",
    ],
)
def test_model_sandbox_claim_cannot_downgrade_host_execution(tool: str) -> None:
    params = {
        "command": "id",
        "execution_scope": "disposable_sandbox",
        "sandbox_profile": "sandbox.offline",
        "project_id": "demo",
        "network": "none",
        "limits": {
            "cpus": 2,
            "memory_mb": 2048,
            "pids": 256,
            "timeout_seconds": 600,
        },
    }
    action = PlannedAction(tool=tool, params=params)
    assert action_risk_class(action, Path.cwd()) == ActionRiskClass.R5_DESTRUCTIVE_SECURITY


def test_unknown_tool_fails_to_approval_floor() -> None:
    action = PlannedAction(tool="future_unclassified_capability", params={})
    assert action_risk_class(action, Path.cwd()) == ActionRiskClass.R3_STAGING_INTEGRATION
    assert risk_floor(action, Path.cwd()) == RiskLevel.ORANGE


@pytest.mark.parametrize(
    "tool",
    [
        "create_chart",
        "screenshot_desktop",
        "pse_synthesize",
        "media_tts",
        "db_connect",
    ],
)
def test_unscoped_or_sensitive_legacy_tools_require_approval(tool: str) -> None:
    action = PlannedAction(tool=tool, params={})
    assert risk_floor(action, Path.cwd()) == RiskLevel.ORANGE


def test_confined_document_export_is_r2_project_write() -> None:
    action = PlannedAction(
        tool="document_export",
        params={"filename": "../../outside", "format": "pdf", "content": "safe"},
    )
    assert action_risk_class(action, Path.cwd()) == ActionRiskClass.R2_PROJECT_WRITE
    assert risk_floor(action, Path.cwd()) == RiskLevel.YELLOW


@pytest.mark.asyncio
async def test_document_export_cannot_escape_configured_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "project" / "media"
    pipeline = MediaPipeline(workspace_dir=workspace)

    with patch.object(pipeline, "_generate_pdf") as generate:
        result = await pipeline.export_document(
            "safe",
            fmt="pdf",
            filename="../../outside",
        )

    expected = workspace / "documents" / "outside.pdf"
    assert result.success is True
    assert result.output_path == str(expected)
    generate.assert_called_once()
    assert generate.call_args.args[0] == expected
