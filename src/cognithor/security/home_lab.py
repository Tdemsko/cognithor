"""Thomas AI home-lab security policy primitives.

This module is intentionally small and deterministic.  It defines risk
floors that tool-provided annotations cannot lower, plus the read-only
allowlist used by global safe mode.  Keeping these rules outside the
Gatekeeper makes the fork delta easy to audit and merge with upstream.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cognithor.models import PlannedAction, RiskLevel

_RISK_ORDER = {
    RiskLevel.GREEN: 0,
    RiskLevel.YELLOW: 1,
    RiskLevel.ORANGE: 2,
    RiskLevel.RED: 3,
}

HOST_EXECUTION_TOOLS = frozenset(
    {
        "exec_command",
        "shell_exec",
        "shell",
        "run_python",
        "start_background",
        "remote_exec",
        "docker_run",
    }
)

PROJECT_WRITE_TOOLS = frozenset(
    {
        "write_file",
        "file_write",
        "edit_file",
        "find_and_replace",
        "git_branch",
        "git_commit",
    }
)

SELF_MODIFICATION_TOOLS = frozenset(
    {
        "create_skill",
        "install_community_skill",
        "publish_skill",
    }
)

EXTERNAL_SIDE_EFFECT_TOOLS = frozenset(
    {
        "api_call",
        "api_connect",
        "api_disconnect",
        "delegate_to_remote_agent",
        "docker_stop",
        "email_send",
        "calendar_create_event",
        "reddit_reply",
        "schedule_job",
        "send_notification",
        "stop_background_job",
        "set_clipboard",
        "computer_click",
        "computer_type",
        "computer_hotkey",
        "computer_scroll",
        "computer_drag",
        "computer_click_element",
        "browse_click",
        "browse_fill",
        "browse_execute_js",
        "browser_solve_captcha",
    }
)

DURABLE_MEMORY_WRITE_TOOLS = frozenset(
    {
        "add_entity",
        "add_relation",
        "identity_dream",
        "knowledge_synthesize",
        "save_to_memory",
        "vault_link",
        "vault_save",
        "vault_update",
        "vault_write",
    }
)

SAFE_MODE_READ_ONLY_TOOLS = frozenset(
    {
        "read_file",
        "list_directory",
        "search_memory",
        "get_entity",
        "search",
        "list_jobs",
        "web_search",
        "web_fetch",
        "web_news_search",
        "search_and_read",
        "browse_url",
        "search_procedures",
        "media_analyze_image",
        "media_extract_text",
        "media_transcribe_audio",
        "get_core_memory",
        "get_recent_episodes",
        "memory_stats",
        "browse_page_info",
        "browse_screenshot",
        "analyze_code",
        "list_skills",
        "search_community_skills",
        "read_pdf",
        "read_ppt",
        "read_docx",
        "template_list",
        "list_remote_agents",
        "git_status",
        "git_diff",
        "git_log",
        "search_files",
        "find_in_files",
        "db_query",
        "db_schema",
        "calendar_today",
        "calendar_upcoming",
        "calendar_check_availability",
        "identity_recall",
        "identity_state",
        "knowledge_contradictions",
        "knowledge_timeline",
        "knowledge_gaps",
        "vault_list",
        "vault_search",
        "vault_read",
        "docker_ps",
        "docker_logs",
        "docker_inspect",
        "api_list",
        "remote_list_hosts",
        "remote_test_connection",
        "list_background_jobs",
        "check_background_job",
        "read_background_log",
        "wait_background_job",
        "arc_status",
        "arc_replay",
        "pse_is_synthesizable",
        "pse_status",
        "atl_status",
        "atl_journal",
        "kanban_list_tasks",
        "social_scan",
        "social_leads",
        "canvas_snapshot",
        "code_review",
        "summarize",
        "translate",
        "explain_concept",
    }
)


def max_risk(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    """Return the stricter of two risk levels."""
    return left if _RISK_ORDER[left] >= _RISK_ORDER[right] else right


def _resolved_workspace_path(params: dict[str, Any], workspace_dir: Path) -> Path | None:
    raw_path = str(params.get("path") or params.get("file_path") or "").strip()
    if not raw_path:
        return None
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = workspace_dir / candidate
    try:
        return candidate.resolve()
    except (OSError, ValueError):
        return None


def _is_workspace_scoped(action: PlannedAction, workspace_dir: Path) -> bool:
    tool = action.tool.lower()
    if tool in {"git_branch", "git_commit"} and not str(action.params.get("path", "")).strip():
        return True
    if tool == "find_and_replace" and action.params.get("dry_run", True) is True:
        return True
    target = _resolved_workspace_path(action.params, workspace_dir)
    if target is None:
        return False
    try:
        target.relative_to(workspace_dir.resolve())
    except (OSError, ValueError):
        return False
    return True


def risk_floor(action: PlannedAction, workspace_dir: Path) -> RiskLevel:
    """Return the minimum risk permitted by the home-lab profile."""
    tool = action.tool.lower()
    if tool in SELF_MODIFICATION_TOOLS:
        return RiskLevel.RED
    if (
        tool in HOST_EXECUTION_TOOLS
        or tool in EXTERNAL_SIDE_EFFECT_TOOLS
        or tool in DURABLE_MEMORY_WRITE_TOOLS
    ):
        return RiskLevel.ORANGE
    if tool in PROJECT_WRITE_TOOLS:
        if tool == "find_and_replace" and action.params.get("dry_run", True) is True:
            return RiskLevel.GREEN
        return RiskLevel.YELLOW if _is_workspace_scoped(action, workspace_dir) else RiskLevel.ORANGE
    return RiskLevel.GREEN


def safe_mode_allows(tool_name: str) -> bool:
    """Whether global safe mode permits a tool call."""
    return tool_name.lower() in SAFE_MODE_READ_ONLY_TOOLS
