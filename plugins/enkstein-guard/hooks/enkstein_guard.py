#!/usr/bin/env python3
"""Enkstein Guard: a PreToolUse hook for Claude Code and Codex CLI.

Reads one hook event as JSON on stdin, decides whether the tool call is
permitted, and answers on stdout. Runs standalone by default; when an Enkstein
backend is reachable it defers to the full Trust Fabric instead.

Exit codes follow the Claude Code hook contract:
    0  allow (stdout may carry structured JSON)
    2  block (stderr is fed back to the model as the reason)
Any other failure exits 0, because a broken security hook must never become a
broken editor. Fail-open is the correct posture for an advisory local tier; the
connected tier is where fail-closed enforcement belongs.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Importing policy.py would otherwise drop a __pycache__ directory into the
# user's plugin install on the first tool call. A security hook should not
# write to its own installation directory.
sys.dont_write_bytecode = True

sys.path.insert(0, str(Path(__file__).resolve().parent))

import policy  # noqa: E402

CONNECT_TIMEOUT = float(os.environ.get("ENKSTEIN_HOOK_TIMEOUT", "2.0"))

# Tools that put content on disk, by agent. Claude and Codex name these
# differently, so both vocabularies are accepted.
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch", "write_file"}
COMMAND_TOOLS = {"Bash", "BashOutput", "shell", "exec_command", "run_command"}


def _read_event() -> dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def _tool_name(event: dict) -> str:
    return event.get("tool_name") or event.get("tool") or event.get("name") or ""


def _tool_input(event: dict) -> dict:
    value = event.get("tool_input") or event.get("input") or event.get("arguments") or {}
    return value if isinstance(value, dict) else {}


def _extract_content(payload: dict) -> str:
    """Collect every field an agent may use to carry file content."""
    parts: list[str] = []
    for key in ("content", "new_string", "new_str", "text", "patch", "contents", "source"):
        value = payload.get(key)
        if isinstance(value, str):
            parts.append(value)
    for edit in payload.get("edits") or []:
        if isinstance(edit, dict):
            for key in ("new_string", "new_str", "content"):
                value = edit.get(key)
                if isinstance(value, str):
                    parts.append(value)
    return "\n".join(parts)


def _extract_command(payload: dict) -> str:
    for key in ("command", "cmd", "script"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return " ".join(str(part) for part in value)
    return ""


def _agent_identity() -> str:
    """Best-effort name of the coding agent hosting this hook."""
    if os.environ.get("CLAUDE_PLUGIN_ROOT") or os.environ.get("CLAUDECODE"):
        return "Claude Code"
    if os.environ.get("CODEX_PLUGIN_ROOT") or os.environ.get("CODEX_HOME"):
        return "Codex CLI"
    return "AI coding agent"


def _target_of(tool: str, payload: dict) -> str:
    """A short, human-readable subject for the audit row."""
    for key in ("file_path", "path", "notebook_path"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value[:512]
    command = _extract_command(payload)
    if command:
        return command.strip()[:512]
    return tool


def _remote_decision(tool: str, payload: dict) -> policy.Decision | None:
    """Ask a reachable Enkstein backend to apply the full Trust Fabric.

    Returns None when no backend is configured or it does not answer promptly,
    so the local pack stays authoritative rather than the call hanging.
    """
    base = os.environ.get("ENKSTEIN_API_URL", "").strip()
    if not base:
        return None

    import urllib.error
    import urllib.request

    # Identify the agent and workspace so a console reader can tell *which*
    # assistant, on *which* project, tried the action. Without this the Events
    # table shows an unattributed row and the audit trail is much less useful.
    agent = _agent_identity()
    body = json.dumps({
        "module": "arcclaw",
        "action": f"agent_tool:{tool}",
        "actor_id": f"coding-agent:{agent}",
        "actor_name": f"{agent} ({Path.cwd().name})",
        "actor_type": "ai_agent",
        "target": _target_of(tool, payload),
        "target_type": "workspace_file" if tool in WRITE_TOOLS else "shell_command",
        "context": {
            "tool": tool,
            "tool_input": payload,
            "channel": "coding_agent",
            "agent": agent,
            "workspace": str(Path.cwd()),
        },
    }).encode()

    request = urllib.request.Request(
        base.rstrip("/") + "/api/v1/trust-fabric/evaluate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    token = os.environ.get("ENKSTEIN_TOKEN", "").strip()
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(request, timeout=CONNECT_TIMEOUT) as response:
            data = json.loads(response.read().decode())
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None

    # The route answers with EventOutcome vocabulary (allowed/blocked/
    # requires_approval/flagged), not PolicyAction. Reading a "decision" key
    # here would silently never match and the connected tier would look like it
    # was working while enforcing nothing.
    outcome = str(data.get("outcome") or "").lower()
    allowed = data.get("allowed")

    if outcome == "blocked":
        decision = policy.DENY
    elif outcome == "requires_approval":
        decision = policy.REQUIRE_APPROVAL
    elif outcome in ("allowed", "flagged", "pending"):
        decision = policy.ALLOW
    elif allowed is False:
        # Older or partial payloads may only carry the boolean.
        decision = policy.DENY
    elif allowed is True:
        decision = policy.ALLOW
    else:
        return None

    findings = []
    if decision in (policy.DENY, policy.REQUIRE_APPROVAL):
        findings.append(policy.Finding(
            rule_id=str(data.get("policy_name") or "trust_fabric"),
            title="Trust Fabric policy",
            decision=decision,
            detail=str(data.get("reason") or "blocked by tenant policy"),
        ))
    return policy.Decision(decision, findings)


def _local_decision(tool: str, payload: dict) -> policy.Decision:
    if tool in COMMAND_TOOLS:
        return policy.scan_command(_extract_command(payload))
    if tool in WRITE_TOOLS:
        return policy.scan_content(_extract_content(payload))
    return policy.Decision(policy.ALLOW)


def _evaluate(tool: str, payload: dict) -> tuple[policy.Decision, str]:
    """Combine both tiers, taking whichever is stricter.

    The two tiers answer different questions. The local pack knows what a secret
    and a destructive command look like; the Trust Fabric knows this tenant's
    policy. Letting a reachable backend *replace* local scanning would make
    connecting a backend reduce protection, because the shipped policies match
    connector and cloud actions rather than agent_tool:* and fall through to
    "default allow". Strictest-wins keeps the connected tier purely additive.
    """
    local = _local_decision(tool, payload)
    remote = _remote_decision(tool, payload)
    if remote is None:
        return local, "standalone"

    combined = policy.Decision(
        policy._worst((local.decision, remote.decision)),
        local.findings + remote.findings,
    )
    return combined, "connected"


def _block(decision: policy.Decision, mode: str) -> None:
    verb = "blocked" if decision.decision == policy.DENY else "held for approval"
    reason = decision.reason() or "policy violation"
    rules = ", ".join(sorted({f.rule_id for f in decision.findings}))

    message = (
        f"Enkstein {verb} this action.\n"
        f"{reason}\n"
        f"Rule: {rules} ({mode} policy)\n"
    )
    if decision.decision == policy.REQUIRE_APPROVAL:
        message += (
            "This needs a human decision. Confirm with the user, or adjust the "
            "approach so approval is not required."
        )
    else:
        message += "Remove the flagged content and try again."

    # Structured output is the documented channel; stderr + exit 2 is the
    # fallback older builds understand. Emitting both keeps one script working
    # across Claude Code and Codex without version detection.
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": message,
        },
        "decision": "block",
        "reason": message,
        "systemMessage": f"Enkstein {verb} a tool call: {reason}",
    }))
    print(message, file=sys.stderr)
    sys.exit(2)


def _handle_prompt(event: dict) -> None:
    """Govern what the user is about to send to a model provider.

    A secret pasted into chat leaves your control the moment the turn is sent:
    it enters the vendor's context, their logs, and usually their retention.
    Blocking the write to disk but not the prompt leaves the larger hole open.
    """
    prompt = event.get("prompt") or event.get("user_prompt") or ""
    if not isinstance(prompt, str) or not prompt.strip():
        sys.exit(0)

    decision = policy.scan_prompt(prompt)
    if not decision.blocked:
        sys.exit(0)

    reason = decision.reason() or "sensitive data"
    rules = ", ".join(sorted({f.rule_id for f in decision.findings}))
    message = (
        f"Enkstein stopped this message before it was sent.\n"
        f"{reason}\n"
        f"Rule: {rules}\n"
        "This would have left your machine and entered the provider's "
        "conversation history. Remove or replace the value and send again."
    )

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "permissionDecision": "deny",
            "permissionDecisionReason": message,
        },
        "decision": "block",
        "reason": message,
        "systemMessage": f"Enkstein blocked a message: {reason}",
    }))
    print(message, file=sys.stderr)
    sys.exit(2)


def main() -> None:
    try:
        event = _read_event()

        # UserPromptSubmit carries no tool, so it must be routed by event name.
        if event.get("hook_event_name") == "UserPromptSubmit" or (
            "prompt" in event and not _tool_name(event)
        ):
            _handle_prompt(event)
            sys.exit(0)

        tool = _tool_name(event)
        if not tool:
            sys.exit(0)

        decision, mode = _evaluate(tool, _tool_input(event))
        if decision.blocked:
            _block(decision, mode)
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        # A hook crash must not brick the editor.
        sys.exit(0)
    sys.exit(0)


if __name__ == "__main__":
    main()
