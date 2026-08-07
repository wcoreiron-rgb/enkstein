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
import hashlib
import os
import re
import shlex
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


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _risk_for(decision: policy.Decision) -> tuple[float, str]:
    return {
        policy.DENY: (95.0, "critical"),
        policy.REQUIRE_APPROVAL: (75.0, "high"),
        policy.MASK: (50.0, "medium"),
        policy.MONITOR: (25.0, "low"),
        policy.ALLOW: (0.0, "none"),
    }.get(decision.decision, (0.0, "none"))


_LABEL_WORDS = {
    "audit", "config", "credential", "database", "deploy", "environment",
    "external", "identity", "key", "log", "network", "password", "private",
    "production", "secret", "security", "token", "vendor",
}


def _safe_target(tool: str, payload: dict) -> tuple[str, list[str], str]:
    """Return a non-sensitive kind, labels, and digest for policy/audit.

    The digest preserves correlation across events without persisting a path or
    command. Labels come from a fixed vocabulary, so a filename containing a
    customer, secret, or case name cannot leak through metadata.
    """
    if tool in WRITE_TOOLS:
        raw = next((payload.get(key) for key in ("file_path", "path", "notebook_path")
                    if isinstance(payload.get(key), str)), "")
        lowered = raw.lower()
        labels = sorted(word for word in _LABEL_WORDS if word in lowered)
        suffix = Path(raw).suffix.lower().lstrip(".")
        if suffix and re.fullmatch(r"[a-z0-9]{1,12}", suffix):
            labels.append(f"ext_{suffix}")
        return "workspace_file", labels[:20], _digest(raw or tool)

    command = _extract_command(payload)
    labels: list[str] = []
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = []
    if parts:
        program = Path(parts[0]).name.lower()
        if re.fullmatch(r"[a-z0-9_.-]{1,32}", program):
            labels.append(f"program_{program}")
    return "shell_command", labels, _digest(command or tool)


def _semantic_operation(tool: str, decision: policy.Decision) -> str:
    ids = " ".join(f.rule_id for f in decision.findings).lower()
    if tool == "UserPromptSubmit":
        return "llm_prompt"
    if tool in WRITE_TOOLS:
        if "secret" in ids or "credential" in ids or "api_key" in ids:
            return "write_file commit_with_secret"
        return "write_file"

    labels = ["shell_execute"]
    if "delete" in ids:
        labels.append("delete_file")
    if "privilege" in ids:
        labels.append("escalate")
    if "publish" in ids:
        labels.append("package_publish")
    if "exfil" in ids:
        labels.append("email_external")
    return " ".join(labels)


def _safe_evidence(
    tool: str,
    payload: dict,
    local: policy.Decision,
    surface: str,
) -> dict:
    if surface == "prompt":
        content = str(payload.get("prompt") or "")
        target_kind, labels, target_digest = "model_provider", [], _digest("model_provider")
    elif surface == "command":
        content = _extract_command(payload)
        target_kind, labels, target_digest = _safe_target(tool, payload)
    else:
        content = _extract_content(payload)
        target_kind, labels, target_digest = _safe_target(tool, payload)

    policy_ids = sorted({
        finding.rule_id for finding in local.findings
        if re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", finding.rule_id)
    })[:128]
    joined = " ".join(policy_ids).lower()
    risk_score, risk_level = _risk_for(local)

    if any(word in joined for word in ("secret", "credential", "key", "token", "password")):
        labels.extend(["credential", "secret"])

    return {
        "surface": surface,
        "tool": tool[:64],
        "operation": _semantic_operation(tool, local),
        "target_kind": target_kind,
        "target_labels": sorted(set(labels))[:20],
        "target_digest": target_digest,
        "content_digest": _digest(content),
        "content_length": min(len(content), 10_000_000),
        "local_decision": local.decision,
        "local_policy_ids": policy_ids,
        "local_findings_count": min(len(local.findings), 10_000),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "is_sensitive": bool(local.findings),
        "prompt_injection_risk": "prompt_injection" in joined,
        "signals": {
            "secret_in_repo_commit": bool(
                surface == "write" and any(word in joined for word in ("secret", "credential", "key", "token"))
            ),
            "shell_access": surface == "command",
            "prompt_count_hour": 1 if surface == "prompt" else 0,
        },
    }


def _remote_decision(
    tool: str,
    payload: dict,
    local: policy.Decision,
    surface: str,
) -> policy.Decision | None:
    """Ask a reachable Enkstein backend to apply the full Trust Fabric.

    Returns None when no backend is configured or it does not answer promptly,
    so the local pack stays authoritative rather than the call hanging.
    """
    base = os.environ.get("ENKSTEIN_API_URL", "").strip()
    if not base:
        return None

    import urllib.error
    import urllib.request

    body = json.dumps(_safe_evidence(tool, payload, local, surface)).encode()

    request = urllib.request.Request(
        base.rstrip("/") + "/api/v1/trust-fabric/guard/evaluate",
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
    action = str(data.get("policy_action") or "").lower()
    allowed = data.get("allowed")

    if action in ("deny", "isolate") or outcome == "blocked":
        decision = policy.DENY
    elif action == "require_approval" or outcome == "requires_approval":
        decision = policy.REQUIRE_APPROVAL
    elif action == "monitor":
        decision = policy.MONITOR
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
    if decision != policy.ALLOW:
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


# Fields that carry text a mask rule may rewrite. Keys are patched in place so
# the returned object still satisfies the tool's own input schema, which Claude
# Code validates before accepting `updatedInput`.
_MASKABLE_KEYS = ("content", "new_string", "new_str", "text", "patch",
                  "contents", "source", "command", "cmd", "script")


def _apply_mask(tool: str, payload: dict) -> tuple[dict | None, list[policy.Finding]]:
    """Rewrite flagged values inside the tool input, leaving structure intact.

    Returns the updated payload and what was masked, or (None, []) if nothing
    matched. Only string fields are touched: replacing a path or a line number
    would fail the tool's schema and the edit would be discarded silently.
    """
    scope = "command" if tool in COMMAND_TOOLS else "content"
    updated = dict(payload)
    applied: list[policy.Finding] = []

    for key in _MASKABLE_KEYS:
        value = updated.get(key)
        if not isinstance(value, str) or not value:
            continue
        masked, findings = policy.redact(value, scope)
        if findings:
            updated[key] = masked
            applied.extend(findings)

    edits = updated.get("edits")
    if isinstance(edits, list):
        rebuilt = []
        for edit in edits:
            if not isinstance(edit, dict):
                rebuilt.append(edit)
                continue
            copy = dict(edit)
            for key in ("new_string", "new_str", "content"):
                value = copy.get(key)
                if not isinstance(value, str) or not value:
                    continue
                masked, findings = policy.redact(value, scope)
                if findings:
                    copy[key] = masked
                    applied.extend(findings)
            rebuilt.append(copy)
        if applied:
            updated["edits"] = rebuilt

    return (updated, applied) if applied else (None, [])


def _mask(tool: str, payload: dict, mode: str) -> None:
    """Let the call through with sensitive values replaced.

    Masking is the right answer when the developer's intent is legitimate but
    the payload carries something that should not travel: the work continues
    and the value does not. Blocking here would be theatre, since the file is
    already on disk in most cases.
    """
    updated, findings = _apply_mask(tool, payload)
    if updated is None:
        sys.exit(0)

    summary = "; ".join(f"{f.title} (line {f.line})" if f.line else f.title
                        for f in findings)
    rules = ", ".join(sorted({f.rule_id for f in findings}))
    note = (
        f"Enkstein masked sensitive values before this ran.\n"
        f"{summary}\n"
        f"Rule: {rules} ({mode} policy)\n"
        "The redacted placeholders are intentional. Do not try to restore the "
        "original values."
    )

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": note,
            "updatedInput": updated,
            "additionalContext": note,
        },
        "systemMessage": f"Enkstein masked {len(findings)} value(s) in a tool call.",
    }))
    sys.exit(0)


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
    surface = "command" if tool in COMMAND_TOOLS else "write"
    remote = _remote_decision(tool, payload, local, surface)
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

    local = policy.scan_prompt(prompt)
    remote = _remote_decision(
        "UserPromptSubmit",
        {"prompt": prompt},
        local,
        "prompt",
    )
    decision = local if remote is None else policy.combine(local, remote)
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
            "suppressOriginalPrompt": True,
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
        if decision.masked:
            _mask(tool, _tool_input(event), mode)
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        # A hook crash must not brick the editor.
        sys.exit(0)
    sys.exit(0)


if __name__ == "__main__":
    main()
