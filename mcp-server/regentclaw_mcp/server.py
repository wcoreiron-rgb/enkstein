"""
RegentClaw MCP Server
=====================
Exposes RegentClaw's governed security capabilities as Model Context Protocol
(MCP) tools, so AI agents inside Cursor, VS Code, Claude Desktop, etc. can call
them — with every call mediated by the running RegentClaw backend (Trust Fabric
policy, risk scoring, and audit apply server-side).

The server is a thin, stateless bridge: it forwards tool calls to the RegentClaw
REST API. It never holds credentials or executes anything locally.

Run (stdio transport, the default for editors):
    regentclaw-mcp

Configure via environment:
    REGENTCLAW_API_URL   default http://localhost:8000
    REGENTCLAW_TOKEN     Bearer JWT (required when the server runs DEBUG=false)
    REGENTCLAW_TIMEOUT   request timeout seconds (default 30)
"""
from __future__ import annotations

import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

BASE_URL = os.environ.get("REGENTCLAW_API_URL", "http://localhost:8000").rstrip("/")
PREFIX = "/api/v1"
TIMEOUT = float(os.environ.get("REGENTCLAW_TIMEOUT", "30"))

mcp = FastMCP("regentclaw")


def _headers() -> dict:
    token = os.environ.get("REGENTCLAW_TOKEN", "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


async def _get(path: str, params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=_headers()) as c:
        r = await c.get(BASE_URL + PREFIX + path, params=params)
        r.raise_for_status()
        return r.json()


async def _post(path: str, body: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=_headers()) as c:
        r = await c.post(BASE_URL + PREFIX + path, json=body or {})
        r.raise_for_status()
        return r.json()


def _safe(coro_result_err: str) -> str:
    return (
        f"⚠️ Could not reach RegentClaw at {BASE_URL}. "
        f"Is the server running and REGENTCLAW_API_URL set? ({coro_result_err})"
    )


# ── Tools ──────────────────────────────────────────────────────────────────────

@mcp.tool()
async def scan_text_for_secrets(text: str) -> str:
    """
    Scan a block of text or code for exposed secrets, API keys, PII, and
    prompt-injection patterns using RegentClaw's ArcClaw scanner + AGT audit.
    Use this before committing code or pasting config. Returns the risk score,
    whether sensitive data was detected, and the governance outcome.
    """
    try:
        r = await _post("/arcclaw/events", {
            "prompt_text": text,
            "tool_name": "mcp_scan",
            "provider": "mcp",
        })
        return (
            f"Sensitive data detected: {r.get('is_sensitive')}\n"
            f"Risk score: {r.get('risk_score')}\n"
            f"Outcome: {r.get('outcome')}\n"
            f"Policy applied: {r.get('policy_applied')}"
        )
    except Exception as e:  # noqa: BLE001
        return _safe(str(e))


@mcp.tool()
async def get_security_posture() -> str:
    """
    Get the current platform security posture from RegentClaw — module counts,
    identities, connectors, high-risk events, blocked actions, and pending
    approvals. Use to answer "what's my current security status?".
    """
    try:
        d = await _get("/dashboard")
        return (
            f"Active modules: {d.get('active_modules')}/{d.get('total_modules')}\n"
            f"Identities: {d.get('total_identities')}\n"
            f"Connectors: {d.get('total_connectors')} ({d.get('pending_connectors')} pending)\n"
            f"High-risk events: {d.get('high_risk_events')}\n"
            f"Blocked actions (24h): {d.get('blocked_actions_24h')}\n"
            f"Pending approvals: {d.get('pending_approvals')}"
        )
    except Exception as e:  # noqa: BLE001
        return _safe(str(e))


@mcp.tool()
async def list_findings(claw: str = "", severity: str = "", limit: int = 20) -> str:
    """
    List security findings, optionally filtered by claw (e.g. cloudclaw,
    identityclaw, devclaw) and severity (critical, high, medium, low).
    Returns a concise list of titles with provider and severity.
    """
    try:
        params: dict = {"limit": limit}
        if claw:
            params["claw"] = claw
        if severity:
            params["severity"] = severity
        items = await _get("/findings", params)
        if not isinstance(items, list) or not items:
            return "No findings match the filter."
        lines = [
            f"[{f.get('severity','?').upper()}] {f.get('title','(no title)')} "
            f"— {f.get('claw','?')}/{f.get('provider','?')}"
            for f in items[:limit]
        ]
        return "\n".join(lines)
    except Exception as e:  # noqa: BLE001
        return _safe(str(e))


@mcp.tool()
async def list_connectors() -> str:
    """
    List configured RegentClaw connectors (integrations) and their status.
    Useful to see which security tools are connected (Okta, CrowdStrike, AWS…).
    """
    try:
        items = await _get("/connectors")
        if not isinstance(items, list) or not items:
            return "No connectors configured."
        return "\n".join(
            f"{c.get('name','?')} ({c.get('connector_type','?')}) — {c.get('status','?')}"
            for c in items[:50]
        )
    except Exception as e:  # noqa: BLE001
        return _safe(str(e))


@mcp.tool()
async def run_swarm_investigation(prompt: str, window: str = "24h") -> str:
    """
    Launch a governed multi-agent Swarm investigation in RegentClaw. The swarm
    runs multiple security claws in parallel, then a judge synthesizes findings.
    High-risk remediation actions still require human approval in the platform.
    Returns the swarm job id and initial status. Describe what to investigate in
    `prompt` (e.g. "investigate suspicious identity activity for user@corp.com").
    """
    try:
        r = await _post("/swarm/jobs", {
            "name": f"MCP Investigation — {prompt[:80]}",
            "profile": "DEEP_INVESTIGATION",
            "requested_by": "mcp-client",
            "trigger_type": "mcp",
            "classification": "internal",
            "participants": ["devclaw", "threatclaw", "cloudclaw", "identityclaw"],
            "task_type": "investigate_security_signal",
            "input": {
                "objective": prompt,
                "time_range": window,
                "source": "mcp",
            },
            "parallelism": 4,
            "model_profile": "swarm_judge_profile",
        })
        return (
            f"Swarm job created: {r.get('id', r.get('job_id', '?'))}\n"
            f"Status: {r.get('status', 'submitted')}\n"
            f"Track progress in the RegentClaw UI → Swarm."
        )
    except Exception as e:  # noqa: BLE001
        return _safe(str(e))


@mcp.tool()
async def terraclaw_generate_secure_terraform(
    description: str,
    cloud: str = "azure",
    environment: str = "dev",
    workspace: str = "default",
) -> str:
    """
    Ask TerraClaw to generate secure Terraform from a natural-language deployment
    request. The backend runs Trust Fabric policy checks and TerraClaw review
    before returning the module. Use for secure-by-default IaC drafts.
    """
    try:
        r = await _post("/terraclaw/generate", {
            "description": description,
            "cloud": cloud.lower(),
            "environment": environment,
            "workspace": workspace,
        })
        return (
            f"Decision: {r.get('decision')} | Risk: {r.get('risk_score')}/100 | "
            f"Secure Score: {r.get('secure_score')}/100\n"
            f"Template: {r.get('template_name', r.get('template_used'))}\n"
            f"Generate ID: {r.get('generate_id')}\n\n"
            f"{r.get('terraform', '')}"
        )
    except Exception as e:  # noqa: BLE001
        return _safe(str(e))


@mcp.tool()
async def terraclaw_review_hcl(hcl: str, context: str = "") -> str:
    """
    Review Terraform HCL with TerraClaw's governed rule engine. Returns the
    APPROVE/WARN/BLOCK decision, risk score, and remediation findings.
    """
    try:
        r = await _post("/terraclaw/review", {"hcl": hcl, "context": context})
        findings = r.get("findings") or []
        lines = [
            f"Decision: {r.get('decision')} | Risk: {r.get('risk_score')}/100 | "
            f"Secure Score: {r.get('secure_score')}/100",
            f"Findings: {r.get('finding_count', len(findings))}",
        ]
        for f in findings[:8]:
            lines.append(f"- [{f.get('severity')}] {f.get('id')}: {f.get('name')} — {f.get('remediation')}")
        return "\n".join(lines)
    except Exception as e:  # noqa: BLE001
        return _safe(str(e))


@mcp.tool()
async def terraclaw_analyze_plan(changes: list[dict], context: str = "") -> str:
    """
    Analyze Terraform plan changes before apply. Pass a normalized list of
    changes with action, resource_type, resource_name, and attribute_changes.
    """
    try:
        r = await _post("/terraclaw/plan", {"changes": changes, "context": context})
        risky = r.get("risky_changes") or []
        lines = [
            f"Decision: {r.get('decision')} | Risk: {r.get('risk_score')}/100",
            f"Changes: {r.get('summary', {}).get('total_changes', len(changes))} | Risky: {len(risky)}",
        ]
        for item in risky[:8]:
            lines.append(f"- [{item.get('severity')}] {item.get('resource')}: {item.get('reason')}")
        return "\n".join(lines)
    except Exception as e:  # noqa: BLE001
        return _safe(str(e))


def main() -> None:
    """Console-script entrypoint. Uses stdio transport (editor default)."""
    mcp.run()


if __name__ == "__main__":
    main()
