"""
Security Copilot Agent
==================================
Tool-calling AI agent for security operations.
Supports: CVE lookup, vulnerability scanning, MITRE ATT&CK,
findings queries, scan triggering, workflow execution, and alert sending.

Providers: Anthropic (Claude) | OpenAI (GPT-4o) | Ollama (fallback, no tools)
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── Internal API base ─────────────────────────────────────────────────────────
BASE = "http://localhost:8000/api/v1"
TIMEOUT = httpx.Timeout(30.0)

# ── Tool definitions (Anthropic format) ───────────────────────────────────────
TOOLS = [
    {
        "name": "lookup_cve",
        "description": "Look up a specific CVE by ID from NVD. Returns CVSS score, severity, description.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE ID e.g. CVE-2024-1234"}
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "scan_recent_vulnerabilities",
        "description": "Scan NVD+EPSS+CISA KEV for recent high/critical CVEs. Returns CVEs sorted by risk.",
        "input_schema": {
            "type": "object",
            "properties": {
                "days_back": {"type": "integer"},
                "cvss_min": {"type": "number"},
                "max_cves": {"type": "integer"},
            },
        },
    },
    {
        "name": "check_actively_exploited",
        "description": "Fetch CISA Known Exploited Vulnerabilities (KEV) catalog — CVEs being actively exploited in the wild.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer"}
            },
        },
    },
    {
        "name": "search_mitre_attack",
        "description": "Search MITRE ATT&CK techniques and tactics. Use for threat modeling and attack pattern analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_security_posture",
        "description": "Get overall security posture across all Capability Nodes — total/critical/high findings per domain.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "get_findings",
        "description": (
            "Get findings from a specific Capability Node. Capability ids: cloudclaw, exposureclaw, threatclaw, netclaw, "
            "endpointclaw, logclaw, accessclaw, dataclaw, appclaw, saasclaw, configclaw, complianceclaw, "
            "privacyclaw, vendorclaw, userclaw, insiderclaw, intelclaw, recoveryclaw, devclaw, "
            "attackpathclaw, automationclaw"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "claw": {"type": "string"},
                "severity": {"type": "string"},
                "limit": {"type": "integer"},
            },
            "required": ["claw"],
        },
    },
    {
        "name": "run_claw_scan",
        "description": "Trigger a fresh security scan on a Capability Node.",
        "input_schema": {
            "type": "object",
            "properties": {
                "claw": {"type": "string", "description": "e.g. cloudclaw, exposureclaw"}
            },
            "required": ["claw"],
        },
    },
    {
        "name": "run_identity_detection",
        "description": (
            "Run a focused identity-risk detection now using the approved identity connector "
            "and persisted identity evidence. Use this whenever the user asks to detect, "
            "investigate, monitor, or automate identity risk. Returns an execution receipt, "
            "connector state, data provenance, findings, and recommended actions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "focus": {
                    "type": "string",
                    "description": "Redacted identity or investigation focus; never include raw secrets or PII.",
                },
                "classification": {
                    "type": "string",
                    "enum": ["public", "internal", "confidential", "restricted"],
                },
            },
        },
    },
    {
        "name": "trigger_workflow",
        "description": "Trigger a security workflow/orchestration by name.",
        "input_schema": {
            "type": "object",
            "properties": {
                "workflow_name": {"type": "string"}
            },
            "required": ["workflow_name"],
        },
    },
    {
        "name": "send_security_alert",
        "description": "Create a security alert event in Enkstein (routable to Slack/Teams/PagerDuty).",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "message": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                },
            },
            "required": ["title", "message", "severity"],
        },
    },
    {
        "name": "get_recent_events",
        "description": "Get recent security events and alerts from Enkstein.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer"}
            },
        },
    },
    {
        "name": "list_connected_claws",
        "description": (
            "ALWAYS call this first when asked about findings, posture, scans, or workflows. "
            "Returns which Capability Nodes have real connectors configured vs which are unconnected. "
            "Only unconnected Capability Nodes should be told they need a data source."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
]


# ── Connector status helper ───────────────────────────────────────────────────

# Maps claw prefix → human label and what connector is needed
CLAW_CONNECTOR_INFO: dict[str, dict] = {
    "cloudclaw":      {"label": "Cloud Security",        "needs": "AWS Security Hub, Azure Defender, or GCP SCC"},
    "exposureclaw":   {"label": "Vulnerability Exposure", "needs": "Tenable, Qualys, Rapid7, or Defender TVM"},
    "threatclaw":     {"label": "Threat Intelligence",   "needs": "CrowdStrike, SentinelOne, or Microsoft Sentinel"},
    "netclaw":        {"label": "Network Security",      "needs": "Palo Alto, Fortinet, or Cisco Umbrella"},
    "endpointclaw":   {"label": "Endpoint Security",     "needs": "CrowdStrike Falcon, Defender for Endpoint, or Carbon Black"},
    "logclaw":        {"label": "Log Management",        "needs": "Splunk, Elastic SIEM, or Microsoft Sentinel"},
    "accessclaw":     {"label": "Access Control",        "needs": "Okta, Entra ID, or Ping Identity"},
    "dataclaw":       {"label": "Data Security",         "needs": "Varonis, Purview, or Macie"},
    "appclaw":        {"label": "Application Security",  "needs": "Snyk, Veracode, or Checkmarx"},
    "saasclaw":       {"label": "SaaS Security",         "needs": "Netskope, CASB, or Zscaler"},
    "configclaw":     {"label": "Cloud Configuration",   "needs": "AWS Config, Azure Policy, or GCP Security Command Center"},
    "complianceclaw": {"label": "Compliance",            "needs": "Drata, Vanta, or Secureframe"},
    "privacyclaw":    {"label": "Privacy",               "needs": "OneTrust or TrustArc"},
    "vendorclaw":     {"label": "Vendor Risk",           "needs": "BitSight, SecurityScorecard, or RiskRecon"},
    "userclaw":       {"label": "User Behavior",         "needs": "Okta, Azure AD, or Ping Identity"},
    "insiderclaw":    {"label": "Insider Threat",        "needs": "Proofpoint ITM, Microsoft Purview, or Forcepoint"},
    "automationclaw": {"label": "Automation Security",  "needs": "ServiceNow, Jira, or custom SOAR"},
    "attackpathclaw": {"label": "Attack Path Analysis",  "needs": "XM Cyber, Orca Security, or Tenable.ep"},
    "devclaw":        {"label": "DevSec",                "needs": "GitHub Advanced Security, GitLab SAST, or Snyk"},
    "intelclaw":      {"label": "Threat Intel",          "needs": "Recorded Future, ThreatConnect, or MISP"},
    "recoveryclaw":   {"label": "Recovery & Resilience", "needs": "Veeam, Rubrik, or Cohesity"},
    "identityclaw":   {"label": "Identity Security",     "needs": "Okta, Entra ID, or CyberArk"},
    "arcclaw":        {"label": "AI Security",           "needs": "AI provider via Connector Marketplace"},
}


async def _claw_has_connector(claw: str) -> bool:
    """Return True if the claw has at least one configured (credentials present) provider."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            r = await client.get(f"{BASE}/{claw}/providers")
            if r.status_code != 200:
                return False
            providers = r.json()
            # providers is a list of {provider, label, configured}
            if isinstance(providers, list):
                return any(p.get("configured") or p.get("connected") or p.get("ready") for p in providers)
            if isinstance(providers, dict):
                return any(
                    v.get("configured") or v.get("connected") or v.get("ready")
                    for v in providers.values() if isinstance(v, dict)
                )
    except Exception:
        pass
    return False


def _no_connector_response(claw: str, action: str = "query") -> dict:
    """Standard response when a claw has no connector configured."""
    info = CLAW_CONNECTOR_INFO.get(claw, {"label": claw, "needs": "a data source connector"})
    return {
        "no_connector": True,
        "claw": claw,
        "label": info["label"],
        "status": "no_data_source",
        "message": (
            f"{info['label']} ({claw}) has no connector configured. "
            f"There is no real data to {action}."
        ),
        "action_required": (
            f"To get real findings from {info['label']}, connect "
            f"{info['needs']} via Connector Marketplace → Add Connector."
        ),
    }


# ── Tool executor ─────────────────────────────────────────────────────────────

async def _execute_tool(name: str, inputs: dict, db) -> dict:
    """Execute a tool call and return the result."""
    try:
        if name == "lookup_cve":
            from app.services.intel_fetcher import lookup_cve
            cve_id = inputs.get("cve_id", "")
            result = await lookup_cve(cve_id)
            return result or {"error": f"CVE {cve_id} not found in NVD"}

        elif name == "scan_recent_vulnerabilities":
            from app.services.intel_fetcher import run_vulnerability_scan
            scan = await run_vulnerability_scan(
                days_back=min(int(inputs.get("days_back", 30)), 90),
                cvss_min=float(inputs.get("cvss_min", 7.0)),
                max_cves=min(int(inputs.get("max_cves", 20)), 30),
            )
            top = scan.get("all_cves", [])[:10]
            stats = scan.get("summary_stats", {})
            return {
                "summary": stats,
                "actively_exploited_count": len(scan.get("actively_exploited", [])),
                "top_cves": [
                    {
                        "cve_id": c["cve_id"],
                        "cvss": c.get("cvss_score"),
                        "severity": c.get("severity"),
                        "epss": round(c.get("epss_score", 0), 3),
                        "actively_exploited": c.get("actively_exploited", False),
                        "description": c.get("description", "")[:200],
                    }
                    for c in top
                ],
            }

        elif name == "check_actively_exploited":
            from app.services.intel_fetcher import fetch_cisa_kev
            kev_set = await fetch_cisa_kev()
            limit = min(int(inputs.get("limit", 15)), 50)
            kev_list = sorted(list(kev_set))[:limit]
            return {
                "total_in_kev": len(kev_set),
                "sample": kev_list,
                "note": (
                    "These CVEs are being actively exploited in the wild. "
                    "CISA mandates federal agencies patch them."
                ),
            }

        elif name == "search_mitre_attack":
            from app.services.intel_fetcher import fetch_mitre_techniques
            query = inputs.get("query", "").lower()
            limit = min(int(inputs.get("limit", 8)), 20)
            techniques = await fetch_mitre_techniques(limit=200)
            matched = [
                t for t in techniques
                if query in t.get("name", "").lower()
                or query in t.get("description", "").lower()
                or any(query in tac.lower() for tac in t.get("tactics", []))
                or query in t.get("technique_id", "").lower()
            ][:limit]
            return {
                "query": query,
                "matched": len(matched),
                "techniques": matched,
            }

        elif name == "list_connected_claws":
            all_claws = list(CLAW_CONNECTOR_INFO.keys())
            connected = []
            disconnected = []
            async with httpx.AsyncClient(timeout=httpx.Timeout(8.0)) as client:
                for claw in all_claws:
                    try:
                        r = await client.get(f"{BASE}/{claw}/providers")
                        if r.status_code == 200:
                            providers = r.json()
                            has_conn = False
                            if isinstance(providers, list):
                                has_conn = any(
                                    p.get("configured") or p.get("connected") or p.get("ready")
                                    for p in providers
                                )
                            info = CLAW_CONNECTOR_INFO.get(claw, {})
                            entry = {
                                "claw": claw,
                                "label": info.get("label", claw),
                                "connected": has_conn,
                            }
                            if has_conn:
                                connected.append(entry)
                            else:
                                disconnected.append({
                                    **entry,
                                    "needs": info.get("needs", "a connector"),
                                })
                        else:
                            disconnected.append({
                                "claw": claw,
                                "label": CLAW_CONNECTOR_INFO.get(claw, {}).get("label", claw),
                                "connected": False,
                                "needs": CLAW_CONNECTOR_INFO.get(claw, {}).get("needs", "a connector"),
                            })
                    except Exception:
                        pass
            return {
                "connected_count": len(connected),
                "disconnected_count": len(disconnected),
                "connected": connected,
                "disconnected": disconnected,
                "summary": (
                    f"{len(connected)} of {len(all_claws)} Capability Nodes have real data sources connected. "
                    + ("No Capability Nodes are connected yet — all data would be placeholder only."
                       if len(connected) == 0 else "")
                ),
            }

        elif name == "get_security_posture":
            # Pull stats from ALL claws — real connector data takes priority,
            # simulation/demo data is included but labelled clearly.
            all_posture_claws = list(CLAW_CONNECTOR_INFO.keys())
            real_claws = []
            demo_claws = []
            posture: dict = {}
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                for claw in all_posture_claws:
                    try:
                        r = await client.get(f"{BASE}/{claw}/stats")
                        if r.status_code == 200:
                            stats = r.json()
                            has_real = await _claw_has_connector(claw)
                            stats["_data_source"] = "real" if has_real else "simulation"
                            posture[claw] = stats
                            if has_real:
                                real_claws.append(claw)
                            else:
                                demo_claws.append(claw)
                    except Exception:
                        pass
            total_critical = sum(v.get("critical", 0) for v in posture.values())
            total_high = sum(v.get("high", 0) for v in posture.values())
            total_open = sum(v.get("open", 0) for v in posture.values())
            real_critical = sum(
                v.get("critical", 0) for k, v in posture.items()
                if v.get("_data_source") == "real"
            )
            return {
                "total_critical_findings": total_critical,
                "total_high_findings": total_high,
                "total_open_findings": total_open,
                "real_critical_findings": real_critical,
                "by_domain": posture,
                "real_connector_claws": real_claws,
                "simulation_claws": demo_claws,
                "risk_level": (
                    "CRITICAL" if real_critical > 5 else
                    "HIGH" if real_critical > 0 or total_critical > 10 else
                    "MEDIUM"
                ),
                "data_coverage_note": (
                    f"{len(real_claws)} claws have real connectors; "
                    f"{len(demo_claws)} claws are showing simulation/demo data. "
                    "Stats from simulation claws are illustrative only."
                ),
            }

        elif name == "get_findings":
            claw = inputs.get("claw", "").lower().strip()
            has_real = await _claw_has_connector(claw)
            limit = min(int(inputs.get("limit", 8)), 20)
            severity_filter = inputs.get("severity", "all").upper()
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                r = await client.get(f"{BASE}/{claw}/findings")
                if r.status_code != 200:
                    return {
                        "error": (
                            f"Capability '{claw}' not found. "
                            "Available: cloudclaw, exposureclaw, threatclaw, etc."
                        )
                    }
                findings = r.json()
            if severity_filter != "ALL":
                findings = [
                    f for f in findings
                    if f.get("severity", "").upper() == severity_filter
                ]
            findings = findings[:limit]
            return {
                "claw": claw,
                "data_source": "real" if has_real else "simulation",
                "count": len(findings),
                "findings": [
                    {
                        "title": f.get("title", ""),
                        "severity": f.get("severity", ""),
                        "status": f.get("status", ""),
                        "resource": f.get("resource_name", ""),
                        "description": (f.get("description", "") or "")[:200],
                        "remediation": (f.get("remediation", "") or "")[:150],
                        "risk_score": f.get("risk_score"),
                        "actively_exploited": f.get("actively_exploited", False),
                    }
                    for f in findings
                ],
            }

        elif name == "run_claw_scan":
            claw = inputs.get("claw", "").lower().strip()
            has_real = await _claw_has_connector(claw)
            async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
                r = await client.post(f"{BASE}/{claw}/scan")
                if r.status_code != 200:
                    return {"error": f"Scan failed for claw '{claw}'"}
                result = r.json()
                result["data_source"] = "real" if has_real else "simulation"
                return result

        elif name == "run_identity_detection":
            # Call the focused worker directly. This avoids a loopback HTTP request and
            # preserves the request transaction/audit boundary.
            from app.claws.identityclaw.routes import IdentityTaskRequest, run_identity_task

            task = IdentityTaskRequest(
                task_type="investigate_identity_risk",
                input={"focus": inputs.get("focus", "identity risk detection")},
                classification=inputs.get("classification", "confidential"),
                allowed_actions=["read", "analyze", "recommend"],
            )
            return await run_identity_task(task, db)

        elif name == "trigger_workflow":
            from sqlalchemy import select as sa_select
            from app.models.workflow import Workflow
            from app.services.workflow_runner import execute_workflow

            query = inputs.get("workflow_name", "").lower()
            result = await db.execute(
                sa_select(Workflow).where(Workflow.is_active == True)
            )
            workflows = result.scalars().all()
            match = next(
                (w for w in workflows if query in w.name.lower()),
                workflows[0] if workflows else None,
            )
            if not match:
                return {
                    "no_connector": True,
                    "status": "no_workflows",
                    "message": "No active workflows found. Seed workflows first via /admin/seed.",
                    "action_required": "Go to Orchestration Builder to create and activate a workflow.",
                }
            # Check if the workflow's target claws have any connectors
            run = await execute_workflow(match.id, "security_agent", db)
            return {
                "workflow": match.name,
                "run_id": str(run.id),
                "status": run.status.value,
                "summary": run.summary,
                "steps_completed": run.steps_completed,
                "duration_sec": run.duration_sec,
                "note": (
                    "Workflow executed against connected data sources only. "
                    "Steps targeting unconnected Capability Nodes returned no data."
                ),
            }

        elif name == "send_security_alert":
            from datetime import datetime
            from app.models.event import Event, EventSeverity, EventOutcome
            from app.services.alert_router import route_event_alert

            sev_map = {
                "info": EventSeverity.INFO,
                "low": EventSeverity.LOW,
                "medium": EventSeverity.MEDIUM,
                "high": EventSeverity.HIGH,
                "critical": EventSeverity.CRITICAL,
            }
            severity_str = inputs.get("severity", "medium")
            title = inputs.get("title", "Security Alert")
            description = inputs.get("message", "")

            event = Event(
                timestamp=datetime.utcnow(),
                source_module="arcclaw",
                actor_id="security_copilot",
                actor_name="Security Copilot",
                actor_type="ai_agent",
                action="send_alert",
                target=title,
                target_type="alert",
                outcome=EventOutcome.FLAGGED,
                severity=sev_map.get(severity_str, EventSeverity.MEDIUM),
                risk_score={"critical": 90.0, "high": 70.0, "medium": 50.0, "low": 25.0, "info": 10.0}.get(severity_str, 50.0),
                description=description,
                requires_review=severity_str in ("critical", "high"),
            )
            db.add(event)
            await db.flush()

            # Route to external channels (Slack/Teams/PagerDuty)
            alerts_sent = await route_event_alert(db, {
                "title": title,
                "description": description,
                "severity": severity_str,
                "claw": "arcclaw",
                "risk_score": event.risk_score,
            })

            return {
                "sent": True,
                "event_id": str(event.id),
                "title": title,
                "severity": severity_str,
                "alerts_routed": alerts_sent,
                "note": (
                    f"Alert created in Enkstein. "
                    f"{'Routed to ' + str(alerts_sent) + ' external channel(s).' if alerts_sent > 0 else 'No alert channels configured — add Slack/Teams/PagerDuty connector to route externally.'}"
                ),
            }

        elif name == "get_recent_events":
            from sqlalchemy import select as sa_select, desc
            from app.models.event import Event

            limit = min(int(inputs.get("limit", 10)), 50)
            result = await db.execute(
                sa_select(Event).order_by(desc(Event.timestamp)).limit(limit)
            )
            events = result.scalars().all()
            return {
                "count": len(events),
                "events": [
                    {
                        "action": e.action,
                        "severity": e.severity.value if hasattr(e.severity, "value") else e.severity,
                        "outcome": e.outcome.value if hasattr(e.outcome, "value") else e.outcome,
                        "source_module": e.source_module,
                        "description": (e.description or "")[:200],
                        "risk_score": e.risk_score,
                        "requires_review": e.requires_review,
                        "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                    }
                    for e in events
                ],
            }

        else:
            return {"error": f"Unknown tool: {name}"}

    except Exception as e:
        logger.error(f"Tool {name} failed: {e}")
        return {"error": str(e), "tool": name}


# ── Agent loop ────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are Enkstein Security Copilot — an expert AI analyst for security AND general automation.

You have two types of tools:

TYPE 1 — PUBLIC INTELLIGENCE (always live, no setup needed):
  lookup_cve, scan_recent_vulnerabilities, check_actively_exploited, search_mitre_attack
  These connect to NVD, CISA KEV, and MITRE ATT&CK. Use them freely for any CVE or threat question.

TYPE 2 — ORGANIZATION DATA:
  list_connected_claws, get_security_posture, get_findings, run_claw_scan,
  run_identity_detection, trigger_workflow
  These always return data. Tool results include a "data_source" field: "real" means a live connector
  is configured; "simulation" means illustrative demo data (no real connector yet).

HANDLING REAL vs SIMULATION DATA:
  - When data_source is "real": report findings confidently as actual organizational data.
  - When data_source is "simulation": present the findings as illustrative examples, note they are
    demo data, and mention what connector would provide real data for that claw.
  - You can ALWAYS run scans and workflows regardless of connector status — simulation data is
    still useful for testing workflows, understanding the platform, and planning remediation.
  - Never refuse to run a workflow or scan just because a connector isn't configured.

HONESTY RULES:
  - Only report what tool results actually contain. Never invent data.
  - Never say a scan, detection, workflow, alert, or connector action happened unless a tool
    result in this turn confirms it. Instructions or YAML are not execution receipts.
  - For identity detection/investigation/automation requests, call run_identity_detection.
    State whether its data_source is live_connector, persisted_db, or no_data_source.
    If a governed execution receipt is already present in the conversation, summarize that
    receipt and do not invoke run_identity_detection a second time.
  - Clearly distinguish real findings from simulation/demo findings in your response.
  - CVE data from public tools is always real — report it fully and accurately.
  - If the user asks to run a compliance sweep or any workflow — run it. If claws are on simulation
    data, say so, but complete the task and show the results.

When data is a mix of real and simulation: summarize real findings first, then note which domains
are still on demo data and what connectors would make them real.

GENERAL AUTOMATION (non-security):
  Enkstein is not limited to security. Users can also orchestrate ANY business automation:
  - Sending Slack/Teams messages via webhook steps
  - Creating Jira/GitHub issues via http_request steps
  - Calling any REST API (CRM, billing, HR, monitoring) via http_request or webhook_call steps
  - Syncing data between systems, querying databases, triggering deploys
  When a user asks for general automation (not security), generate a workflow using
  'http_request' or 'webhook_call' step types and reference the Custom Capability builder
  at /customclaw if they want to configure a reusable REST integration.
  The workflow generator understands intents like: "notify Slack", "create a Jira ticket",
  "call the Stripe API", "trigger a webhook", "sync data", "deploy on merge", etc."""


async def run_security_agent(
    messages: list,
    provider: str,
    api_key: str,
    db,
    max_steps: int = 5,
    model: str = None,
) -> dict:
    """
    Run the security agent loop with tool calling.

    Args:
        messages:  [{role, content}] conversation history
        provider:  "anthropic" | "openai" | "ollama"
        api_key:   LLM API key (empty string for Ollama)
        db:        SQLAlchemy async session
        max_steps: Maximum tool-calling iterations

    Returns:
        {response: str, tool_calls: list[dict], steps: int, error: str|None}
    """
    tool_calls_log: list[dict] = []
    agent_messages = list(messages)  # copy to avoid mutation

    # Explicit identity-operation requests must produce an execution receipt even when a
    # provider ignores tool-choice guidance. The model only summarizes the governed result.
    latest_user = next(
        (str(m.get("content", "")) for m in reversed(agent_messages) if m.get("role") == "user"),
        "",
    )
    normalized = latest_user.lower()
    identity_operation = "identity" in normalized and any(
        word in normalized
        for word in ("detect", "investigat", "monitor", "scan", "automate", "risk")
    )
    if identity_operation:
        t_start = asyncio.get_event_loop().time()
        execution = await _execute_tool(
            "run_identity_detection",
            {"focus": latest_user, "classification": "confidential"},
            db,
        )
        tool_calls_log.append({
            "tool": "run_identity_detection",
            "input": {"focus": "[REDACTED REQUEST CONTEXT]", "classification": "confidential"},
            "result": execution,
            "duration_ms": int((asyncio.get_event_loop().time() - t_start) * 1000),
        })
        agent_messages.append({
            "role": "user",
            "content": (
                "A governed identity detection was executed for this request. Summarize this "
                "execution receipt accurately. Do not claim live coverage when data_source is "
                f"not live_connector. Receipt: {json.dumps(execution, default=str)}"
            ),
        })

    if provider == "anthropic":
        return await _run_anthropic_agent(
            agent_messages, api_key, SYSTEM_PROMPT, tool_calls_log, db, max_steps,
            model=model or "claude-opus-4-5",
        )
    elif provider == "openai":
        return await _run_openai_agent(
            agent_messages, api_key, SYSTEM_PROMPT, tool_calls_log, db, max_steps,
            model=model or "gpt-4o",
        )
    elif provider == "nvidia":
        # NVIDIA NIM is OpenAI-compatible — reuse OpenAI agent loop with NIM base URL
        return await _run_openai_agent(
            agent_messages, api_key, SYSTEM_PROMPT, tool_calls_log, db, max_steps,
            model=model or "nvidia/nemotron-4-340b-instruct",
            base_url="https://integrate.api.nvidia.com/v1",
        )
    else:
        # Ollama — use specified model; tool injection provides live data
        return await _run_simple_agent(agent_messages, provider, api_key, SYSTEM_PROMPT,
                                       model=model, db=db, initial_tool_calls=tool_calls_log)


# ── Anthropic agent loop ──────────────────────────────────────────────────────

async def _run_anthropic_agent(
    messages: list,
    api_key: str,
    system: str,
    tool_calls_log: list,
    db,
    max_steps: int,
    model: str = "claude-opus-4-5",
) -> dict:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    current_messages = [{"role": m["role"], "content": m["content"]} for m in messages]
    step = 0

    while step < max_steps:
        step += 1
        payload = {
            "model": model,
            "max_tokens": 4096,
            "system": system,
            "tools": TOOLS,
            "messages": current_messages,
        }

        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload,
            )
            if r.status_code != 200:
                return {
                    "response": f"API error: {r.status_code} {r.text[:200]}",
                    "tool_calls": tool_calls_log,
                    "steps": step,
                    "error": r.text,
                }
            data = r.json()

        stop_reason = data.get("stop_reason")
        content = data.get("content", [])

        if stop_reason == "end_turn":
            text_blocks = [b["text"] for b in content if b.get("type") == "text"]
            final_text = "\n".join(text_blocks)
            return {
                "response": final_text,
                "tool_calls": tool_calls_log,
                "steps": step,
                "error": None,
            }

        elif stop_reason == "tool_use":
            current_messages.append({"role": "assistant", "content": content})

            tool_results = []
            for block in content:
                if block.get("type") != "tool_use":
                    continue
                tool_name = block["name"]
                tool_input = block.get("input", {})
                tool_use_id = block["id"]

                t_start = asyncio.get_event_loop().time()
                result = await _execute_tool(tool_name, tool_input, db)
                t_end = asyncio.get_event_loop().time()

                tool_calls_log.append({
                    "tool": tool_name,
                    "input": tool_input,
                    "result": result,
                    "duration_ms": int((t_end - t_start) * 1000),
                })

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": json.dumps(result, default=str),
                })

            current_messages.append({"role": "user", "content": tool_results})

        else:
            text_blocks = [b.get("text", "") for b in content if b.get("type") == "text"]
            return {
                "response": "\n".join(text_blocks) or "Unexpected stop.",
                "tool_calls": tool_calls_log,
                "steps": step,
                "error": None,
            }

    return {
        "response": "Maximum steps reached.",
        "tool_calls": tool_calls_log,
        "steps": step,
        "error": "max_steps",
    }


# ── OpenAI agent loop ─────────────────────────────────────────────────────────

async def _run_openai_agent(
    messages: list,
    api_key: str,
    system: str,
    tool_calls_log: list,
    db,
    max_steps: int,
    model: str = "gpt-4o",
    base_url: str = "https://api.openai.com/v1",
) -> dict:
    """
    OpenAI-compatible agent loop.
    Works with OpenAI, NVIDIA NIM, or any OpenAI-compatible API —
    just pass a different base_url (e.g. https://integrate.api.nvidia.com/v1).
    """
    openai_tools = [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in TOOLS
    ]
    current_messages = [{"role": "system", "content": system}] + list(messages)
    step = 0

    while step < max_steps:
        step += 1
        payload = {
            "model": model,
            "messages": current_messages,
            "tools": openai_tools,
            "tool_choice": "auto",
        }

        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
            r = await client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if r.status_code != 200:
                return {
                    "response": f"OpenAI error: {r.status_code}",
                    "tool_calls": tool_calls_log,
                    "steps": step,
                    "error": r.text,
                }
            data = r.json()

        choice = data["choices"][0]
        msg = choice["message"]
        finish = choice["finish_reason"]

        if finish in ("stop", "length"):
            return {
                "response": msg.get("content", ""),
                "tool_calls": tool_calls_log,
                "steps": step,
                "error": None,
            }

        elif finish == "tool_calls":
            current_messages.append(msg)
            for tc in (msg.get("tool_calls") or []):
                fn = tc["function"]
                tool_input = json.loads(fn.get("arguments", "{}"))

                t_start = asyncio.get_event_loop().time()
                result = await _execute_tool(fn["name"], tool_input, db)
                t_end = asyncio.get_event_loop().time()

                tool_calls_log.append({
                    "tool": fn["name"],
                    "input": tool_input,
                    "result": result,
                    "duration_ms": int((t_end - t_start) * 1000),
                })

                current_messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": json.dumps(result, default=str),
                })

        else:
            return {
                "response": msg.get("content", "Done."),
                "tool_calls": tool_calls_log,
                "steps": step,
                "error": None,
            }

    return {
        "response": "Max steps reached.",
        "tool_calls": tool_calls_log,
        "steps": step,
        "error": "max_steps",
    }


# ── Simple fallback (Ollama — manual tool injection) ─────────────────────────

async def _run_simple_agent(
    messages: list,
    provider: str,
    api_key: str,
    system: str,
    model: str = None,
    db=None,
    initial_tool_calls: list[dict] | None = None,
) -> dict:
    """
    Ollama fallback — no native tool calling.
    We detect security intent, pre-call the relevant tools, inject
    live results as context, then ask Ollama to reason over real data.
    This prevents hallucination of outdated CVE/vulnerability information.
    """
    import re
    from datetime import datetime as dt
    from app.claws.arcclaw.llm_proxy import call_llm

    user_turns = [m["content"] for m in messages if m["role"] == "user"]
    last_user = next(
        (m for m in reversed(user_turns) if not m.startswith("A governed identity detection was executed")),
        "Hello",
    )
    last_lower = last_user.lower()
    tool_calls_log: list[dict] = list(initial_tool_calls or [])
    context_blocks: list[str] = []
    for call in tool_calls_log:
        context_blocks.append(
            "## Governed execution receipt\n"
            f"```json\n{json.dumps(call.get('result', {}), indent=2, default=str)}\n```"
        )

    # ── Intent detection → pre-call tools ─────────────────────────────────────
    # Separate public-intel queries (CVE/MITRE) from org-data queries (findings/posture).
    # Never mix them — org-data queries require connectors; CVE queries never do.

    # Public CVE/threat intelligence (TYPE 1 — no connectors needed)
    is_cve_intent = any(w in last_lower for w in [
        "cve", "nvd", "epss", "kev", "cisa", "exploit", "patch",
        "scan for cve", "cves this week", "recent cve", "new vuln",
        "this week", "latest cve", "published this"
    ])
    is_mitre_intent = any(w in last_lower for w in [
        "mitre", "att&ck", "attack technique", "lateral movement",
        "tactic", "technique", "ttp", "initial access", "persistence",
        "privilege escalation", "exfiltration",
    ])

    # Org-data intent (TYPE 2 — connector gated)
    is_org_intent = any(w in last_lower for w in [
        "posture", "security status", "how am i", "our org", "our environment",
        "my org", "finding", "run scan", "trigger", "workflow", "sweep",
        "compliance check", "show me critical", "show critical",
        "cloud finding", "identity risk", "critical cloud",
    ])

    try:
        # ── TYPE 1: Public intelligence tools ─────────────────────────────────

        # Specific CVE lookup
        cve_match = re.search(r"CVE-\d{4}-\d+", last_user, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0).upper()
            t0 = asyncio.get_event_loop().time()
            result = await _execute_tool("lookup_cve", {"cve_id": cve_id}, db)
            ms = int((asyncio.get_event_loop().time() - t0) * 1000)
            tool_calls_log.append({"tool": "lookup_cve", "input": {"cve_id": cve_id},
                                   "result": result, "duration_ms": ms})
            context_blocks.append(
                f"## CVE Lookup — {cve_id}\n"
                f"```json\n{json.dumps(result, indent=2, default=str)}\n```"
            )

        # Recent vulnerability scan
        if is_cve_intent and not cve_match:
            days = 7 if any(w in last_lower for w in ["week", "7 day", "this week"]) else 30
            t0 = asyncio.get_event_loop().time()
            result = await _execute_tool(
                "scan_recent_vulnerabilities",
                {"days_back": days, "cvss_min": 7.0, "max_cves": 10}, db
            )
            ms = int((asyncio.get_event_loop().time() - t0) * 1000)
            tool_calls_log.append({"tool": "scan_recent_vulnerabilities",
                                   "input": {"days_back": days}, "result": result, "duration_ms": ms})
            context_blocks.append(
                f"## Recent Vulnerability Scan (last {days} days, CVSS ≥ 7.0)\n"
                f"```json\n{json.dumps(result, indent=2, default=str)}\n```"
            )

        # Actively exploited / CISA KEV
        if any(w in last_lower for w in [
            "actively exploit", "kev", "known exploit", "in the wild",
            "cisa", "exploited right now", "being exploited"
        ]):
            t0 = asyncio.get_event_loop().time()
            result = await _execute_tool("check_actively_exploited", {"limit": 20}, db)
            ms = int((asyncio.get_event_loop().time() - t0) * 1000)
            tool_calls_log.append({"tool": "check_actively_exploited",
                                   "input": {"limit": 20}, "result": result, "duration_ms": ms})
            context_blocks.append(
                f"## CISA KEV — Actively Exploited CVEs\n"
                f"```json\n{json.dumps(result, indent=2, default=str)}\n```"
            )

        # MITRE ATT&CK
        if is_mitre_intent:
            mitre_keywords = [
                "lateral movement", "privilege escalation", "persistence",
                "exfiltration", "command and control", "initial access",
                "defense evasion", "credential access",
            ]
            query = next((q for q in mitre_keywords if q in last_lower), last_user[:60])
            t0 = asyncio.get_event_loop().time()
            result = await _execute_tool("search_mitre_attack", {"query": query, "limit": 6}, db)
            ms = int((asyncio.get_event_loop().time() - t0) * 1000)
            tool_calls_log.append({"tool": "search_mitre_attack",
                                   "input": {"query": query}, "result": result, "duration_ms": ms})
            context_blocks.append(
                f"## MITRE ATT&CK — \"{query}\"\n"
                f"```json\n{json.dumps(result, indent=2, default=str)}\n```"
            )

        # ── TYPE 2: Org data tools — check connectors first ────────────────────
        if is_org_intent and db and not is_cve_intent and not is_mitre_intent:
            t0 = asyncio.get_event_loop().time()
            conn_result = await _execute_tool("list_connected_claws", {}, db)
            ms = int((asyncio.get_event_loop().time() - t0) * 1000)
            tool_calls_log.append({"tool": "list_connected_claws",
                                   "input": {}, "result": conn_result, "duration_ms": ms})
            context_blocks.append(
                f"## Connector Status (which Claws have real data sources)\n"
                f"```json\n{json.dumps(conn_result, indent=2, default=str)}\n```"
            )
            # Always pull posture — includes real + simulation data, labelled clearly
            t0 = asyncio.get_event_loop().time()
            result = await _execute_tool("get_security_posture", {}, db)
            ms = int((asyncio.get_event_loop().time() - t0) * 1000)
            tool_calls_log.append({"tool": "get_security_posture",
                                   "input": {}, "result": result, "duration_ms": ms})
            context_blocks.append(
                f"## Security Posture (real connectors + simulation data labelled)\n"
                f"```json\n{json.dumps(result, indent=2, default=str)}\n```"
            )

    except Exception as tool_err:
        logger.warning(f"Ollama tool injection error (non-fatal): {tool_err}")

    # ── Build enriched prompt with live data ───────────────────────────────────
    today = dt.utcnow().strftime("%Y-%m-%d")
    if context_blocks:
        live_section = "\n\n".join(context_blocks)
        has_org_data = any("Connector Status" in b or "Security Posture" in b for b in context_blocks)
        instructions = (
            "Summarize the live data above clearly. "
            "Cite specific CVE IDs, CVSS scores, and exploitation status from the data. "
            + (
                "For org-data sections showing no_connector or 0 connected claws: "
                "tell the user that domain has no data source and what they need to connect. "
                if has_org_data else ""
            )
            + "Do not invent any specific names, IDs, or scores not present in the data above."
        )
        enriched_prompt = (
            f"# Live Security Data — {today}\n\n"
            f"{live_section}\n\n"
            f"---\n\n"
            f"**User question:** {last_user}\n\n"
            f"{instructions}"
        )
    else:
        enriched_prompt = last_user

    result = await call_llm(
        provider=provider,
        prompt=enriched_prompt,
        system=system,
        api_key=api_key,
        model=model,
    )
    return {
        "response": result.content if result.success else f"LLM error: {result.error}",
        "tool_calls": tool_calls_log,
        "steps": 1 + len(tool_calls_log),
        "error": None if result.success else result.error,
    }
