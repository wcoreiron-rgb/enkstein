"""
Enkstein — Alert Router
Routes high-risk findings and policy violations to configured notification channels:
  - Slack webhooks
  - PagerDuty Events API v2
  - Microsoft Teams webhooks
  - Email (via SMTP or SendGrid)

Alert routing is connector-driven: channels are only active if the corresponding
connector has been configured with valid credentials in the secrets manager.

Called automatically by finding_pipeline.py for findings above the risk threshold.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.connector import Connector, ConnectorStatus
from app.models.finding import Finding, FindingSeverity
from app.services import secrets_manager

logger = logging.getLogger("alert_router")

# Connector types that support alert delivery
ALERT_CONNECTOR_TYPES = {"slack", "pagerduty", "teams", "email", "sendgrid"}

# Severity color codes for Slack/Teams formatting
_SEVERITY_COLOR = {
    FindingSeverity.CRITICAL: "#FF0000",
    FindingSeverity.HIGH:     "#FF6600",
    FindingSeverity.MEDIUM:   "#FFAA00",
    FindingSeverity.LOW:      "#0066FF",
    FindingSeverity.INFO:     "#888888",
}

_SEVERITY_PAGERDUTY = {
    FindingSeverity.CRITICAL: "critical",
    FindingSeverity.HIGH:     "error",
    FindingSeverity.MEDIUM:   "warning",
    FindingSeverity.LOW:      "info",
    FindingSeverity.INFO:     "info",
}


def _finding_summary(finding: Finding) -> str:
    """Short one-line summary for notification subjects."""
    kev = " [KEV]" if finding.actively_exploited else ""
    return f"[{finding.severity.upper()}]{kev} {finding.title[:180]}"


async def _get_alert_connectors(db: AsyncSession) -> list[dict]:
    """
    Query the DB for all approved alert connectors with stored credentials.
    Returns list of {connector_type, credentials} dicts.
    """
    result = await db.execute(
        select(Connector)
        .where(Connector.status == ConnectorStatus.APPROVED)
        .where(Connector.connector_type.in_(ALERT_CONNECTOR_TYPES))
    )
    connectors = result.scalars().all()

    active = []
    for conn in connectors:
        creds = secrets_manager.get_credential(str(conn.id))
        if creds:
            active.append({
                "id": str(conn.id),
                "name": conn.name,
                "connector_type": conn.connector_type,
                "credentials": creds,
                "endpoint": conn.endpoint,
            })
    return active


# ─── Slack ───────────────────────────────────────────────────────────────────

async def _send_slack(
    client: httpx.AsyncClient,
    webhook_url: str,
    finding: Finding,
) -> bool:
    """Post a finding alert to a Slack webhook."""
    color = _SEVERITY_COLOR.get(finding.severity, "#888888")
    kev_block = ""
    if finding.actively_exploited:
        kev_block = "\n🚨 *CISA KEV — Actively Exploited in the Wild*"

    payload = {
        "attachments": [
            {
                "color": color,
                "fallback": _finding_summary(finding),
                "title": f"Enkstein Alert — {finding.severity.upper()} Finding",
                "text": (
                    f"*{finding.title[:256]}*{kev_block}\n"
                    f"Capability: `{finding.claw}` | Provider: `{finding.provider}` | "
                    f"Risk Score: `{finding.risk_score:.0f}/100`"
                ),
                "fields": [
                    {"title": "Severity",  "value": finding.severity.upper(), "short": True},
                    {"title": "Risk Score","value": f"{finding.risk_score:.0f}", "short": True},
                    {"title": "Category",  "value": finding.category or "—", "short": True},
                    {"title": "Status",    "value": finding.status, "short": True},
                ],
                "footer": "Enkstein Security Platform",
                "ts": int(datetime.utcnow().timestamp()),
            }
        ]
    }

    if finding.remediation:
        payload["attachments"][0]["fields"].append({
            "title": "Recommended Action",
            "value": finding.remediation[:300],
            "short": False,
        })

    try:
        resp = await client.post(webhook_url, json=payload, timeout=10.0)
        return resp.status_code == 200
    except Exception as exc:
        logger.warning("Slack webhook failed: %s", exc)
        return False


# ─── PagerDuty ───────────────────────────────────────────────────────────────

async def _send_pagerduty(
    client: httpx.AsyncClient,
    integration_key: str,
    finding: Finding,
) -> bool:
    """Send a PagerDuty event via the Events API v2."""
    severity = _SEVERITY_PAGERDUTY.get(finding.severity, "warning")

    payload = {
        "routing_key": integration_key,
        "event_action": "trigger",
        "dedup_key": f"regentclaw-{finding.claw}-{finding.external_id or str(finding.id)}",
        "payload": {
            "summary": _finding_summary(finding),
            "severity": severity,
            "source": f"Enkstein/{finding.claw}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "component": finding.claw,
            "group": "security",
            "class": finding.category or "security_finding",
            "custom_details": {
                "provider":          finding.provider,
                "risk_score":        finding.risk_score,
                "cvss_score":        finding.cvss_score,
                "actively_exploited": finding.actively_exploited,
                "external_id":       finding.external_id,
                "resource":          finding.resource_name or finding.resource_id,
            },
        },
    }

    if finding.reference_url:
        payload["links"] = [{"href": finding.reference_url, "text": "Reference"}]

    try:
        resp = await client.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
            timeout=10.0,
        )
        return resp.status_code in (200, 201, 202)
    except Exception as exc:
        logger.warning("PagerDuty send failed: %s", exc)
        return False


# ─── Microsoft Teams ─────────────────────────────────────────────────────────

async def _send_teams(
    client: httpx.AsyncClient,
    webhook_url: str,
    finding: Finding,
) -> bool:
    """Post a finding alert to a Microsoft Teams incoming webhook."""
    color = _SEVERITY_COLOR.get(finding.severity, "#888888").lstrip("#")
    kev_note = "🚨 **CISA KEV — Actively Exploited**\n\n" if finding.actively_exploited else ""

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": _finding_summary(finding),
        "sections": [
            {
                "activityTitle": f"**Enkstein — {finding.severity.upper()} Security Finding**",
                "activitySubtitle": f"Capability: {finding.claw} | Provider: {finding.provider}",
                "activityText": f"{kev_note}{finding.title[:256]}",
                "facts": [
                    {"name": "Severity",   "value": finding.severity.upper()},
                    {"name": "Risk Score", "value": f"{finding.risk_score:.0f} / 100"},
                    {"name": "Category",   "value": finding.category or "—"},
                    {"name": "Status",     "value": finding.status},
                    {"name": "External ID","value": finding.external_id or "—"},
                ],
            }
        ],
    }

    if finding.remediation:
        payload["sections"].append({
            "title": "Recommended Remediation",
            "text": finding.remediation[:400],
        })

    try:
        resp = await client.post(webhook_url, json=payload, timeout=10.0)
        return resp.status_code == 200
    except Exception as exc:
        logger.warning("Teams webhook failed: %s", exc)
        return False


# ─── Main Router ─────────────────────────────────────────────────────────────

async def route_findings(
    db: AsyncSession,
    claw: str,
    findings: list[Finding],
) -> int:
    """
    Route a list of findings to all configured alert channels.

    Args:
        db: Database session (used to query active connectors)
        claw: The claw that produced these findings
        findings: Pre-filtered list of high-risk findings to alert on

    Returns:
        Number of alerts successfully sent across all channels.
    """
    if not findings:
        return 0

    alert_connectors = await _get_alert_connectors(db)
    if not alert_connectors:
        logger.debug("No alert connectors configured — skipping alert routing for %s", claw)
        return 0

    sent = 0

    async with httpx.AsyncClient() as client:
        for finding in findings:
            for conn in alert_connectors:
                ctype = conn["connector_type"]
                creds = conn["credentials"]

                try:
                    success = False

                    if ctype == "slack":
                        webhook_url = creds.get("webhook_url") or conn.get("endpoint", "")
                        if webhook_url:
                            success = await _send_slack(client, webhook_url, finding)

                    elif ctype == "pagerduty":
                        integration_key = creds.get("integration_key") or creds.get("api_key", "")
                        if integration_key:
                            success = await _send_pagerduty(client, integration_key, finding)

                    elif ctype == "teams":
                        webhook_url = creds.get("webhook_url") or conn.get("endpoint", "")
                        if webhook_url:
                            success = await _send_teams(client, webhook_url, finding)

                    if success:
                        sent += 1
                        logger.info(
                            "Alert sent via %s [%s] for finding: %s",
                            ctype, conn["name"], finding.title[:80],
                        )

                except Exception as exc:
                    logger.error(
                        "Alert routing error via %s for finding %s: %s",
                        ctype, finding.id, exc, exc_info=True,
                    )

    return sent


async def route_event_alert(
    db: AsyncSession,
    event_data: dict[str, Any],
) -> int:
    """
    Route a raw event (dict) to alert channels.
    Used by orchestration workflows and AI Security governance alerts.

    event_data keys: title, description, severity, claw, risk_score, metadata
    """
    alert_connectors = await _get_alert_connectors(db)
    if not alert_connectors:
        return 0

    severity = event_data.get("severity", "medium")
    color = {
        "critical": "#FF0000",
        "high":     "#FF6600",
        "medium":   "#FFAA00",
        "low":      "#0066FF",
    }.get(severity.lower(), "#888888")

    sent = 0
    async with httpx.AsyncClient() as client:
        for conn in alert_connectors:
            ctype = conn["connector_type"]
            creds = conn["credentials"]
            try:
                if ctype == "slack":
                    webhook_url = creds.get("webhook_url") or conn.get("endpoint", "")
                    if not webhook_url:
                        continue
                    payload = {
                        "attachments": [{
                            "color": color,
                            "title": f"Enkstein Event — {severity.upper()}",
                            "text": event_data.get("title", "Security Event"),
                            "fields": [
                                {"title": "Description", "value": event_data.get("description", "")[:300], "short": False},
                                {"title": "Capability",  "value": event_data.get("claw", "—"), "short": True},
                                {"title": "Risk Score",  "value": str(event_data.get("risk_score", 0)), "short": True},
                            ],
                            "footer": "Enkstein Security Platform",
                            "ts": int(datetime.utcnow().timestamp()),
                        }]
                    }
                    resp = await client.post(webhook_url, json=payload, timeout=10.0)
                    if resp.status_code == 200:
                        sent += 1

                elif ctype == "pagerduty":
                    integration_key = creds.get("integration_key") or creds.get("api_key", "")
                    if not integration_key:
                        continue
                    pd_sev = {"critical": "critical", "high": "error", "medium": "warning"}.get(severity, "info")
                    payload = {
                        "routing_key": integration_key,
                        "event_action": "trigger",
                        "payload": {
                            "summary": event_data.get("title", "Enkstein Security Event")[:256],
                            "severity": pd_sev,
                            "source": f"Enkstein/{event_data.get('claw', 'system')}",
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                        },
                    }
                    resp = await client.post(
                        "https://events.pagerduty.com/v2/enqueue",
                        json=payload, timeout=10.0
                    )
                    if resp.status_code in (200, 201, 202):
                        sent += 1

                elif ctype == "teams":
                    webhook_url = creds.get("webhook_url") or conn.get("endpoint", "")
                    if not webhook_url:
                        continue
                    payload = {
                        "@type": "MessageCard",
                        "@context": "http://schema.org/extensions",
                        "themeColor": color.lstrip("#"),
                        "summary": event_data.get("title", "Security Event"),
                        "sections": [{
                            "activityTitle": f"**Enkstein — {severity.upper()} Event**",
                            "activityText": event_data.get("description", "")[:400],
                            "facts": [
                                {"name": "Capability", "value": event_data.get("claw", "—")},
                                {"name": "Risk Score", "value": str(event_data.get("risk_score", 0))},
                            ],
                        }],
                    }
                    resp = await client.post(webhook_url, json=payload, timeout=10.0)
                    if resp.status_code == 200:
                        sent += 1

            except Exception as exc:
                logger.error("Event alert routing error via %s: %s", ctype, exc)

    return sent
