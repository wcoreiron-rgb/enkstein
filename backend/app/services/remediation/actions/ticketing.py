"""
Ticketing and notification remediation actions.

Supported actions:
  create_jira_ticket        — Create a Jira issue
  create_pagerduty_incident — Trigger a PagerDuty incident
  send_slack_alert          — POST to a Slack webhook
  call_webhook              — Generic HTTP POST to any URL

Credentials dict expected keys (from secrets_manager):
  Jira:       {"jira_url": "https://xxx.atlassian.net", "jira_email": "...", "jira_api_token": "...", "jira_project_key": "SEC"}
  PagerDuty:  {"pd_api_token": "...", "pd_service_id": "..."}
  Slack:      {"slack_webhook_url": "https://hooks.slack.com/services/..."}
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from .base import ActionResult, simulated

logger = logging.getLogger(__name__)

SUPPORTED_ACTIONS = [
    "create_jira_ticket",
    "create_pagerduty_incident",
    "send_slack_alert",
    "call_webhook",
]


# ─── Jira ─────────────────────────────────────────────────────────────────────

def _has_jira_creds(creds: dict) -> bool:
    return bool(creds.get("jira_url") and creds.get("jira_email") and creds.get("jira_api_token"))


async def _create_jira_ticket(params: dict, creds: dict, context: dict) -> ActionResult:
    base        = creds["jira_url"].rstrip("/")
    project_key = params.get("project_key") or creds.get("jira_project_key", "SEC")
    summary     = _fmt(params.get("summary", "Security Finding Requires Action"), context)
    description = _fmt(
        params.get("description", "An automated remediation action was triggered by Enkstein."),
        context,
    )
    priority    = params.get("priority", "High")

    payload = {
        "fields": {
            "project":     {"key": project_key},
            "summary":     summary,
            "description": {
                "type":    "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": description}]}
                ],
            },
            "issuetype": {"name": "Bug"},
            "priority":  {"name": priority},
        }
    }

    auth    = (creds["jira_email"], creds["jira_api_token"])
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{base}/rest/api/3/issue",
            json=payload,
            auth=auth,
            headers=headers,
        )
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}

    if resp.status_code in (200, 201):
        issue_key = body.get("key", "?")
        return ActionResult(
            success=True,
            message=f"Jira ticket {issue_key} created in project {project_key}",
            rollback_data={"issue_key": issue_key, "jira_url": base, "provider": "jira"},
            output={"issue_key": issue_key, "issue_url": f"{base}/browse/{issue_key}"},
        )
    return ActionResult(
        success=False,
        message=f"Jira ticket creation failed (HTTP {resp.status_code})",
        error=str(body)[:500],
    )


# ─── PagerDuty ────────────────────────────────────────────────────────────────

def _has_pd_creds(creds: dict) -> bool:
    return bool(creds.get("pd_api_token") and creds.get("pd_service_id"))


async def _create_pd_incident(params: dict, creds: dict, context: dict) -> ActionResult:
    title       = _fmt(params.get("title", "Security Incident — Enkstein Alert"), context)
    urgency     = params.get("urgency", "high")
    service_id  = creds.get("pd_service_id", "")
    body_detail = _fmt(
        params.get("body", "Enkstein detected a critical security event that requires immediate attention."),
        context,
    )

    payload = {
        "incident": {
            "type":    "incident",
            "title":   title,
            "urgency": urgency,
            "service": {"id": service_id, "type": "service_reference"},
            "body":    {"type": "incident_body", "details": body_detail},
        }
    }
    headers = {
        "Authorization":  f"Token token={creds['pd_api_token']}",
        "Content-Type":   "application/json",
        "Accept":         "application/vnd.pagerduty+json;version=2",
        "From":           params.get("from_email", "redacted_user"),
    }

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post("https://api.pagerduty.com/incidents", json=payload, headers=headers)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}

    if resp.status_code in (200, 201):
        incident_id  = body.get("incident", {}).get("id", "?")
        incident_num = body.get("incident", {}).get("incident_number", "?")
        return ActionResult(
            success=True,
            message=f"PagerDuty incident #{incident_num} created",
            rollback_data={"incident_id": incident_id, "provider": "pagerduty"},
            output={"incident_id": incident_id, "incident_number": incident_num},
        )
    return ActionResult(
        success=False,
        message=f"PagerDuty incident creation failed (HTTP {resp.status_code})",
        error=str(body)[:500],
    )


# ─── Slack ────────────────────────────────────────────────────────────────────

def _has_slack_creds(creds: dict) -> bool:
    return bool(creds.get("slack_webhook_url"))


async def _send_slack(params: dict, creds: dict, context: dict) -> ActionResult:
    webhook_url = creds["slack_webhook_url"]
    text        = _fmt(params.get("text", "Security alert from Enkstein"), context)
    blocks = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": text},
        }
    ]
    if context.get("finding_title"):
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Finding: *{context['finding_title']}*"}],
        })

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(webhook_url, json={"text": text, "blocks": blocks})

    if resp.status_code == 200 and resp.text == "ok":
        return ActionResult(
            success=True,
            message="Slack alert sent",
            rollback_data={"provider": "slack"},
            output={"sent": True, "text": text[:200]},
        )
    return ActionResult(
        success=False,
        message=f"Slack webhook failed (HTTP {resp.status_code}): {resp.text[:200]}",
        error=resp.text[:500],
    )


# ─── Generic webhook ──────────────────────────────────────────────────────────

async def _call_webhook(params: dict, context: dict) -> ActionResult:
    url     = params.get("url", "")
    method  = params.get("method", "POST").upper()
    headers = params.get("headers", {})
    payload = params.get("payload", {})
    # Template the payload values
    payload_str = str(payload)
    for k, v in context.items():
        payload_str = payload_str.replace(f"{{{k}}}", str(v))

    if not url:
        return ActionResult(success=False, message="call_webhook requires params.url", error="Missing url")

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.request(method, url, headers=headers, json=payload)

    if resp.status_code < 400:
        return ActionResult(
            success=True,
            message=f"Webhook {method} {url} returned {resp.status_code}",
            rollback_data={"url": url, "provider": "webhook"},
            output={"status_code": resp.status_code},
        )
    return ActionResult(
        success=False,
        message=f"Webhook call failed (HTTP {resp.status_code})",
        error=resp.text[:500],
    )


# ─── Shared helpers ───────────────────────────────────────────────────────────

def _fmt(template: str, ctx: dict) -> str:
    """Simple template substitution: {finding.title} → ctx["finding_title"]."""
    result = template
    for k, v in ctx.items():
        result = result.replace(f"{{{k}}}", str(v))
    # Also support "finding.title" style keys
    for k, v in ctx.items():
        result = result.replace(f"{{finding.{k}}}", str(v))
    return result


# ─── Dispatcher ───────────────────────────────────────────────────────────────

async def execute(
    action_type: str,
    target_id: str,
    params: dict,
    credentials: dict,
) -> ActionResult:
    """Execute a ticketing/notification action."""
    creds   = credentials or {}
    context = params.get("_context", {})

    if action_type == "create_jira_ticket":
        if _has_jira_creds(creds):
            return await _create_jira_ticket(params, creds, context)
        return simulated(action_type, target_id)

    if action_type == "create_pagerduty_incident":
        if _has_pd_creds(creds):
            return await _create_pd_incident(params, creds, context)
        return simulated(action_type, target_id)

    if action_type == "send_slack_alert":
        if _has_slack_creds(creds):
            return await _send_slack(params, creds, context)
        return simulated(action_type, target_id)

    if action_type == "call_webhook":
        url = params.get("url", "")
        if url:
            return await _call_webhook(params, context)
        return simulated(action_type, target_id)

    return ActionResult(success=False, message=f"Unknown ticketing action: {action_type}", error="unsupported_action")


async def rollback(
    action_type: str,
    target_id: str,
    rollback_data: dict,
    credentials: dict,
) -> ActionResult:
    """Ticketing actions are typically not reversible via API."""
    if action_type == "create_jira_ticket":
        issue_key = rollback_data.get("issue_key", "")
        if issue_key:
            return ActionResult(
                success=True,
                message=f"Jira rollback note: manually close ticket {issue_key} to reverse",
                output={"issue_key": issue_key, "manual_action_required": True},
            )
    return ActionResult(
        success=True,
        message=f"Notification action '{action_type}' does not require rollback",
        output={"note": "Notifications are not reversible"},
    )
