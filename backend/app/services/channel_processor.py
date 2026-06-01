"""
RegentClaw — Channel Gateway message processor
Ingests a message → identity check → policy eval → intent parse → dispatch → respond.

Outbound alert delivery is handled by the provider modules in
app.services.channels (slack_provider, email_provider, teams_provider).
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# ─── intent patterns (reuse NL workflow engine logic, lighter version) ───────

_INTENT_PATTERNS = [
    ("scan",             re.compile(r"\b(scan|check|audit|assess|inspect|review)\b", re.I)),
    ("block",            re.compile(r"\b(block|deny|restrict|quarantine|isolate)\b", re.I)),
    ("rotate",           re.compile(r"\b(rotate|reset|regenerate|refresh)\b.{0,20}(key|credential|password|secret|token)", re.I)),
    ("disable_account",  re.compile(r"\b(disable|suspend|lock|deactivate)\b.{0,20}\b(user|account|identity)\b", re.I)),
    ("remediate",        re.compile(r"\b(remediate|fix|patch|harden|mitigate)\b", re.I)),
    ("report",           re.compile(r"\b(report|status|summary|overview|health)\b", re.I)),
    ("investigate",      re.compile(r"\b(investigate|hunt|search|find|look for|detect)\b", re.I)),
    ("run_workflow",     re.compile(r"\b(run|trigger|execute|kick off|start)\b.{0,20}(workflow|playbook|automation)", re.I)),
    ("run_agent",        re.compile(r"\b(run|trigger|execute|start)\b.{0,20}(agent)", re.I)),
    ("approve",          re.compile(r"\b(approve|allow|authorize|permit)\b", re.I)),
    ("deny_action",      re.compile(r"\b(deny|reject|refuse)\b", re.I)),
]

_CLAW_PATTERNS = [
    ("ArcClaw",          re.compile(r"\b(ai|llm|model|prompt|chatbot|arcclaw)\b", re.I)),
    ("CloudClaw",        re.compile(r"\b(cloud|aws|azure|gcp|s3|bucket|cloudclaw)\b", re.I)),
    ("IdentityClaw",     re.compile(r"\b(identity|user|account|mfa|identityclaw)\b", re.I)),
    ("AccessClaw",       re.compile(r"\b(access|privilege|pam|credential|accessclaw)\b", re.I)),
    ("EndpointClaw",     re.compile(r"\b(endpoint|host|device|laptop|server|endpointclaw)\b", re.I)),
    ("NetClaw",          re.compile(r"\b(network|traffic|firewall|ip|dns|netclaw)\b", re.I)),
    ("DataClaw",         re.compile(r"\b(data|pii|database|encrypt|dataclaw)\b", re.I)),
    ("ThreatClaw",       re.compile(r"\b(threat|ioc|malware|indicator|threatclaw)\b", re.I)),
    ("ExposureClaw",     re.compile(r"\b(vulnerability|vuln|cve|exposure|exposureclaw)\b", re.I)),
    ("LogClaw",          re.compile(r"\b(log|siem|splunk|sentinel|logclaw)\b", re.I)),
    ("ComplianceClaw",   re.compile(r"\b(compliance|soc2|hipaa|pci|gdpr|complianceclaw)\b", re.I)),
]

_HIGH_RISK_PATTERNS = re.compile(
    r"\b(delete|wipe|destroy|drop|nuke|all users|all devices|production|prod\b|reset all)\b", re.I
)


def _detect_intents(text: str) -> list[str]:
    return [name for name, pat in _INTENT_PATTERNS if pat.search(text)]


def _detect_claws(text: str) -> list[str]:
    return [name for name, pat in _CLAW_PATTERNS if pat.search(text)]


def _is_high_risk(text: str) -> bool:
    return bool(_HIGH_RISK_PATTERNS.search(text))


def _identity_check(sender_email: str, channel_identity: dict | None) -> dict:
    """
    Check sender identity against ChannelIdentity record.
    Returns: { verified, risk, role, allowed, reason }
    """
    if not channel_identity:
        return {
            "verified": False,
            "risk":     "high",
            "role":     "unknown",
            "allowed":  False,
            "reason":   "Sender not registered in Channel Identity registry",
        }
    ci = channel_identity
    if not ci.get("is_trusted"):
        return {
            "verified": True,
            "risk":     "high",
            "role":     ci.get("regentclaw_role", "readonly"),
            "allowed":  False,
            "reason":   "Sender identity is not trusted",
        }
    return {
        "verified": True,
        "risk":     "low" if ci.get("trust_score", 0) >= 70 else "medium",
        "role":     ci.get("regentclaw_role", "analyst"),
        "allowed":  True,
        "reason":   "Identity verified",
    }


def _policy_check(intents: list[str], claws: list[str], identity: dict, high_risk: bool) -> dict:
    """
    Run policy gate. Returns { decision, flags, requires_approval }.
    """
    flags   = []
    blocked = False

    if not identity.get("allowed"):
        return {
            "decision": "blocked",
            "flags":    ["identity_not_verified"],
            "requires_approval": False,
        }

    role = identity.get("role", "readonly")
    if role == "readonly":
        blocked = True
        flags.append("readonly_role_cannot_execute")

    if high_risk:
        flags.append("high_risk_operation")

    destructive = {"block", "disable_account", "rotate"}
    if destructive & set(intents):
        if role not in ("admin", "engineer"):
            blocked = True
            flags.append("insufficient_role_for_destructive_action")
        elif high_risk:
            flags.append("requires_approval_high_risk_destructive")

    requires_approval = (
        high_risk
        or "requires_approval_high_risk_destructive" in flags
        or role == "analyst" and destructive & set(intents)
    )

    return {
        "decision":           "blocked" if blocked else ("requires_approval" if requires_approval else "allowed"),
        "flags":              flags,
        "requires_approval":  requires_approval,
    }


def _build_response(
    text: str,
    identity: dict,
    policy: dict,
    intents: list[str],
    claws: list[str],
    execution: dict | None,
) -> str:
    """Build the text response to send back to the channel."""
    lines = []

    if policy["decision"] == "blocked":
        lines.append("🚫 **Request blocked by RegentClaw**")
        for flag in policy.get("flags", []):
            lines.append(f"  • {flag.replace('_', ' ').title()}")
        return "\n".join(lines)

    if policy["decision"] == "requires_approval":
        lines.append("⏳ **Request queued for approval**")
        lines.append(f"Intent: `{', '.join(intents) or 'general'}`")
        lines.append(f"Claws: `{', '.join(claws) or 'none detected'}`")
        lines.append("An admin will review and approve this action.")
        return "\n".join(lines)

    # Allowed
    lines.append("✅ **RegentClaw executing**")
    lines.append(f"Intent: `{', '.join(intents) or 'general'}`")
    lines.append(f"Claws: `{', '.join(claws) or 'auto-detected'}`")
    if execution:
        run_id = execution.get("run_id", execution.get("id", ""))
        if run_id:
            lines.append(f"Run ID: `{run_id}`")
        lines.append(f"Status: `{execution.get('status', 'dispatched')}`")
    return "\n".join(lines)


def process_message(
    message_id:   str,
    message_text: str,
    sender_id:    str,
    sender_email: str,
    sender_name:  str,
    channel_type: str,
    channel_id:   str,
    channel_identity: dict | None,
) -> dict[str, Any]:
    """
    Full processing pipeline for one inbound channel message.
    Returns: processed message dict (does NOT write to DB — caller handles persistence).
    """
    intents   = _detect_intents(message_text)
    claws     = _detect_claws(message_text)
    high_risk = _is_high_risk(message_text)
    identity  = _identity_check(sender_email, channel_identity)
    policy    = _policy_check(intents, claws, identity, high_risk)

    # Determine execution action
    execution: dict | None = None
    exec_status = "blocked"
    workflow_run_id = ""
    agent_run_id    = ""

    if policy["decision"] == "allowed":
        exec_status = "dispatched"
        # In production this would call agent_runner / workflow engine
        # Here we return enough metadata for the caller to dispatch
        execution = {
            "run_id":   str(uuid.uuid4()),
            "status":   "dispatched",
            "intents":  intents,
            "claws":    claws,
        }
        workflow_run_id = execution["run_id"]
    elif policy["decision"] == "requires_approval":
        exec_status = "pending_approval"

    response_text = _build_response(message_text, identity, policy, intents, claws, execution)

    return {
        "id":               message_id,
        "channel_type":     channel_type,
        "channel_id":       channel_id,
        "sender_id":        sender_id,
        "sender_email":     sender_email,
        "sender_name":      sender_name,
        "message_text":     message_text,

        "identity_verified": identity["verified"],
        "identity_risk":     identity["risk"],
        "policy_decision":   policy["decision"],
        "policy_flags":      policy["flags"],
        "detected_intent":   ", ".join(intents),
        "detected_claws":    claws,

        "execution_status": exec_status,
        "workflow_run_id":  workflow_run_id,
        "agent_run_id":     agent_run_id,
        "response_text":    response_text,
        "execution":        execution,

        "processed_at": datetime.utcnow().isoformat(),
    }


# ── Outbound alert routing ────────────────────────────────────────────────────

async def dispatch_alert(
    channel_type: str,
    title:        str,
    text:         str,
    config:       dict,
) -> bool:
    """
    Route an outbound security alert to the correct channel provider.

    Args:
        channel_type: "slack" | "teams" | "email"
        title:        Alert title / subject.
        text:         Alert body text.
        config:       Channel-specific configuration dict.
                      Slack  → {"webhook_url": str}
                      Teams  → {"webhook_url": str, "color": str (optional)}
                      Email  → {"smtp_host", "smtp_port", "username", "password",
                                "from_addr", "to_addrs": list[str]}

    Returns:
        True if the provider accepted the message, False otherwise.
    """
    ct = channel_type.lower()

    if ct == "slack":
        from app.services.channels.slack_provider import send_message as _slack
        webhook = config.get("webhook_url", "")
        if not webhook:
            logger.error("dispatch_alert: Slack config missing webhook_url")
            return False
        return await _slack(
            webhook_url=webhook,
            text=f"*{title}*\n{text}",
            blocks=config.get("blocks"),
            thread_ts=config.get("thread_ts"),
        )

    if ct == "teams":
        from app.services.channels.teams_provider import send_message as _teams
        webhook = config.get("webhook_url", "")
        if not webhook:
            logger.error("dispatch_alert: Teams config missing webhook_url")
            return False
        return await _teams(
            webhook_url=webhook,
            title=title,
            text=text,
            color=config.get("color", "#D13438"),  # default to red for alerts
            actions=config.get("actions"),
            facts=config.get("facts"),
        )

    if ct == "email":
        from app.services.channels.email_provider import send_email as _email
        required = ("smtp_host", "smtp_port", "from_addr", "to_addrs")
        missing  = [k for k in required if not config.get(k)]
        if missing:
            logger.error("dispatch_alert: Email config missing keys: %s", missing)
            return False
        return await _email(
            smtp_host=config["smtp_host"],
            smtp_port=int(config["smtp_port"]),
            username=config.get("username", ""),
            password=config.get("password", ""),
            from_addr=config["from_addr"],
            to_addrs=config["to_addrs"],
            subject=f"[RegentClaw Alert] {title}",
            body=text,
            html_body=config.get("html_body"),
        )

    logger.warning("dispatch_alert: unknown channel_type %r — message dropped", channel_type)
    return False
