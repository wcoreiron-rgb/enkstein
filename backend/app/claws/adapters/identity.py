"""
Identity, privileged access, and SaaS posture adapters.

These providers mostly answer "who can do what, and is that still justified".
Several expose aggregate posture rather than per-row findings, so they use the
``summarize`` hook: one meaningful finding such as "14 privileged accounts
without MFA" is more actionable than 14 near-identical rows.
"""
from __future__ import annotations

from typing import Any, Optional

from app.claws.rest_adapter import AdapterSpec, Endpoint, as_mapping, normalize_severity


def _count(payload: Any, key: Optional[str] = None) -> int:
    if key and isinstance(payload, dict):
        payload = payload.get(key)
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        return len(payload.get("value") or payload.get("data") or [])
    return 0


# ── Ping Identity ─────────────────────────────────────────────────────────────

def _summarize_ping(payload: Any, _creds: dict) -> list[dict]:
    embedded = as_mapping(payload).get("_embedded") or {}
    users = embedded.get("users") or []
    disabled_mfa = [u for u in users if not u.get("mfaEnabled", True)]
    if not disabled_mfa:
        return []
    return [{
        "title": f"Ping Identity: {len(disabled_mfa)} users without MFA enabled",
        "description": (
            f"{len(disabled_mfa)} Ping Identity users can authenticate without a "
            "second factor, leaving password compromise as a single point of failure."
        ),
        "category": "authentication",
        "severity": "high" if len(disabled_mfa) > 5 else "medium",
        "resource_id": "ping-users-no-mfa",
        "resource_type": "user_group",
        "external_id": f"PING-MFA-MISSING-{len(disabled_mfa)}",
        "remediation": "Require MFA for all Ping Identity users through an authentication policy.",
        "remediation_effort": "quick_win",
    }]


PING = AdapterSpec(
    provider="ping_identity",
    connector_type="ping_identity",
    label="Ping Identity",
    claw="accessclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url="https://api.pingone.com",
    token_field="client_secret",
    required_fields=("env_id", "client_id", "client_secret"),
    endpoints=(
        Endpoint(path="/v1/environments/{env_id}/users", summarize=_summarize_ping),
    ),
)


# ── Auth0 ─────────────────────────────────────────────────────────────────────

def _summarize_auth0(payload: Any, _creds: dict) -> list[dict]:
    users = payload if isinstance(payload, list) else as_mapping(payload).get("users", [])
    blocked = [u for u in users if u.get("blocked")]
    unverified = [u for u in users if not u.get("email_verified", True)]
    findings = []
    if unverified:
        findings.append({
            "title": f"Auth0: {len(unverified)} accounts with unverified email",
            "description": (
                f"{len(unverified)} Auth0 accounts were created without verifying "
                "their email address, which weakens account-recovery assurance."
            ),
            "category": "identity_hygiene",
            "severity": "medium",
            "resource_id": "auth0-unverified-email",
            "resource_type": "user_group",
            "external_id": f"AUTH0-UNVERIFIED-{len(unverified)}",
            "remediation": "Require email verification before granting application access.",
        })
    if blocked:
        findings.append({
            "title": f"Auth0: {len(blocked)} blocked accounts still present",
            "description": (
                f"{len(blocked)} blocked Auth0 accounts remain in the tenant. Blocked "
                "accounts that are never removed accumulate as dormant identity risk."
            ),
            "category": "identity_hygiene",
            "severity": "low",
            "resource_id": "auth0-blocked-accounts",
            "resource_type": "user_group",
            "external_id": f"AUTH0-BLOCKED-{len(blocked)}",
            "remediation": "Review and remove blocked accounts that are no longer needed.",
        })
    return findings


AUTH0 = AdapterSpec(
    provider="auth0",
    connector_type="auth0",
    label="Auth0",
    claw="accessclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url_field="domain",
    token_field="client_secret",
    required_fields=("domain", "client_id", "client_secret"),
    endpoints=(
        Endpoint(path="/api/v2/users", params={"per_page": 100}, summarize=_summarize_auth0),
    ),
)


# ── CyberArk ──────────────────────────────────────────────────────────────────

def _parse_cyberark(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("name") or row.get("userName")
    if not name:
        return None
    # An account whose secret has never rotated is the classic PAM failure.
    stale = not row.get("secretManagement", {}).get("lastModifiedTime")
    return {
        "title": f"CyberArk: privileged account '{name}' has no recorded rotation",
        "description": (
            "This privileged account has no secret-rotation timestamp, so its "
            "credential age cannot be demonstrated to an auditor."
        ),
        "category": "privileged_access",
        "severity": "high" if stale else "low",
        "resource_id": str(row.get("id") or name)[:120],
        "resource_type": "privileged_account",
        "resource_name": name,
        "external_id": f"CYBERARK-{row.get('id')}"[:120],
        "remediation": "Enrol the account in automatic credential rotation.",
    } if stale else None


CYBERARK = AdapterSpec(
    provider="cyberark",
    connector_type="cyberark",
    label="CyberArk",
    claw="accessclaw",
    auth="header",
    auth_name="Authorization",
    base_url_field="base_url",
    token_field="password",
    required_fields=("base_url", "username", "password"),
    endpoints=(
        Endpoint(path="/PasswordVault/api/Accounts", items_key="value", parse=_parse_cyberark, limit=50),
    ),
)


# ── HashiCorp Vault ───────────────────────────────────────────────────────────

def _summarize_vault(payload: Any, _creds: dict) -> list[dict]:
    data = as_mapping(as_mapping(payload).get("data"))
    # Vault's own seal/HA status is the highest-signal posture check.
    if data.get("sealed") or as_mapping(payload).get("sealed"):
        return [{
            "title": "HashiCorp Vault is sealed",
            "description": (
                "The Vault instance is sealed, so applications depending on it "
                "cannot retrieve secrets and may fall back to static credentials."
            ),
            "category": "secrets_management",
            "severity": "critical",
            "resource_id": "vault-sealed",
            "resource_type": "vault",
            "external_id": "VAULT-SEALED",
            "remediation": "Unseal Vault and investigate why it sealed.",
        }]
    return []


VAULT = AdapterSpec(
    provider="hashicorp_vault",
    connector_type="hashicorp_vault",
    label="HashiCorp Vault",
    claw="accessclaw",
    auth="header",
    auth_name="X-Vault-Token",
    base_url_field="vault_url",
    token_field="token",
    required_fields=("vault_url", "token"),
    endpoints=(
        Endpoint(path="/v1/sys/seal-status", summarize=_summarize_vault),
    ),
)


# ── Duo ───────────────────────────────────────────────────────────────────────

def _summarize_duo(payload: Any, _creds: dict) -> list[dict]:
    users = as_mapping(payload).get("response") or []
    if not isinstance(users, list):
        return []
    no_phone = [u for u in users if not u.get("phones") and not u.get("tokens")]
    if not no_phone:
        return []
    return [{
        "title": f"Duo: {len(no_phone)} users with no enrolled authentication device",
        "description": (
            f"{len(no_phone)} Duo users have neither a phone nor a hardware token "
            "enrolled, so MFA cannot actually be enforced for them."
        ),
        "category": "authentication",
        "severity": "high",
        "resource_id": "duo-users-unenrolled",
        "resource_type": "user_group",
        "external_id": f"DUO-UNENROLLED-{len(no_phone)}",
        "remediation": "Require device enrolment before granting access.",
        "remediation_effort": "quick_win",
    }]


DUO = AdapterSpec(
    provider="duo",
    connector_type="duo",
    label="Duo Security",
    claw="accessclaw",
    auth="header",
    auth_name="Authorization",
    auth_prefix="Basic",
    base_url_field="api_host",
    token_field="secret_key",
    required_fields=("api_host", "integration_key", "secret_key"),
    endpoints=(
        Endpoint(path="/admin/v1/users", summarize=_summarize_duo),
    ),
)


# ── Slack ─────────────────────────────────────────────────────────────────────

def _summarize_slack(payload: Any, _creds: dict) -> list[dict]:
    members = as_mapping(payload).get("members") or []
    if not isinstance(members, list):
        return []
    guests = [m for m in members if m.get("is_restricted") or m.get("is_ultra_restricted")]
    admins = [m for m in members if m.get("is_admin") or m.get("is_owner")]
    findings = []
    if len(admins) > 5:
        findings.append({
            "title": f"Slack: {len(admins)} workspace admins",
            "description": (
                f"{len(admins)} accounts hold Slack admin or owner rights. A broad "
                "admin population increases the blast radius of a single compromise."
            ),
            "category": "saas_posture",
            "severity": "medium",
            "resource_id": "slack-admin-sprawl",
            "resource_type": "workspace",
            "external_id": f"SLACK-ADMINS-{len(admins)}",
            "remediation": "Review admin membership and remove standing rights that are not required.",
        })
    if guests:
        findings.append({
            "title": f"Slack: {len(guests)} guest accounts with channel access",
            "description": (
                f"{len(guests)} restricted or single-channel guests are active in the "
                "workspace and should be reviewed against current engagements."
            ),
            "category": "saas_posture",
            "severity": "low",
            "resource_id": "slack-guest-accounts",
            "resource_type": "workspace",
            "external_id": f"SLACK-GUESTS-{len(guests)}",
            "remediation": "Deactivate guest accounts whose engagement has ended.",
        })
    return findings


SLACK = AdapterSpec(
    provider="slack",
    connector_type="slack",
    label="Slack",
    claw="saasclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url="https://slack.com",
    token_field="bot_token",
    required_fields=("bot_token",),
    endpoints=(
        Endpoint(path="/api/users.list", params={"limit": 200}, summarize=_summarize_slack),
    ),
)


# ── Microsoft Teams (via Graph) ───────────────────────────────────────────────

def _summarize_teams(payload: Any, _creds: dict) -> list[dict]:
    teams = as_mapping(payload).get("value") or []
    public = [t for t in teams if t.get("visibility") == "Public"]
    if not public:
        return []
    return [{
        "title": f"Microsoft Teams: {len(public)} public teams",
        "description": (
            f"{len(public)} teams are set to public visibility, so any member of the "
            "organisation can join and read their content without an approval step."
        ),
        "category": "saas_posture",
        "severity": "medium",
        "resource_id": "teams-public-visibility",
        "resource_type": "team_collection",
        "external_id": f"TEAMS-PUBLIC-{len(public)}",
        "remediation": "Review public teams and switch those handling sensitive work to private.",
    }]


MS_TEAMS = AdapterSpec(
    provider="ms_teams",
    connector_type="ms_teams",
    label="Microsoft Teams",
    claw="saasclaw",
    auth="device",
    base_url="https://graph.microsoft.com",
    token_field="access_token",
    endpoints=(
        Endpoint(path="/v1.0/groups", items_key="value", params={"$top": 100}, summarize=_summarize_teams),
    ),
)


# ── Netskope ──────────────────────────────────────────────────────────────────

def _parse_netskope(row: dict, _creds: dict) -> Optional[dict]:
    app = row.get("app") or row.get("application")
    if not app:
        return None
    score = row.get("cci") or row.get("ccl_score")
    return {
        "title": f"Netskope: risky cloud app in use — {app}",
        "description": (
            f"Netskope observed usage of {app}, which carries a low cloud "
            "confidence rating and may not meet data-handling requirements."
        ),
        "category": "shadow_it",
        "severity": normalize_severity(row.get("ccl"), default="medium"),
        "resource_id": str(row.get("app_id") or app)[:120],
        "resource_type": "saas_application",
        "resource_name": app,
        "risk_score": float(100 - score) if isinstance(score, (int, float)) else None,
        "external_id": f"NETSKOPE-{app}"[:120],
        "remediation": "Review the application against policy and sanction or block it.",
    }


NETSKOPE = AdapterSpec(
    provider="netskope",
    connector_type="netskope",
    label="Netskope",
    claw="saasclaw",
    auth="query",
    auth_name="token",
    base_url_field="tenant",
    token_field="api_token",
    required_fields=("tenant", "api_token"),
    endpoints=(
        Endpoint(path="/api/v1/app/list", items_key="data", parse=_parse_netskope, limit=50),
    ),
)


SPECS = (PING, AUTH0, CYBERARK, VAULT, DUO, SLACK, MS_TEAMS, NETSKOPE)
