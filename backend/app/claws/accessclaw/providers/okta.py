"""
Okta Adapter
Pulls identity/access findings from Okta using the Okta API.

Auth: API Token (SSWS token)
Credentials expected:
  {
    "api_token": "...",
    "org_url": "https://yourorg.okta.com"
  }
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from app.claws import provenance
from app.claws import credential_aliases

logger = logging.getLogger("accessclaw.okta")
TIMEOUT = httpx.Timeout(30.0)

SIMULATED_FINDINGS = [
    {
        "title": "Okta: 12 Users with MFA Not Configured",
        "description": (
            "12 active Okta user accounts have never configured MFA. "
            "These accounts rely solely on password authentication, making them highly susceptible to credential stuffing."
        ),
        "category": "authentication",
        "severity": "high",
        "resource_id": "okta-group-no-mfa",
        "resource_type": "user_group",
        "risk_score": 82.0,
        "remediation": "Enforce MFA enrollment via Okta policy for all users within 7 days. Enable Okta FastPass or FIDO2 as preferred methods.",
        "remediation_effort": "quick_win",
        "external_id": "OKTA-MFA-NOT-ENROLLED-12",
    },
    {
        "title": "Okta: Admin Account Without MFA — 3 Privileged Users",
        "description": (
            "3 Okta Super Administrator or Application Administrator accounts do not have MFA enabled. "
            "Admin compromise without MFA gives an attacker full control of the Okta tenant."
        ),
        "category": "authentication",
        "severity": "critical",
        "resource_id": "okta-admins-no-mfa",
        "resource_type": "privileged_user_group",
        "risk_score": 97.0,
        "actively_exploited": False,
        "remediation": "Immediately enforce MFA on all admin accounts. Consider phishing-resistant MFA (FIDO2) for Super Admins.",
        "remediation_effort": "quick_win",
        "external_id": "OKTA-ADMIN-NO-MFA-3",
    },
    {
        "title": "Okta: Suspicious Login — Multiple Countries in 24h",
        "description": (
            "User redacted_user authenticated from US (9:02 AM) and Russia (9:47 AM) within 45 minutes — "
            "physically impossible travel. Potential account takeover or credential sharing."
        ),
        "category": "suspicious_login",
        "severity": "critical",
        "resource_id": "okta-user-jdoe",
        "resource_type": "user_account",
        "risk_score": 95.0,
        "actively_exploited": True,
        "remediation": "Force password reset and MFA re-enrollment. Review all sessions and apps accessed in the last 24h. Consider suspending account pending investigation.",
        "remediation_effort": "quick_win",
        "external_id": "OKTA-IMPOSSIBLE-TRAVEL-JDOE",
    },
    {
        "title": "Okta: 34 Inactive Users Still Active (>90 Days No Login)",
        "description": (
            "34 Okta user accounts have not logged in for more than 90 days but remain active "
            "with full application access. Stale accounts are a common initial access vector."
        ),
        "category": "identity_hygiene",
        "severity": "medium",
        "resource_id": "okta-group-stale-users-90d",
        "resource_type": "user_group",
        "risk_score": 58.0,
        "remediation": "Deprovision or suspend accounts inactive for >90 days. Implement Okta Lifecycle Management automation for joiner/mover/leaver processes.",
        "remediation_effort": "medium_term",
        "external_id": "OKTA-STALE-USERS-90D-34",
    },
]


async def _fetch_real_findings(credentials: dict) -> list[dict]:
    credentials = credential_aliases.resolve("okta", credentials)
    org_url = credentials.get("org_url", "").rstrip("/")
    api_token = credentials.get("api_token", "")
    if not org_url or not api_token:
        raise ValueError(
            "Okta requires an org URL (Okta Domain) and an API token"
        )

    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}
    findings = []

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        # Fetch users without MFA
        resp = await client.get(
            f"{org_url}/api/v1/users",
            headers=headers,
            params={"filter": 'status eq "ACTIVE"', "limit": 200},
        )
        resp.raise_for_status()
        users = resp.json()

        no_mfa = []
        for user in users[:50]:  # Cap for now
            uid = user.get("id", "")
            mfa_resp = await client.get(f"{org_url}/api/v1/users/{uid}/factors", headers=headers)
            if mfa_resp.status_code == 200 and not mfa_resp.json():
                no_mfa.append(user)

        if no_mfa:
            findings.append({
                "title": f"Okta: {len(no_mfa)} Active Users Missing MFA",
                "description": f"{len(no_mfa)} active Okta users have no MFA factors enrolled.",
                "category": "authentication",
                "severity": "high",
                "resource_id": "okta-users-no-mfa",
                "resource_type": "user_group",
                "risk_score": 80.0,
                "external_id": f"OKTA-MFA-NOT-ENROLLED-{len(no_mfa)}",
                "remediation": "Enforce MFA enrollment via Okta policy within 7 days.",
                "remediation_effort": "quick_win",
            })

    return findings


async def fetch_findings(credentials: dict) -> list[dict]:
    """Authenticated fetch that propagates failure to the caller."""
    return provenance.live(
        await _fetch_real_findings(credentials), provider="okta", connector="okta"
    )


async def get_findings(credentials: Optional[dict] = None) -> list[dict]:
    if credentials:
        try:
            return await fetch_findings(credentials)
        except Exception as exc:
            logger.warning("Okta API failed: %s — using simulated data", exc)
    return provenance.simulated(SIMULATED_FINDINGS, provider="okta")
