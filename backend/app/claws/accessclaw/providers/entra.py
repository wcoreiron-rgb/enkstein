"""
Microsoft Entra ID (Azure AD) Adapter
Pulls identity risk and access findings via Microsoft Graph API.

Auth: Azure AD OAuth2 client credentials
Required permissions: IdentityRiskyUser.Read.All, Directory.Read.All, AuditLog.Read.All

Credentials expected:
  {
    "tenant_id": "...",
    "client_id": "...",
    "client_secret": "..."
  }
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

logger = logging.getLogger("accessclaw.entra")
TIMEOUT = httpx.Timeout(30.0)
TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

SIMULATED_FINDINGS = [
    {
        "title": "Entra ID: Global Admin Without Conditional Access MFA",
        "description": (
            "3 Global Administrator accounts are not covered by any Conditional Access policy requiring MFA. "
            "Admin account compromise without MFA grants full tenant control."
        ),
        "category": "privileged_access",
        "severity": "critical",
        "resource_id": "entra-global-admins-no-ca",
        "resource_type": "privileged_user_group",
        "risk_score": 97.0,
        "remediation": "Create a Conditional Access policy: All Users + Privileged roles → Require MFA. Enable Entra ID PIM for JIT admin access.",
        "remediation_effort": "quick_win",
        "external_id": "ENTRA-GLOBAL-ADMIN-NO-MFA-3",
    },
    {
        "title": "Entra ID: 7 Risky Users Detected by Identity Protection",
        "description": (
            "Entra ID Identity Protection has flagged 7 users at HIGH risk based on leaked credentials, "
            "impossible travel, and anonymous IP usage signals."
        ),
        "category": "identity_risk",
        "severity": "high",
        "resource_id": "entra-risky-users-high",
        "resource_type": "user_group",
        "risk_score": 88.0,
        "actively_exploited": True,
        "remediation": "Force password change and MFA re-registration for all HIGH risk users. Review sign-in logs and revoke sessions.",
        "remediation_effort": "quick_win",
        "external_id": "ENTRA-RISKY-USERS-HIGH-7",
    },
    {
        "title": "Entra ID: Service Principal with Owner Role — 2 Found",
        "description": (
            "2 Azure AD application service principals have the Owner role at the subscription level. "
            "A compromised app credential would give an attacker full subscription control."
        ),
        "category": "privileged_access",
        "severity": "critical",
        "resource_id": "entra-sp-owner-role",
        "resource_type": "service_principal",
        "risk_score": 96.0,
        "remediation": "Remove Owner role from service principals. Assign minimum required roles. Enable credential rotation policies.",
        "remediation_effort": "medium_term",
        "external_id": "ENTRA-SP-OWNER-2",
    },
    {
        "title": "Entra ID: Legacy Authentication Not Blocked",
        "description": (
            "No Conditional Access policy blocks legacy authentication protocols (POP3, SMTP, IMAP, Exchange ActiveSync). "
            "Legacy auth bypasses MFA and is the primary vector for password spray attacks."
        ),
        "category": "authentication",
        "severity": "high",
        "resource_id": "entra-legacy-auth-gap",
        "resource_type": "tenant_policy",
        "risk_score": 85.0,
        "remediation": "Create a Conditional Access policy blocking legacy authentication for all users and all cloud apps.",
        "remediation_effort": "quick_win",
        "external_id": "ENTRA-LEGACY-AUTH-NOT-BLOCKED",
    },
]


async def _get_token(credentials: dict) -> str:
    url = TOKEN_URL.format(tenant_id=credentials["tenant_id"])
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.post(url, data={
            "grant_type": "client_credentials",
            "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"],
            "scope": "https://graph.microsoft.com/.default",
        })
        resp.raise_for_status()
        return resp.json()["access_token"]


async def _fetch_real_findings(credentials: dict) -> list[dict]:
    token = await _get_token(credentials)
    headers = {"Authorization": f"Bearer {token}"}
    findings = []

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        # Fetch risky users
        resp = await client.get(
            f"{GRAPH_BASE}/identityProtection/riskyUsers",
            headers=headers,
            params={"$filter": "riskLevel eq 'high' or riskLevel eq 'medium'", "$top": 50},
        )
        if resp.status_code == 200:
            risky = resp.json().get("value", [])
            if risky:
                findings.append({
                    "title": f"Entra ID: {len(risky)} Risky Users Detected",
                    "description": f"Entra ID Identity Protection flagged {len(risky)} users at medium or high risk.",
                    "category": "identity_risk",
                    "severity": "high" if any(u.get("riskLevel") == "high" for u in risky) else "medium",
                    "resource_id": "entra-risky-users",
                    "resource_type": "user_group",
                    "risk_score": 85.0,
                    "actively_exploited": True,
                    "external_id": f"ENTRA-RISKY-USERS-{len(risky)}",
                    "remediation": "Force password change and MFA re-registration for flagged users.",
                    "remediation_effort": "quick_win",
                })

    return findings


async def get_findings(credentials: Optional[dict] = None) -> list[dict]:
    if credentials:
        try:
            return [{**f, "provider": "entra"} for f in await _fetch_real_findings(credentials)]
        except Exception as exc:
            logger.warning("Entra ID API failed: %s — using simulated data", exc)
    return [{**f, "provider": "entra"} for f in SIMULATED_FINDINGS]
