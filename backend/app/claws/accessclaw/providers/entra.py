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
from app.claws import provenance
from app.services import device_code_auth

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
    # Interactive device sign-in already yields a delegated token, so no client
    # secret is involved; fall through to client credentials when absent.
    device_token = await device_code_auth.resolve_access_token(credentials)
    if device_token:
        return device_token
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
        # Identity Protection needs an Entra ID P2 licence and an extra scope,
        # so a tenant without it returns 403. Reading only that endpoint meant a
        # correctly connected tenant produced nothing at all, which then read as
        # a credential failure. The checks below use directory reads that the
        # base sign-in scope covers, and each optional check degrades on its own.
        findings.extend(await _risky_users(client, headers))
        findings.extend(await _tenant_defaults(client, headers))
        findings.extend(await _privileged_roles(client, headers))
    return findings


async def _risky_users(client: httpx.AsyncClient, headers: dict) -> list[dict]:
    """Identity Protection risk, when the tenant is licensed for it."""
    resp = await client.get(
        f"{GRAPH_BASE}/identityProtection/riskyUsers",
        headers=headers,
        params={"$filter": "riskLevel eq 'high' or riskLevel eq 'medium'", "$top": 50},
    )
    if resp.status_code != 200:
        return []
    risky = resp.json().get("value", [])
    if not risky:
        return []
    return [{
        "title": f"Entra ID: {len(risky)} risky users detected",
        "description": f"Identity Protection flagged {len(risky)} users at medium or high risk.",
        "category": "identity_risk",
        "severity": "high" if any(u.get("riskLevel") == "high" for u in risky) else "medium",
        "resource_id": "entra-risky-users",
        "resource_type": "user_group",
        "risk_score": 85.0,
        "actively_exploited": True,
        "external_id": f"ENTRA-RISKY-USERS-{len(risky)}",
            "control_id": "ENTRA.IDP.RISKY-USERS",
            "control_source": "authored",
            "zt_pillar": "identity",
            "frameworks": {"nist_800_53": ["AC-2(12)"]},
            "zt_tenets": ["T5","T7"],
        "remediation": "Force password change and MFA re-registration for flagged users.",
        "remediation_effort": "quick_win",
    }]


async def _tenant_defaults(client: httpx.AsyncClient, headers: dict) -> list[dict]:
    """Directory defaults that widen the blast radius of any single account."""
    resp = await client.get(f"{GRAPH_BASE}/policies/authorizationPolicy", headers=headers)
    if resp.status_code != 200:
        return []
    policy = resp.json()
    permissions = policy.get("defaultUserRolePermissions") or {}
    findings: list[dict] = []

    if permissions.get("allowedToCreateTenants"):
        findings.append({
            "title": "Entra ID: any user can create new tenants",
            "description": (
                "Every member of the directory may create additional Entra tenants. "
                "Tenants created this way fall outside the governance, logging and "
                "conditional access applied to this one."
            ),
            "category": "identity_governance",
            "severity": "medium",
            "resource_id": "entra-default-user-role",
            "resource_type": "directory_policy",
            "risk_score": 55.0,
            "external_id": "ENTRA-DEFAULT-USERS-CREATE-TENANTS",
            "control_id": "ENTRA.DIR.CREATE-TENANTS",
            "control_source": "authored",
            "zt_pillar": "identity",
            "frameworks": {"nist_800_53": ["AC-6(1)"]},
            "zt_tenets": ["T4","T6"],
            "remediation": "Set 'Restrict non-admin users from creating tenants' to Yes in User settings.",
            "remediation_effort": "quick_win",
        })

    if permissions.get("allowedToCreateApps"):
        findings.append({
            "title": "Entra ID: any user can register applications",
            "description": (
                "Every member of the directory may register application objects, which "
                "is a common path to establishing persistent OAuth access."
            ),
            "category": "identity_governance",
            "severity": "medium",
            "resource_id": "entra-default-user-role",
            "resource_type": "directory_policy",
            "risk_score": 50.0,
            "external_id": "ENTRA-DEFAULT-USERS-CREATE-APPS",
            "control_id": "ENTRA.DIR.CREATE-APPS",
            "control_source": "authored",
            "zt_pillar": "identity",
            "frameworks": {"nist_800_53": ["AC-6(1)"]},
            "zt_tenets": ["T4","T6"],
            "remediation": "Set 'Users can register applications' to No and grant the Application Developer role where needed.",
            "remediation_effort": "quick_win",
        })

    if policy.get("allowUserConsentForRiskyApps"):
        findings.append({
            "title": "Entra ID: user consent permitted for risky applications",
            "description": (
                "Users may grant consent to applications Microsoft classifies as risky, "
                "which allows an illicit consent grant to succeed without admin review."
            ),
            "category": "identity_governance",
            "severity": "high",
            "resource_id": "entra-user-consent",
            "resource_type": "directory_policy",
            "risk_score": 72.0,
            "external_id": "ENTRA-RISKY-APP-CONSENT",
            "control_id": "ENTRA.DIR.RISKY-CONSENT",
            "control_source": "authored",
            "zt_pillar": "identity",
            "frameworks": {"nist_800_53": ["AC-6(2)"]},
            "zt_tenets": ["T4","T6"],
            "remediation": "Disable user consent for risky applications and require admin consent requests.",
            "remediation_effort": "quick_win",
        })

    return findings


# Roles whose standing membership should be kept minimal and just-in-time.
_HIGH_PRIVILEGE_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
}


async def _privileged_roles(client: httpx.AsyncClient, headers: dict) -> list[dict]:
    """Standing membership in roles that should be rare and time-bound."""
    resp = await client.get(f"{GRAPH_BASE}/directoryRoles", headers=headers)
    if resp.status_code != 200:
        return []

    findings: list[dict] = []
    for role in resp.json().get("value", []):
        name = role.get("displayName", "")
        if name not in _HIGH_PRIVILEGE_ROLES:
            continue
        members = await client.get(
            f"{GRAPH_BASE}/directoryRoles/{role.get('id')}/members?$select=id&$top=100",
            headers=headers,
        )
        if members.status_code != 200:
            continue
        count = len(members.json().get("value", []))
        if count <= 2:
            continue
        findings.append({
            "title": f"Entra ID: {count} standing members in {name}",
            "description": (
                f"{count} principals hold the {name} role permanently. Standing "
                f"privilege of this kind is a durable target; Microsoft recommends "
                f"keeping it minimal and assigning it just-in-time."
            ),
            "category": "privileged_access",
            "severity": "high" if count > 4 else "medium",
            "resource_id": f"entra-role-{role.get('id')}",
            "resource_type": "directory_role",
            "resource_name": name,
            "risk_score": 78.0 if count > 4 else 60.0,
            "external_id": f"ENTRA-STANDING-ROLE-{role.get('id')}",
            "control_id": "ENTRA.PIM.STANDING-ROLE",
            "control_source": "authored",
            "zt_pillar": "identity",
            "frameworks": {"nist_800_53": ["AC-6(5)"]},
            "zt_tenets": ["T3","T6"],
            "remediation": "Move these assignments to eligible (just-in-time) via Privileged Identity Management.",
            "remediation_effort": "planned",
        })
    return findings


async def fetch_findings(credentials: dict) -> list[dict]:
    """Authenticated fetch that propagates failure to the caller."""
    return provenance.live(
        await _fetch_real_findings(credentials), provider="entra", connector="entra_id"
    )


async def get_findings(credentials: Optional[dict] = None) -> list[dict]:
    if credentials:
        try:
            return await fetch_findings(credentials)
        except Exception as exc:
            logger.warning("Entra ID API failed: %s — using simulated data", exc)
    return provenance.simulated(SIMULATED_FINDINGS, provider="entra")
