"""
Azure Provider Adapter
Connects to Microsoft Defender for Cloud (Azure Security Center) to pull assessments.
Real URL: GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2021-06-01
Falls back to simulated findings when no credentials configured.
"""
import logging
from datetime import datetime
from typing import Optional

import httpx

from app.claws import provenance
from app.services import device_code_auth

logger = logging.getLogger("cloudclaw.azure")

TIMEOUT = httpx.Timeout(30.0)
AZURE_MGMT_BASE = "https://management.azure.com"
AZURE_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
API_VERSION = "2021-06-01"


# ─── Simulated findings for demo ─────────────────────────────────────────────

SIMULATED_FINDINGS = [
    {
        "title": "Azure Storage Account Allows Public Blob Access",
        "description": (
            "Storage account 'stproddata01' has 'allowBlobPublicAccess' enabled. "
            "This allows any internet user to access blob containers configured as public."
        ),
        "category": "misconfiguration",
        "severity": "high",
        "resource_id": "/subscriptions/sub-001/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/stproddata01",
        "resource_type": "storage_account",
        "resource_name": "stproddata01",
        "region": "eastus",
        "account_id": "sub-00000000-0000-0000-0000-000000000001",
        "risk_score": 80.0,
        "remediation": (
            "Set 'allowBlobPublicAccess' to false at the storage account level. "
            "In Azure Portal: Storage Account > Configuration > Allow Blob public access > Disabled. "
            "Review all containers and remove public access policies."
        ),
        "remediation_effort": "quick_win",
        "external_id": "Azure-Defender-Storage.1",
        "reference_url": "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent",
    },
    {
        "title": "Azure SQL Server Firewall Allows All Azure Services",
        "description": (
            "SQL server 'sql-prod-eastus' has 'Allow Azure services and resources to access this server' enabled. "
            "This grants access to all Azure IP ranges, including other tenants."
        ),
        "category": "misconfiguration",
        "severity": "medium",
        "resource_id": "/subscriptions/sub-001/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/sql-prod-eastus",
        "resource_type": "sql_server",
        "resource_name": "sql-prod-eastus",
        "region": "eastus",
        "account_id": "sub-00000000-0000-0000-0000-000000000001",
        "risk_score": 62.0,
        "remediation": (
            "Disable 'Allow Azure services' and configure explicit IP firewall rules or "
            "use Private Endpoints for database connectivity. "
            "Consider Azure Virtual Network service endpoints."
        ),
        "remediation_effort": "medium_term",
        "external_id": "Azure-Defender-SQL.2",
        "reference_url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure",
    },
    {
        "title": "Azure VM Missing Endpoint Protection",
        "description": (
            "Virtual machine 'vm-prod-web-01' does not have Microsoft Defender for Endpoint "
            "or an approved antimalware solution installed and running."
        ),
        "category": "vulnerability",
        "severity": "high",
        "resource_id": "/subscriptions/sub-001/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-prod-web-01",
        "resource_type": "virtual_machine",
        "resource_name": "vm-prod-web-01",
        "region": "westeurope",
        "account_id": "sub-00000000-0000-0000-0000-000000000001",
        "risk_score": 75.0,
        "remediation": (
            "Deploy Microsoft Defender for Endpoint via Azure Security Center. "
            "Enable 'Endpoint protection' in the Defender for Cloud recommendations. "
            "Alternatively, deploy the Microsoft Antimalware extension via ARM template."
        ),
        "remediation_effort": "medium_term",
        "external_id": "Azure-Defender-VM.1",
        "reference_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/endpoint-protection-recommendations-technical",
    },
    {
        "title": "Azure Key Vault Soft Delete Not Enabled",
        "description": (
            "Key Vault 'kv-prod-secrets' does not have soft-delete enabled. "
            "Accidental or malicious deletion of secrets, keys, or certificates is permanent."
        ),
        "category": "misconfiguration",
        "severity": "medium",
        "resource_id": "/subscriptions/sub-001/resourceGroups/prod-rg/providers/Microsoft.KeyVault/vaults/kv-prod-secrets",
        "resource_type": "key_vault",
        "resource_name": "kv-prod-secrets",
        "region": "eastus",
        "account_id": "sub-00000000-0000-0000-0000-000000000001",
        "risk_score": 58.0,
        "remediation": (
            "Enable soft-delete and purge protection on the Key Vault. "
            "Note: once purge protection is enabled, it cannot be disabled. "
            "Set the retention period to at least 90 days."
        ),
        "remediation_effort": "quick_win",
        "external_id": "Azure-Defender-KeyVault.1",
        "reference_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview",
    },
    {
        "title": "Azure Active Directory MFA Not Enforced for Admins",
        "description": (
            "Conditional Access policies do not enforce MFA for users with "
            "Global Administrator, Privileged Role Administrator, or Security Administrator roles."
        ),
        "category": "misconfiguration",
        "severity": "critical",
        "resource_id": "/tenants/tenant-00000000/conditionalAccess/policies",
        "resource_type": "conditional_access_policy",
        "resource_name": "admin-mfa-policy",
        "region": "global",
        "account_id": "sub-00000000-0000-0000-0000-000000000001",
        "risk_score": 96.0,
        "remediation": (
            "Create a Conditional Access policy requiring MFA for all users with privileged roles. "
            "Scope: All privileged role members. Conditions: All cloud apps. Grant: Require MFA. "
            "Test in report-only mode before enforcing."
        ),
        "remediation_effort": "quick_win",
        "external_id": "Azure-Defender-AAD.1",
        "reference_url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa",
    },
]


# ─── Azure OAuth token acquisition ───────────────────────────────────────────

async def _get_azure_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Acquire an Azure AD access token using client credentials flow."""
    url = AZURE_TOKEN_URL.format(tenant_id=tenant_id)
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://management.azure.com/.default",
    }
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.post(url, data=data)
        resp.raise_for_status()
        return resp.json()["access_token"]


async def _fetch_real_findings(credentials: dict) -> list[dict]:
    """
    Call Azure Defender for Cloud assessments API.
    Expects credentials: {tenant_id, client_id, client_secret, subscription_id}.
    """
    tenant_id = credentials.get("tenant_id", "")
    client_id = credentials.get("client_id", "")
    client_secret = credentials.get("client_secret", "")
    subscription_id = credentials.get("subscription_id", "")

    # Interactive device sign-in supplies a delegated token directly, so the
    # client-secret fields are only required for the app-registration path.
    token = await device_code_auth.resolve_access_token(credentials)
    if not token:
        if not all([tenant_id, client_id, client_secret]):
            raise ValueError("Missing required Azure credentials fields")
        token = await _get_azure_token(tenant_id, client_id, client_secret)
    if not subscription_id:
        raise ValueError("Azure requires a subscription_id")

    url = (
        f"{AZURE_MGMT_BASE}/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Security/assessments"
        f"?api-version={API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}

    all_findings = []
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        while url:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            all_findings.extend(data.get("value", []))
            url = data.get("nextLink")  # pagination

    return all_findings


def _parse_azure_assessment(raw: dict, subscription_id: str) -> dict:
    """Parse a raw Azure Defender assessment into the universal Finding format."""
    props = raw.get("properties", {})
    status = props.get("status", {})
    metadata = props.get("metadata", {})

    severity_map = {
        "High": "high",
        "Medium": "medium",
        "Low": "low",
    }
    severity = severity_map.get(metadata.get("severity", "Medium"), "medium")

    resource_id = props.get("resourceDetails", {}).get("Id", raw.get("id", ""))
    resource_name = resource_id.split("/")[-1] if resource_id else "unknown"

    assessment_status = status.get("code", "Unhealthy")
    finding_status = "open" if assessment_status == "Unhealthy" else "resolved"

    return {
        "claw": "cloudclaw",
        "provider": "azure",
        "title": metadata.get("displayName", raw.get("name", "Unknown Azure Finding"))[:512],
        "description": (metadata.get("description") or "")[:2000],
        "category": "misconfiguration",
        "severity": severity,
        "resource_id": resource_id[:512],
        "resource_type": "azure_resource",
        "resource_name": resource_name[:255],
        "region": "azure",
        "account_id": subscription_id,
        "risk_score": {"High": 75.0, "Medium": 50.0, "Low": 25.0}.get(
            metadata.get("severity", "Medium"), 50.0
        ),
        "actively_exploited": False,
        "status": finding_status,
        "external_id": raw.get("name", "")[:256],
        "reference_url": metadata.get("remediationDescription", "")[:512],
        "raw_data": str(raw)[:5000],
    }


# ─── Public entry point ───────────────────────────────────────────────────────

async def fetch_findings(credentials: dict) -> list[dict]:
    """Authenticated fetch that propagates failure to the caller."""
    raw_findings = await _fetch_real_findings(credentials)
    subscription_id = credentials.get("subscription_id", "unknown")
    return provenance.live(
        [_parse_azure_assessment(f, subscription_id) for f in raw_findings],
        provider="azure",
        connector="azure_defender_for_cloud",
    )


async def get_findings(credentials: Optional[dict] = None) -> list[dict]:
    """
    Main entry point for the Azure adapter.
    Attempts a real Defender for Cloud call if credentials are provided.
    Falls back to simulated findings for demo/dev environments.
    """
    if credentials:
        try:
            return await fetch_findings(credentials)
        except Exception as exc:
            logger.warning("Azure Defender call failed: %s — falling back to simulated findings", exc)

    # Return simulated findings with required universal fields
    results = []
    for f in SIMULATED_FINDINGS:
        finding = {
            "claw": "cloudclaw",
            "provider": "azure",
            "actively_exploited": f.get("actively_exploited", False),
            "status": "open",
            **f,
        }
        results.append({**finding, "data_origin": provenance.SIMULATED})
    return results
