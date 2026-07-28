"""
Microsoft Defender for Endpoint Adapter
Pulls alerts and vulnerabilities from MDE via Microsoft Graph / Defender APIs.

Auth: Azure AD OAuth2 client credentials
Required permissions: Alert.Read.All, Machine.Read.All, Vulnerability.Read.All

Credentials expected:
  {
    "tenant_id": "...",
    "client_id": "...",
    "client_secret": "..."
  }
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from app.claws import provenance
from app.services import device_code_auth

logger = logging.getLogger("endpointclaw.defender")

TIMEOUT = httpx.Timeout(30.0)
TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
MDE_BASE = "https://api.securitycenter.microsoft.com/api"

SIMULATED_FINDINGS = [
    {
        "title": "Defender: 31 Laptops Missing BitLocker Encryption",
        "description": (
            "31 corporate laptops fail the Intune compliance policy 'BitLocker Required'. "
            "Full-disk encryption is not enabled. Data loss risk in case of device theft."
        ),
        "category": "unencrypted_disk",
        "severity": "high",
        "resource_id": "intune-group-unencrypted-laptops",
        "resource_type": "endpoint_group",
        "resource_name": "unencrypted-laptops",
        "risk_score": 76.0,
        "remediation": "Enable BitLocker via Intune device configuration profile. Escrow keys to Azure AD.",
        "remediation_effort": "medium_term",
        "external_id": "MDE-BITLOCKER-COMPLIANCE-FAIL-31",
    },
    {
        "title": "Defender: Windows 10 21H2 End-of-Life — 23 Endpoints",
        "description": (
            "23 endpoints running Windows 10 21H2 or earlier no longer receive security patches from Microsoft. "
            "Any newly discovered Windows vulnerability has no remediation path on these systems."
        ),
        "category": "outdated_os",
        "severity": "high",
        "resource_id": "fleet-group-win10-eol",
        "resource_type": "endpoint_group",
        "resource_name": "win10-eol-fleet",
        "risk_score": 80.0,
        "remediation": "Upgrade to Windows 11 24H2 or minimum Windows 10 22H2. Prioritize internet-facing and privileged hosts.",
        "remediation_effort": "strategic",
        "external_id": "MDE-EOL-WIN10-21H2",
    },
    {
        "title": "Defender: Stale AV Signatures on 19 Endpoints",
        "description": (
            "19 endpoints have Defender antivirus signature definitions older than 7 days. "
            "Stale signatures reduce detection effectiveness against recent malware variants."
        ),
        "category": "outdated_os",
        "severity": "medium",
        "resource_id": "intune-group-stale-av",
        "resource_type": "endpoint_group",
        "resource_name": "stale-av-signatures",
        "risk_score": 55.0,
        "remediation": "Force signature update via Intune remediation script. Investigate why automatic updates are failing.",
        "remediation_effort": "quick_win",
        "external_id": "MDE-STALE-SIGNATURES-19",
    },
    {
        "title": "Defender: Suspicious Script Execution Blocked on CORP-LAPTOP-0314",
        "description": (
            "Microsoft Defender for Endpoint blocked a suspicious WScript.exe invocation on CORP-LAPTOP-0314. "
            "The script attempted to reach out to a known phishing domain (update-cdn-static[.]com) "
            "and write a VBScript dropper to the Startup folder."
        ),
        "category": "threat",
        "severity": "high",
        "resource_id": "corp-laptop-0314-machine-id",
        "resource_type": "endpoint",
        "resource_name": "CORP-LAPTOP-0314",
        "risk_score": 82.0,
        "cvss_score": 8.0,
        "actively_exploited": True,
        "remediation": (
            "Isolate CORP-LAPTOP-0314 and review Defender timeline for full process chain. "
            "Block the phishing domain on the proxy layer. Audit email delivery that may have carried the payload."
        ),
        "remediation_effort": "quick_win",
        "external_id": "MDE-ALERT-WSCRIPT-DROPPER-0314",
        "reference_url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/",
    },
    {
        "title": "Defender: Tamper Protection Disabled on 8 Servers",
        "description": (
            "8 Windows Server hosts have Tamper Protection disabled in their MDE policy. "
            "Without tamper protection, malware can disable Defender real-time protection, "
            "cloud-delivered protection, and behavior monitoring via registry changes."
        ),
        "category": "misconfiguration",
        "severity": "high",
        "resource_id": "intune-group-tamper-disabled",
        "resource_type": "endpoint_group",
        "resource_name": "tamper-protection-disabled-servers",
        "risk_score": 79.0,
        "actively_exploited": False,
        "remediation": (
            "Enable Tamper Protection in the MDE security settings policy. "
            "Audit registry paths HKLM\\SOFTWARE\\Microsoft\\Windows Defender for unauthorized changes."
        ),
        "remediation_effort": "quick_win",
        "external_id": "MDE-TAMPER-PROTECTION-DISABLED-8",
    },
    {
        "title": "Defender: Vulnerable Driver (CVE-2021-21551) Detected on 5 Hosts",
        "description": (
            "Defender Vulnerability Management flagged a vulnerable Dell DBUtil driver (CVE-2021-21551) "
            "on 5 hosts. This driver can be exploited to escalate privileges to KERNEL level. "
            "CVSS score 8.8. Known exploit code is publicly available."
        ),
        "category": "vulnerability",
        "severity": "critical",
        "resource_id": "fleet-group-cve-2021-21551",
        "resource_type": "endpoint_group",
        "resource_name": "dell-dbutildrv-vulnerable",
        "risk_score": 91.0,
        "cvss_score": 8.8,
        "epss_score": 0.61,
        "actively_exploited": True,
        "remediation": (
            "Run the Dell security advisory remediation tool to remove the vulnerable driver. "
            "Verify removal with: sc query dbutildrv2. Reboot required after removal."
        ),
        "remediation_effort": "quick_win",
        "external_id": "MDE-CVE-2021-21551-DRIVER",
        "reference_url": "https://www.dell.com/support/kbdoc/en-us/000186019/dsa-2021-088",
    },
    {
        "title": "Defender: MDE Sensor Not Reporting — 11 Endpoints Offline > 7 Days",
        "description": (
            "11 endpoints have not sent telemetry to the MDE cloud service for more than 7 days. "
            "These machines have no threat visibility. They may be powered off, reimaged without re-enrollment, "
            "or have their MDE sense service stopped."
        ),
        "category": "missing_edr",
        "severity": "medium",
        "resource_id": "mde-group-offline-sensors",
        "resource_type": "endpoint_group",
        "resource_name": "mde-offline-sensor-fleet",
        "risk_score": 62.0,
        "actively_exploited": False,
        "remediation": (
            "Verify host health via Intune/SCCM. Re-enroll or reimage hosts that have been offline. "
            "Run the MDE client analyzer tool to diagnose sense service failures on reachable hosts."
        ),
        "remediation_effort": "medium_term",
        "external_id": "MDE-SENSOR-OFFLINE-11",
    },
]


async def _get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    url = TOKEN_URL.format(tenant_id=tenant_id)
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.post(url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://api.securitycenter.microsoft.com/.default",
        })
        resp.raise_for_status()
        return resp.json()["access_token"]


async def _fetch_real_findings(credentials: dict) -> list[dict]:
    """Fetch MDE alerts from the past 7 days with HIGH or CRITICAL severity."""
    tenant_id = credentials.get("tenant_id", "")
    client_id = credentials.get("client_id", "")
    client_secret = credentials.get("client_secret", "")

    # Interactive device sign-in supplies a delegated token directly.
    token = await device_code_auth.resolve_access_token(credentials)
    if not token:
        if not all([tenant_id, client_id, client_secret]):
            raise ValueError("MDE requires tenant_id, client_id, client_secret")
        token = await _get_token(tenant_id, client_id, client_secret)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    odata_filter = f"alertCreationTime ge {since} and severity in ('High', 'Critical')"

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{MDE_BASE}/alerts",
            headers=headers,
            params={"$filter": odata_filter, "$top": 100, "$orderby": "alertCreationTime desc"},
        )
        resp.raise_for_status()
        return resp.json().get("value", [])


def _parse_mde_alert(raw: dict) -> dict:
    sev_map = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
    severity = sev_map.get(raw.get("severity", "Medium"), "medium")
    machine = raw.get("computerDnsName", raw.get("machineId", "unknown"))

    return {
        "provider": "defender_endpoint",
        "title": f"Defender: {raw.get('title', 'Alert')} — {machine}",
        "description": raw.get("description", ""),
        "category": raw.get("category", "threat").lower(),
        "severity": severity,
        "resource_id": raw.get("machineId", ""),
        "resource_type": "endpoint",
        "resource_name": machine,
        "risk_score": {"Critical": 92.0, "High": 75.0, "Medium": 50.0, "Low": 25.0}.get(
            raw.get("severity", "Medium"), 50.0
        ),
        "actively_exploited": severity == "critical",
        "external_id": raw.get("id", ""),
        "reference_url": raw.get("alertCreationTime", ""),
        "remediation": raw.get("recommendedAction", "Investigate via Microsoft 365 Defender portal."),
        "remediation_effort": "quick_win",
    }


async def fetch_findings(credentials: dict) -> list[dict]:
    """Authenticated fetch that propagates failure to the caller."""
    raw = await _fetch_real_findings(credentials)
    return provenance.live(
        [_parse_mde_alert(a) for a in raw],
        provider="defender_endpoint",
        connector="defender_endpoint",
    )


async def get_findings(credentials: Optional[dict] = None) -> list[dict]:
    if credentials:
        try:
            return await fetch_findings(credentials)
        except Exception as exc:
            logger.warning("Defender for Endpoint API failed: %s — using simulated data", exc)
    return provenance.simulated(SIMULATED_FINDINGS, provider="defender_endpoint")
