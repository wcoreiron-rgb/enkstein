"""
CrowdStrike Falcon Adapter
Pulls endpoint detections and prevention alerts from CrowdStrike Falcon.

Auth: OAuth2 client credentials (client_id + client_secret)
API docs: https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis

Credentials expected:
  {
    "client_id": "...",
    "client_secret": "...",
    "base_url": "https://api.crowdstrike.com"   # or regional equivalent
  }
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from app.claws import credential_aliases, provenance

logger = logging.getLogger("endpointclaw.crowdstrike")

TIMEOUT = httpx.Timeout(30.0)
DEFAULT_BASE = "https://api.crowdstrike.com"

SIMULATED_FINDINGS = [
    {
        "title": "CrowdStrike: Emotet Trojan Detected and Quarantined",
        "description": (
            "CrowdStrike Falcon detected Emotet trojan activity on endpoint CORP-WIN-0142. "
            "Process injection into lsass.exe was prevented. C2 callback to 185.220.101.47:8080 blocked."
        ),
        "category": "malware",
        "severity": "critical",
        "resource_id": "CORP-WIN-0142",
        "resource_type": "endpoint",
        "resource_name": "CORP-WIN-0142",
        "risk_score": 98.0,
        "cvss_score": 9.8,
        "epss_score": 0.94,
        "actively_exploited": True,
        "remediation": (
            "Isolate CORP-WIN-0142 immediately. Run full forensic collection. "
            "Reset credentials used from this host. Scan adjacent hosts CORP-WIN-0140 to CORP-WIN-0145."
        ),
        "remediation_effort": "quick_win",
        "external_id": "CS-DETECT-EMOTET-WIN-0142",
        "reference_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-280a",
    },
    {
        "title": "CrowdStrike: 47 Endpoints Missing Falcon Sensor",
        "description": (
            "47 Windows endpoints in the PROD-WIN-* hostname range have no CrowdStrike Falcon sensor "
            "installed or are running sensor version below the minimum (6.30). These hosts have no EDR coverage."
        ),
        "category": "missing_edr",
        "severity": "critical",
        "resource_id": "fleet-group-prod-windows-unprotected",
        "resource_type": "endpoint_group",
        "resource_name": "prod-windows-unprotected",
        "risk_score": 93.0,
        "actively_exploited": False,
        "remediation": (
            "Deploy Falcon sensor via SCCM or Intune to all unprotected hosts. "
            "Set a compliance policy blocking domain join for hosts without valid sensor."
        ),
        "remediation_effort": "medium_term",
        "external_id": "CS-SENSOR-COVERAGE-GAP-PROD",
    },
    {
        "title": "CrowdStrike: PowerShell Encoded Command Execution Detected",
        "description": (
            "Falcon detected suspicious PowerShell activity on CORP-WIN-0089 — "
            "encoded command execution (powershell -EncodedCommand) with AMSI bypass attempts. "
            "Process was blocked but lateral movement scripts were found in %TEMP%."
        ),
        "category": "threat",
        "severity": "high",
        "resource_id": "CORP-WIN-0089",
        "resource_type": "endpoint",
        "resource_name": "CORP-WIN-0089",
        "risk_score": 85.0,
        "actively_exploited": True,
        "remediation": (
            "Isolate endpoint and collect forensic artifact. Enable AMSI enforcement. "
            "Set PowerShell Constrained Language Mode via AppLocker or WDAC."
        ),
        "remediation_effort": "quick_win",
        "external_id": "CS-DETECT-PS-ENCODED-WIN-0089",
    },
    {
        "title": "CrowdStrike: Sensor Policy — Prevention Mode Disabled on 12 Hosts",
        "description": (
            "12 endpoints in the CORP-LEGACY-* group are running Falcon sensor in 'Detection Only' mode "
            "instead of 'Prevention'. Malicious processes will be detected but not automatically blocked."
        ),
        "category": "misconfiguration",
        "severity": "high",
        "resource_id": "falcon-policy-group-legacy",
        "resource_type": "endpoint_group",
        "resource_name": "CORP-LEGACY-group",
        "risk_score": 78.0,
        "actively_exploited": False,
        "remediation": (
            "Upgrade the Falcon sensor policy to 'Prevention' mode for the CORP-LEGACY-* group. "
            "Test against a canary host first to rule out operational disruptions."
        ),
        "remediation_effort": "quick_win",
        "external_id": "CS-POLICY-DETECT-ONLY-LEGACY",
    },
    {
        "title": "CrowdStrike: DLL Side-Loading via Legitimate Signed Binary on CORP-WIN-0217",
        "description": (
            "Falcon detected DLL side-loading on CORP-WIN-0217 — a malicious 'version.dll' was placed "
            "in the directory of a legitimate signed application (OneDriveUpdater.exe). "
            "The technique abuses trusted process context to evade signature-based detection."
        ),
        "category": "threat",
        "severity": "high",
        "resource_id": "CORP-WIN-0217",
        "resource_type": "endpoint",
        "resource_name": "CORP-WIN-0217",
        "risk_score": 83.0,
        "cvss_score": 8.1,
        "actively_exploited": True,
        "remediation": (
            "Quarantine CORP-WIN-0217 and remove the malicious DLL. "
            "Audit writable directories alongside signed binaries. "
            "Enable Falcon's DLL protection policy."
        ),
        "remediation_effort": "quick_win",
        "external_id": "CS-DETECT-DLLSIDELOAD-WIN-0217",
        "reference_url": "https://attack.mitre.org/techniques/T1574/002/",
    },
    {
        "title": "CrowdStrike: Ransomware-Style File Encryption Pattern on FILE-SERVER-02",
        "description": (
            "Falcon Overwatch detected rapid file-rename activity matching ransomware staging patterns "
            "on FILE-SERVER-02. Over 4,000 files were touched in 90 seconds before the process was "
            "killed. No ransom note was dropped — encryption payload may have been stopped mid-execution."
        ),
        "category": "malware",
        "severity": "critical",
        "resource_id": "FILE-SERVER-02",
        "resource_type": "endpoint",
        "resource_name": "FILE-SERVER-02",
        "risk_score": 96.0,
        "cvss_score": 9.5,
        "actively_exploited": True,
        "remediation": (
            "Isolate FILE-SERVER-02 and take a snapshot before any recovery action. "
            "Restore affected file share from last-known-good backup. "
            "Audit all SMB sessions active at the time of the event."
        ),
        "remediation_effort": "quick_win",
        "external_id": "CS-OVERWATCH-RANSOMWARE-FILESERVER-02",
    },
    {
        "title": "CrowdStrike: Outdated Falcon Sensor — 64 Endpoints Below Minimum Version",
        "description": (
            "64 endpoints are running Falcon sensor versions below the required minimum (7.05). "
            "Older sensor versions do not support the latest behavioral detections and kernel protections. "
            "Hosts are grouped across CORP-WIN-*, CORP-MAC-*, and REMOTE-* naming ranges."
        ),
        "category": "missing_edr",
        "severity": "medium",
        "resource_id": "fleet-group-outdated-sensor",
        "resource_type": "endpoint_group",
        "resource_name": "outdated-sensor-fleet",
        "risk_score": 58.0,
        "actively_exploited": False,
        "remediation": (
            "Enable automatic sensor updates in the Falcon sensor update policy. "
            "Target the outdated-sensor-fleet group for immediate upgrade to sensor 7.10+."
        ),
        "remediation_effort": "medium_term",
        "external_id": "CS-SENSOR-VERSION-BELOW-MIN",
    },
]


async def _get_token(client: httpx.AsyncClient, base_url: str, client_id: str, client_secret: str) -> str:
    """Exchange CrowdStrike client credentials for an OAuth2 access token."""
    resp = await client.post(
        f"{base_url}/oauth2/token",
        data={"client_id": client_id, "client_secret": client_secret, "grant_type": "client_credentials"},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


async def _fetch_real_findings(credentials: dict) -> list[dict]:
    """
    Pull CrowdStrike detections from the Falcon Detections API.
    Fetches detections from the last 7 days with severity HIGH or CRITICAL.
    """
    credentials = credential_aliases.resolve("crowdstrike", credentials)
    base_url = credentials.get("base_url", DEFAULT_BASE).rstrip("/")
    client_id = credentials.get("client_id", "")
    client_secret = credentials.get("client_secret", "")

    if not client_id or not client_secret:
        raise ValueError("CrowdStrike credentials require client_id and client_secret")

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        token = await _get_token(client, base_url, client_id, client_secret)
        headers = {"Authorization": f"Bearer {token}"}

        # Query for recent detections (FQL filter)
        since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        fql = f"created_timestamp:>'{since}'+severity_name:['Critical','High']"

        # Step 1: Get detection IDs
        ids_resp = await client.get(
            f"{base_url}/detects/queries/detects/v1",
            headers=headers,
            params={"filter": fql, "limit": 100},
        )
        ids_resp.raise_for_status()
        detect_ids = ids_resp.json().get("resources", [])

        if not detect_ids:
            return []

        # Step 2: Get detection details
        details_resp = await client.post(
            f"{base_url}/detects/entities/summaries/GET/v1",
            headers=headers,
            json={"ids": detect_ids[:100]},
        )
        details_resp.raise_for_status()
        return details_resp.json().get("resources", [])


def _parse_falcon_detection(raw: dict) -> dict:
    """Convert a Falcon detection summary to universal finding format."""
    severity_map = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Informational": "info",
    }
    severity = severity_map.get(raw.get("max_severity_displayname", "Medium"), "medium")
    device = raw.get("device", {})
    behaviors = raw.get("behaviors", [{}])
    tactic = behaviors[0].get("tactic", "") if behaviors else ""
    technique = behaviors[0].get("technique", "") if behaviors else ""

    return {
        "provider": "crowdstrike",
        "title": f"CrowdStrike: {raw.get('max_severity_displayname', 'Detection')} — {raw.get('filename', 'Unknown')}",
        "description": behaviors[0].get("description", "") if behaviors else "",
        "category": "malware" if "malware" in tactic.lower() else "threat",
        "severity": severity,
        "resource_id": device.get("device_id", ""),
        "resource_type": "endpoint",
        "resource_name": device.get("hostname", device.get("device_id", "unknown")),
        "region": device.get("site_name", ""),
        "risk_score": {"Critical": 95.0, "High": 80.0, "Medium": 55.0, "Low": 30.0}.get(
            raw.get("max_severity_displayname", "Medium"), 50.0
        ),
        "actively_exploited": severity == "critical",
        "external_id": raw.get("detection_id", ""),
        "remediation": "Investigate detection via CrowdStrike Falcon console. Consider host isolation if confirmed compromise.",
        "remediation_effort": "quick_win",
    }


async def fetch_findings(credentials: dict) -> list[dict]:
    """
    Authenticated fetch that propagates failure.

    ``get_findings`` deliberately falls back to demonstration data so a
    standalone view is never blank. A shared scan needs the opposite: a
    provider that failed must be reported as failed rather than counted as a
    successful scan that happened to return demo findings.
    """
    raw = await _fetch_real_findings(credentials)
    return provenance.live(
        [_parse_falcon_detection(d) for d in raw],
        provider="crowdstrike",
        connector="crowdstrike",
    )


async def get_findings(credentials: Optional[dict] = None) -> list[dict]:
    """Main entry point for CrowdStrike Falcon adapter."""
    if credentials:
        try:
            return await fetch_findings(credentials)
        except Exception as exc:
            logger.warning("CrowdStrike Falcon API failed: %s — using simulated data", exc)

    return provenance.simulated(SIMULATED_FINDINGS, provider="crowdstrike")
