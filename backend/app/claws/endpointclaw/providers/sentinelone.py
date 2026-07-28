"""
SentinelOne Adapter
Pulls threats and alerts from SentinelOne Singularity platform.

Auth: API Token (passed as Authorization header)
API docs: https://usea1-partners.sentinelone.net/api-doc/

Credentials expected:
  {
    "api_token": "...",
    "base_url": "https://usea1.sentinelone.net"
  }
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from app.claws import provenance

logger = logging.getLogger("endpointclaw.sentinelone")

TIMEOUT = httpx.Timeout(30.0)

SIMULATED_FINDINGS = [
    {
        "title": "SentinelOne: Ransomware Activity Blocked on SERVER-PROD-04",
        "description": (
            "SentinelOne detected and killed a ransomware process (Conti variant) on SERVER-PROD-04 "
            "before encryption began. Shadow copies were preserved. C2 domains blocked by network quarantine."
        ),
        "category": "malware",
        "severity": "critical",
        "resource_id": "SERVER-PROD-04",
        "resource_type": "endpoint",
        "resource_name": "SERVER-PROD-04",
        "risk_score": 97.0,
        "cvss_score": 9.9,
        "actively_exploited": True,
        "remediation": "Isolate SERVER-PROD-04. Run full threat scope. Rotate all credentials used from this server.",
        "remediation_effort": "quick_win",
        "external_id": "S1-THREAT-CONTI-SERVER-PROD-04",
    },
    {
        "title": "SentinelOne: Credential Dumping via Mimikatz on DEV-WIN-0022",
        "description": (
            "SentinelOne detected Mimikatz-style credential dumping attempt on DEV-WIN-0022. "
            "The process was blocked in detect mode. LSASS memory access was attempted from a non-system process."
        ),
        "category": "threat",
        "severity": "high",
        "resource_id": "DEV-WIN-0022",
        "resource_type": "endpoint",
        "resource_name": "DEV-WIN-0022",
        "risk_score": 88.0,
        "actively_exploited": True,
        "remediation": "Enable Credential Guard. Rotate all domain account passwords. Review DEV-WIN-0022 for persistence.",
        "remediation_effort": "quick_win",
        "external_id": "S1-THREAT-CREDUMP-DEV-0022",
    },
    {
        "title": "SentinelOne: Suspicious WMI Lateral Movement from CORP-WIN-0055",
        "description": (
            "SentinelOne flagged outbound WMI remote execution (wmic /node:… process call create) "
            "from CORP-WIN-0055 targeting 6 other hosts in the 10.10.20.0/24 subnet. "
            "The technique matches TA0008 (Lateral Movement). Process was detected but not killed — "
            "sensor policy is set to 'Detect' on this host group."
        ),
        "category": "threat",
        "severity": "high",
        "resource_id": "CORP-WIN-0055",
        "resource_type": "endpoint",
        "resource_name": "CORP-WIN-0055",
        "risk_score": 86.0,
        "cvss_score": 8.3,
        "actively_exploited": True,
        "remediation": (
            "Switch sensor policy for CORP-WIN-0055 host group to 'Protect' mode immediately. "
            "Isolate CORP-WIN-0055. Audit all 6 WMI target hosts for secondary payloads."
        ),
        "remediation_effort": "quick_win",
        "external_id": "S1-THREAT-WMI-LATERAL-WIN-0055",
        "reference_url": "https://attack.mitre.org/techniques/T1047/",
    },
    {
        "title": "SentinelOne: Agent Disconnected — 18 Endpoints Unreachable > 5 Days",
        "description": (
            "18 SentinelOne agents have not connected to the management console for more than 5 days. "
            "Endpoints without active agent connections receive no real-time threat detection or policy updates. "
            "Affected hosts are in the REMOTE-MAC-* and CORP-LINUX-* ranges."
        ),
        "category": "missing_edr",
        "severity": "medium",
        "resource_id": "s1-group-disconnected-agents",
        "resource_type": "endpoint_group",
        "resource_name": "disconnected-agent-fleet",
        "risk_score": 60.0,
        "actively_exploited": False,
        "remediation": (
            "Check network connectivity and VPN status for affected endpoints. "
            "Re-register agents that have been reimaged. Remove stale records older than 30 days."
        ),
        "remediation_effort": "medium_term",
        "external_id": "S1-AGENT-DISCONNECTED-18",
    },
    {
        "title": "SentinelOne: Supply-Chain IOC Match — SolarWinds Orion DLL on MGMT-WIN-01",
        "description": (
            "SentinelOne's threat intelligence matched a SolarWinds Orion DLL (SolarWinds.Orion.Core.BusinessLayer.dll) "
            "hash against the known supply-chain compromise indicator list on MGMT-WIN-01. "
            "The file was not quarantined — it was on the global exclusion list added by the previous IT admin."
        ),
        "category": "malware",
        "severity": "critical",
        "resource_id": "MGMT-WIN-01",
        "resource_type": "endpoint",
        "resource_name": "MGMT-WIN-01",
        "risk_score": 99.0,
        "cvss_score": 10.0,
        "epss_score": 0.97,
        "actively_exploited": True,
        "remediation": (
            "Remove the global exclusion covering SolarWinds DLL hashes. "
            "Quarantine the flagged file and isolate MGMT-WIN-01. "
            "Rotate all credentials stored or used from this management host. "
            "Conduct a full IR engagement — this host likely has network-wide access."
        ),
        "remediation_effort": "quick_win",
        "external_id": "S1-SUPPLYCHAIN-SOLARWINDS-MGMT-01",
        "reference_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a",
    },
    {
        "title": "SentinelOne: macOS Gatekeeper Bypass Detected on CORP-MAC-0031",
        "description": (
            "SentinelOne detected an unsigned application executing on CORP-MAC-0031 after a Gatekeeper bypass. "
            "The application used the com.apple.quarantine attribute removal technique to avoid macOS notarization checks. "
            "The process attempted to install a LaunchAgent persistence entry."
        ),
        "category": "threat",
        "severity": "high",
        "resource_id": "CORP-MAC-0031",
        "resource_type": "endpoint",
        "resource_name": "CORP-MAC-0031",
        "risk_score": 81.0,
        "actively_exploited": True,
        "remediation": (
            "Remove the malicious LaunchAgent from ~/Library/LaunchAgents/. "
            "Enable MDM-enforced Gatekeeper policy: 'App Store and identified developers' only. "
            "Audit macOS endpoints for unauthorized xattr -d com.apple.quarantine usage."
        ),
        "remediation_effort": "quick_win",
        "external_id": "S1-THREAT-GATEKEEPER-BYPASS-MAC-0031",
        "reference_url": "https://attack.mitre.org/techniques/T1553/001/",
    },
    {
        "title": "SentinelOne: Protect Policy Not Applied — 9 Linux Servers in Detect-Only Mode",
        "description": (
            "9 Linux servers in the APP-PROD-LINUX-* group are running SentinelOne in 'Detect' mode only. "
            "Threats are observed and alerted but not automatically remediated. "
            "This misconfiguration was introduced during a policy migration 3 weeks ago."
        ),
        "category": "misconfiguration",
        "severity": "medium",
        "resource_id": "s1-group-linux-detect-only",
        "resource_type": "endpoint_group",
        "resource_name": "APP-PROD-LINUX-detect-only",
        "risk_score": 57.0,
        "actively_exploited": False,
        "remediation": (
            "Update the S1 policy for the APP-PROD-LINUX-* group to 'Protect' mode. "
            "Validate no exclusions are blocking protection on kernel modules."
        ),
        "remediation_effort": "quick_win",
        "external_id": "S1-POLICY-DETECT-ONLY-LINUX-9",
    },
]


async def _fetch_real_findings(credentials: dict) -> list[dict]:
    base_url = credentials.get("base_url", "").rstrip("/")
    api_token = credentials.get("api_token", "")

    if not base_url or not api_token:
        raise ValueError("SentinelOne requires base_url and api_token")

    headers = {"Authorization": f"ApiToken {api_token}", "Content-Type": "application/json"}
    since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{base_url}/web/api/v2.1/threats",
            headers=headers,
            params={
                "createdAt__gte": since,
                "resolved": False,
                "confidenceLevel__in": "malicious,suspicious",
                "limit": 100,
            },
        )
        resp.raise_for_status()
        return resp.json().get("data", [])


def _parse_s1_threat(raw: dict) -> dict:
    info = raw.get("threatInfo", {})
    agent = raw.get("agentRealtimeInfo", {})
    sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    severity = sev_map.get(info.get("confidenceLevel", "medium").lower(), "medium")

    return {
        "provider": "sentinelone",
        "title": f"SentinelOne: {info.get('classification', 'Threat')} on {agent.get('agentComputerName', 'unknown')}",
        "description": info.get("threatName", ""),
        "category": "malware",
        "severity": severity,
        "resource_id": agent.get("agentId", ""),
        "resource_type": "endpoint",
        "resource_name": agent.get("agentComputerName", "unknown"),
        "risk_score": 90.0 if severity == "critical" else 70.0 if severity == "high" else 50.0,
        "actively_exploited": info.get("confidenceLevel", "") == "malicious",
        "external_id": raw.get("id", ""),
        "remediation": "Investigate threat in SentinelOne console. Consider endpoint isolation if confirmed compromise.",
        "remediation_effort": "quick_win",
    }


async def fetch_findings(credentials: dict) -> list[dict]:
    """Authenticated fetch that propagates failure to the caller."""
    raw = await _fetch_real_findings(credentials)
    return provenance.live(
        [_parse_s1_threat(t) for t in raw],
        provider="sentinelone",
        connector="sentinelone",
    )


async def get_findings(credentials: Optional[dict] = None) -> list[dict]:
    if credentials:
        try:
            return await fetch_findings(credentials)
        except Exception as exc:
            logger.warning("SentinelOne API failed: %s — using simulated data", exc)
    return provenance.simulated(SIMULATED_FINDINGS, provider="sentinelone")
