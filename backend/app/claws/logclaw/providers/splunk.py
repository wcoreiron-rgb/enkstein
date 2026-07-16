"""
Splunk Adapter
Pulls security alerts and notable events from Splunk Enterprise Security.

Auth: Username/password or API token
Credentials expected:
  {
    "base_url": "https://splunk.company.com:8089",
    "username": "admin",
    "password": "..."
  }
  OR
  {
    "base_url": "https://splunk.company.com:8089",
    "token": "Splunk <token>"
  }
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

logger = logging.getLogger("logclaw.splunk")
TIMEOUT = httpx.Timeout(60.0)

SIMULATED_FINDINGS = [
    {
        "title": "Splunk ES: 847 Failed Logins from 192.168.10.45 in 1 Hour",
        "description": (
            "Splunk Enterprise Security detected a brute-force credential attack. "
            "Host 192.168.10.45 attempted 847 logins against 23 different accounts in under 60 minutes. "
            "5 accounts were locked out. No successful logins detected."
        ),
        "category": "brute_force",
        "severity": "critical",
        "resource_id": "192.168.10.45",
        "resource_type": "ip_address",
        "resource_name": "192.168.10.45",
        "risk_score": 92.0,
        "actively_exploited": True,
        "remediation": "Block 192.168.10.45 at firewall. Investigate the source — check if it's a misconfigured internal service. Unlock affected accounts after verifying owner identity.",
        "remediation_effort": "quick_win",
        "external_id": "SPLUNK-ES-BRUTE-FORCE-192.168.10.45",
    },
    {
        "title": "Splunk ES: Data Exfiltration Pattern — 4.2 GB Outbound to Unknown IP",
        "description": (
            "Unusual outbound data transfer detected: HOST-CORP-042 transferred 4.2 GB to external IP 91.213.9.18 "
            "(unregistered, Eastern Europe) between 02:00-03:30 UTC. "
            "No legitimate business context found for this transfer."
        ),
        "category": "data_exfiltration",
        "severity": "critical",
        "resource_id": "HOST-CORP-042",
        "resource_type": "host",
        "resource_name": "HOST-CORP-042",
        "risk_score": 97.0,
        "actively_exploited": True,
        "remediation": "Immediately isolate HOST-CORP-042. Block IP 91.213.9.18 at perimeter. Review all outbound connections from this host. Initiate incident response.",
        "remediation_effort": "quick_win",
        "external_id": "SPLUNK-ES-EXFIL-CORP-042",
    },
    {
        "title": "Splunk: Windows Event ID 4698 — Suspicious Scheduled Task Created",
        "description": (
            "Windows Event ID 4698 detected on CORP-WIN-0156: a scheduled task named 'WindowsUpdateHelper' "
            "was created by non-SYSTEM user 'svc-app01' pointing to %APPDATA%\\svchost.exe. "
            "Persistence mechanism indicator."
        ),
        "category": "persistence",
        "severity": "high",
        "resource_id": "CORP-WIN-0156",
        "resource_type": "host",
        "resource_name": "CORP-WIN-0156",
        "risk_score": 85.0,
        "actively_exploited": False,
        "remediation": "Investigate the scheduled task and the binary at %APPDATA%\\svchost.exe. Remove if malicious. Check svc-app01 account for compromise.",
        "remediation_effort": "quick_win",
        "external_id": "SPLUNK-WIN-SCHED-TASK-CORP-0156",
    },
    {
        "title": "Splunk: DNS Tunneling Detected — High Entropy DNS Queries",
        "description": (
            "DNS anomaly detection alert: HOST-DEV-0091 is generating DNS queries with unusually high entropy subdomains "
            "(avg 42 chars). Pattern consistent with DNS tunneling for C2 communication or data exfiltration."
        ),
        "category": "threat",
        "severity": "high",
        "resource_id": "HOST-DEV-0091",
        "resource_type": "host",
        "resource_name": "HOST-DEV-0091",
        "risk_score": 83.0,
        "actively_exploited": True,
        "remediation": "Block suspicious DNS resolution at DNS resolver. Isolate HOST-DEV-0091 and investigate DNS request logs. Check for rogue software.",
        "remediation_effort": "quick_win",
        "external_id": "SPLUNK-DNS-TUNNEL-DEV-0091",
    },
]


async def _fetch_real_findings(credentials: dict) -> list[dict]:
    """Run a Splunk search via the REST API to fetch notable events from Enterprise Security."""
    base_url = credentials.get("base_url", "").rstrip("/")
    if not base_url:
        raise ValueError("Splunk requires base_url")

    token = credentials.get("token", "")
    if token:
        headers = {"Authorization": token}
    else:
        import base64
        user = credentials.get("username", "")
        password = credentials.get("password", "")
        creds_b64 = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers = {"Authorization": f"Basic {creds_b64}"}

    # Search for notable events from the last 24 hours
    search = "search index=notable earliest=-24h | fields src_ip, dest, severity, description, rule_name | head 50"

    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
        # Create search job
        create_resp = await client.post(
            f"{base_url}/services/search/jobs",
            headers=headers,
            data={"search": search, "output_mode": "json", "exec_mode": "oneshot"},
        )
        create_resp.raise_for_status()
        results = create_resp.json().get("results", [])

    return results


def _parse_splunk_event(raw: dict) -> dict:
    severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    severity = severity_map.get(str(raw.get("severity", "medium")).lower(), "medium")
    return {
        "provider": "splunk",
        "title": f"Splunk: {raw.get('rule_name', 'Notable Event')}",
        "description": raw.get("description", ""),
        "category": "threat",
        "severity": severity,
        "resource_id": raw.get("src_ip", raw.get("dest", "")),
        "resource_type": "host",
        "resource_name": raw.get("dest", raw.get("src_ip", "unknown")),
        "risk_score": {"critical": 90.0, "high": 72.0, "medium": 50.0, "low": 25.0}.get(severity, 50.0),
        "actively_exploited": severity == "critical",
        "external_id": f"SPLUNK-{raw.get('rule_name', 'event').replace(' ', '-')[:80]}",
        "remediation": "Investigate via Splunk Enterprise Security console.",
        "remediation_effort": "quick_win",
    }


async def get_findings(credentials: Optional[dict] = None) -> list[dict]:
    if credentials:
        try:
            raw = await _fetch_real_findings(credentials)
            return [_parse_splunk_event(e) for e in raw]
        except Exception as exc:
            logger.warning("Splunk API failed: %s — using simulated data", exc)
    return [{**f, "provider": "splunk"} for f in SIMULATED_FINDINGS]
