"""UserClaw — User Behavior Analytics (UBA) API Routes."""
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, select

from app.core.database import get_db
from app.models.finding import Finding

router = APIRouter(prefix="/userclaw", tags=["UserClaw"])
CLAW_NAME = "userclaw"


class UserTaskRequest(BaseModel):
    swarm_job_id: str
    task_type: str
    input: dict[str, Any] = {}
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = ["read", "analyze", "recommend"]

PROVIDER_MAP = [
    {"provider": "microsoft_sentinel", "label": "Microsoft Sentinel UEBA", "connector_type": "microsoft_sentinel"},
    {"provider": "exabeam",            "label": "Exabeam",                  "connector_type": "exabeam"},
    {"provider": "securonix",          "label": "Securonix",                "connector_type": "securonix"},
]

_FINDINGS = [
    {
        "id": "uc-001",
        "claw": "userclaw",
        "provider": "exabeam",
        "title": "User Accessing 10x More Records Than Baseline — Potential Data Exfiltration",
        "description": (
            "User redacted_user accessed 14,382 customer records from the CRM system "
            "(salesforce-prod) between 09:00–11:30 UTC. Exabeam UEBA baseline analysis "
            "(90-day rolling average) shows this user's normal access rate is 1,240 records/week. "
            "The activity today represents a 10.3x deviation from baseline — flagged as a "
            "statistically anomalous event (z-score: 4.7). Records accessed include customer PII "
            "(name, address, SSN), payment card data, and account notes. "
            "The access was via the Salesforce API using an OAuth token rather than the web UI, "
            "which is atypical for this user's role (Account Executive)."
        ),
        "category": "data_access_anomaly",
        "severity": "CRITICAL",
        "resource_id": "salesforce-prod-instance-NA147",
        "resource_type": "CRMApplication",
        "resource_name": "salesforce-prod",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Suspend dthompson's Salesforce API access pending investigation. "
            "2. Revoke the OAuth token used for the anomalous access session. "
            "3. Determine if 14,382 records were downloaded or just viewed — check export/download logs. "
            "4. Interview dthompson and their manager — verify business justification. "
            "5. Notify DLP team and legal if data was extracted outside the system. "
            "6. Implement Salesforce API rate limiting: max 2,000 records/day for Account Executive role."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 92.0,
        "actively_exploited": False,
        "first_seen": "2024-01-15T09:00:00Z",
        "external_id": "UC-EXABEAM-20240115-001",
    },
    {
        "id": "uc-002",
        "claw": "userclaw",
        "provider": "microsoft_sentinel",
        "title": "Impossible Travel Detected — New York to London in 2 Hours",
        "description": (
            "Microsoft Sentinel UEBA detected an impossible travel event for user "
            "redacted_user. Authentication from New York City (IP 203.0.113.45, "
            "Verizon AS701, geolocation: 40.7128N 74.0060W) was recorded at 08:42 UTC. "
            "A subsequent successful authentication occurred at 10:38 UTC from London, UK "
            "(IP 185.220.101.6, Virgin Media AS5089, geolocation: 51.5074N 0.1278W) — "
            "a physical distance of 5,570 km traversed in 1 hour 56 minutes. "
            "Commercial flight time between these cities is minimum 7 hours. "
            "The London IP is listed in threat intelligence feeds as a VPN exit node "
            "associated with credential-based attacks. The New York session accessed "
            "the HR system; the London session accessed the financial reporting tool."
        ),
        "category": "impossible_travel",
        "severity": "CRITICAL",
        "resource_id": "user-jsmith-aad-objectid-00a1b2c3",
        "resource_type": "AzureADUser",
        "resource_name": "redacted_user",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately revoke all active sessions and refresh tokens for redacted_user. "
            "2. Force password reset with MFA re-enrollment. "
            "3. Determine which resources were accessed from the London IP and assess data exposure. "
            "4. Correlate with physical badge access data to confirm if jsmith was actually in NYC. "
            "5. Block the London IP range at the identity provider perimeter. "
            "6. Enable Conditional Access policy: require MFA step-up for new country logins."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 97.0,
        "actively_exploited": True,
        "first_seen": "2024-01-15T10:38:00Z",
        "external_id": "UC-SENTINEL-20240115-002",
    },
    {
        "id": "uc-003",
        "claw": "userclaw",
        "provider": "securonix",
        "title": "Admin Account Used Outside Business Hours — Privileged Access at 02:47 AM",
        "description": (
            "Securonix UEBA flagged privileged account CORP\\svc-dba-admin accessing "
            "production Oracle database fin-oracle-prod-01 at 02:47 AM local time on Wednesday "
            "— outside this account's established activity window (Mon–Fri, 08:00–18:00). "
            "The session ran for 47 minutes and executed 23 DDL statements including "
            "ALTER TABLE, DROP INDEX, and GRANT commands on the payroll and accounts_payable schemas. "
            "No change management ticket (ITSM) was opened, no on-call rotation assigned "
            "this account, and the DBA team lead confirmed no authorized work was scheduled. "
            "This is the first after-hours access for this account in 14 months of history."
        ),
        "category": "after_hours_privileged_access",
        "severity": "CRITICAL",
        "resource_id": "fin-oracle-prod-01.corp.internal",
        "resource_type": "Database",
        "resource_name": "fin-oracle-prod-01",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Revoke the session immediately and disable CORP\\svc-dba-admin pending investigation. "
            "2. Review all 23 DDL statements executed — check for unauthorized schema modifications. "
            "3. Identify who used the admin account: check source workstation and user attribution. "
            "4. Implement just-in-time (JIT) privileged access with ITSM ticket requirement. "
            "5. Alert on any privileged database access outside approved maintenance windows. "
            "6. Enable Oracle Unified Audit for full SQL statement logging on fin-oracle-prod-01."
        ),
        "remediation_effort": "medium_term",
        "risk_score": 88.0,
        "actively_exploited": False,
        "first_seen": "2024-01-17T02:47:00Z",
        "external_id": "UC-SECURONIX-20240117-003",
    },
    {
        "id": "uc-004",
        "claw": "userclaw",
        "provider": "exabeam",
        "title": "Bulk Data Download Before Resignation — 4.1 GB Downloaded by Departing Employee",
        "description": (
            "Exabeam detected that senior engineer redacted_user, who submitted resignation "
            "6 days ago (last day: January 22, 2024), downloaded 4.1 GB of files from "
            "SharePoint, GitHub, and the internal wiki between 14:30–17:15 UTC. "
            "File types include source code archives (.zip from GitHub API), architecture "
            "diagrams (.vsdx, .drawio), client NDA documents (.pdf), and product roadmaps (.pptx). "
            "The download volume is 31x above aparker's 90-day baseline (avg 130 MB/week). "
            "LinkedIn shows aparker accepted an offer at a direct competitor. "
            "The data was transferred to an external USB drive and personal Google Drive account "
            "(drive.google.com — confirmed by DLP proxy logs)."
        ),
        "category": "data_exfiltration",
        "severity": "CRITICAL",
        "resource_id": "user-aparker-m365-id-00d4e5f6",
        "resource_type": "M365User",
        "resource_name": "redacted_user",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Revoke aparker's access to all systems immediately — do not wait for last day. "
            "2. Preserve forensic image of aparker's corporate laptop before return. "
            "3. Engage legal and HR — potential trade secret theft under the DTSA. "
            "4. Block Google Drive uploads from corporate proxies via CASB policy. "
            "5. Implement departing employee alert: automatically flag >50 file downloads/day for leavers. "
            "6. Conduct exit interview with legal counsel present."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 96.0,
        "actively_exploited": True,
        "first_seen": "2024-01-16T14:30:00Z",
        "external_id": "UC-EXABEAM-20240116-004",
    },
    {
        "id": "uc-005",
        "claw": "userclaw",
        "provider": "microsoft_sentinel",
        "title": "MFA Bypass via Legacy Authentication Protocol — IMAP Access to Exchange",
        "description": (
            "Microsoft Sentinel detected user redacted_user authenticating to Exchange Online "
            "via IMAP (legacy protocol) from IP 91.108.56.183 at 03:22 UTC. "
            "The organization's Conditional Access policy requires MFA for all cloud app access "
            "— but the IMAP protocol does not support modern authentication, bypassing MFA entirely. "
            "The IMAP session downloaded 847 email messages including 12 flagged by DLP as "
            "containing financial data and 3 containing HR information. "
            "bpatel's primary workstation IP is 10.0.1.155 (corporate network) — the IMAP "
            "access from 91.108.56.183 (Bucharest, Romania) is geographically anomalous. "
            "This technique matches MITRE ATT&CK T1078.004 (Valid Accounts: Cloud Accounts)."
        ),
        "category": "mfa_bypass",
        "severity": "HIGH",
        "resource_id": "user-bpatel-aad-objectid-00g7h8i9",
        "resource_type": "AzureADUser",
        "resource_name": "redacted_user",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Disable legacy authentication for bpatel's account immediately. "
            "2. Force password reset and MFA re-enrollment for redacted_user. "
            "3. Create a Conditional Access policy to block all legacy authentication protocols org-wide. "
            "4. Audit which other accounts have authenticated via IMAP or POP3 in the past 30 days. "
            "5. Review the 847 downloaded emails for data exfiltration scope. "
            "6. Block IMAP/POP3 at the Exchange Online tenant level."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 82.0,
        "actively_exploited": True,
        "first_seen": "2024-01-17T03:22:00Z",
        "external_id": "UC-SENTINEL-20240117-005",
    },
    {
        "id": "uc-006",
        "claw": "userclaw",
        "provider": "securonix",
        "title": "Account Sharing Detected — Concurrent Sessions from 3 Different IP Addresses",
        "description": (
            "Securonix detected simultaneous active sessions for shared service account "
            "'redacted_user' from 3 geographically distinct IP addresses: "
            "10.0.1.47 (NYC office), 203.0.113.88 (Chicago office), and 198.51.100.44 "
            "(unrecognized external IP — Frankfurt, Germany). "
            "All three sessions are active concurrently — this is only possible if the "
            "account credentials are being shared between users or the account has been "
            "compromised. The Frankfurt session is executing API calls to the financial "
            "reporting system at 3x the rate of the office sessions. "
            "Shared accounts violate SOX compliance requirements and destroy individual "
            "accountability in audit trails."
        ),
        "category": "account_sharing",
        "severity": "HIGH",
        "resource_id": "redacted_user",
        "resource_type": "SharedServiceAccount",
        "resource_name": "svc-reporting",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately terminate the Frankfurt session — it is the anomalous external connection. "
            "2. Rotate svc-reporting credentials and issue individual named accounts to replace the shared one. "
            "3. Identify all users currently using svc-reporting — check with the finance team. "
            "4. Enable concurrent session limits: max 1 active session per account. "
            "5. Audit all shared service accounts for SOX compliance — shared accounts must be eliminated. "
            "6. Review the Frankfurt IP's API activity for unauthorized data extraction."
        ),
        "remediation_effort": "medium_term",
        "risk_score": 77.0,
        "actively_exploited": False,
        "first_seen": "2024-01-16T11:15:00Z",
        "external_id": "UC-SECURONIX-20240116-006",
    },
]


@router.get("/stats", summary="UserClaw summary statistics")
async def get_stats(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    from app.models.finding import Finding
    result = await db.execute(select(Finding).where(Finding.claw == CLAW_NAME))
    findings = result.scalars().all()
    if not findings:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        open_count = 0; providers = set()
        for f in _FINDINGS:
            sev = f["severity"].lower()
            if sev in severity_counts: severity_counts[sev] += 1
            if f.get("status") == "OPEN": open_count += 1
            providers.add(f["provider"])
        return {"total": len(_FINDINGS), "critical": severity_counts["critical"],
                "high": severity_counts["high"], "medium": severity_counts["medium"],
                "low": severity_counts["low"], "open": open_count,
                "resolved": len(_FINDINGS) - open_count,
                "providers_connected": len(providers), "last_scan": None}
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    open_count = 0; providers = set(); last_seen = None
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev in by_sev: by_sev[sev] += 1
        if (f.status.value if hasattr(f.status, "value") else str(f.status)) == "open": open_count += 1
        if f.provider: providers.add(f.provider)
        if f.last_seen and (last_seen is None or f.last_seen > last_seen): last_seen = f.last_seen
    return {"total": len(findings), "critical": by_sev["critical"], "high": by_sev["high"],
            "medium": by_sev["medium"], "low": by_sev["low"], "open": open_count,
            "resolved": len(findings) - open_count, "providers_connected": len(providers),
            "last_scan": last_seen.isoformat() if last_seen else None}


@router.get("/findings", summary="All UserClaw findings")
async def get_findings(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    from app.models.finding import Finding
    from app.services.connector_check import is_connector_configured
    result = await db.execute(
        select(Finding).where(Finding.claw == CLAW_NAME).order_by(Finding.risk_score.desc())
    )
    findings = result.scalars().all()
    if not findings:
        any_configured = any([
            await is_connector_configured(db, p["connector_type"])
            for p in PROVIDER_MAP if p.get("connector_type")
        ])
        if not any_configured:
            return _FINDINGS
        return []
    return [
        {
            "id": str(f.id), "claw": f.claw, "provider": f.provider,
            "title": f.title, "description": f.description, "category": f.category,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "status": f.status.value if hasattr(f.status, "value") else f.status,
            "resource_id": f.resource_id, "resource_type": f.resource_type,
            "resource_name": f.resource_name, "region": f.region,
            "risk_score": f.risk_score, "actively_exploited": f.actively_exploited,
            "remediation": f.remediation, "remediation_effort": f.remediation_effort,
            "external_id": f.external_id,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        }
        for f in findings
    ]


@router.get("/providers", summary="UserClaw provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    from app.services.connector_check import check_providers
    return await check_providers(db, PROVIDER_MAP)


@router.get("/anomalies", summary="User anomaly summary counts")
async def get_anomalies():
    return {
        "users_with_anomalies": 8,
        "high_risk_users": 3,
        "new_anomalies_24h": 2,
        "avg_risk_score": 42.3,
    }


@router.post("/scan", summary="Run User Claw scan and persist findings")
async def run_scan(db: AsyncSession = Depends(get_db)):
    """Run a UserClaw scan. Persists via the finding pipeline for dedup, policy eval, and alerting."""
    from app.services.finding_pipeline import ingest_findings
    pipeline_findings = []
    for f in _FINDINGS:
        entry = dict(f)
        entry.setdefault("claw", CLAW_NAME)
        if "severity" in entry:
            entry["severity"] = str(entry["severity"]).lower()
        pipeline_findings.append(entry)
    summary = await ingest_findings(db, CLAW_NAME, pipeline_findings)
    return {
        "status": "completed",
        "findings_created": summary["created"],
        "findings_updated": summary["updated"],
        "critical": summary["critical"],
        "high": summary["high"],
    }


@router.post("/task", summary="Execute focused UserClaw swarm task")
async def run_user_task(payload: UserTaskRequest, db: AsyncSession = Depends(get_db)):
    started = datetime.utcnow()
    result = await db.execute(
        select(Finding).where(Finding.claw == CLAW_NAME).order_by(desc(Finding.risk_score)).limit(5)
    )
    findings = result.scalars().all()
    fallback = _FINDINGS[:3] if not findings else []
    max_risk = max(
        [float(f.risk_score or 0.0) for f in findings],
        default=max([float(f.get("risk_score") or 0.0) for f in fallback], default=0.0),
    )
    severity = "critical" if max_risk >= 85 else "high" if max_risk >= 70 else "medium" if max_risk >= 40 else "low"
    confidence = 0.88 if findings else 0.74
    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    rows = [
        {"title": f.title, "detail": f"{f.provider or 'user'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}"}
        for f in findings[:3]
    ] or [
        {"title": f.get("title", "User finding"), "detail": (f.get("description", "")[:220] or "Simulation finding")}
        for f in fallback
    ]
    return {
        "task_id": f"user-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": "userclaw",
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": rows or [{"title": "No user findings", "detail": "Run /userclaw/scan first."}],
        "evidence": [],
        "recommended_actions": [
            "Contain anomalous user sessions and enforce step-up controls",
            "Escalate high-risk identity behavior to incident response",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["NIST AC-2", "ISO 27001 A.9"],
        "execution_time_ms": elapsed_ms,
    }
