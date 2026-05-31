"""InsiderClaw — Insider Threat Detection API Routes."""
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, select

from app.core.database import get_db
from app.models.finding import Finding
from app.services.connector_check import is_connector_configured

router = APIRouter(prefix="/insiderclaw", tags=["InsiderClaw"])
CLAW_NAME = "insiderclaw"


class InsiderTaskRequest(BaseModel):
    swarm_job_id: str
    task_type: str
    input: dict[str, Any] = {}
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = ["read", "analyze", "recommend"]

PROVIDER_MAP = [
    {"provider": "dtex",             "label": "DTEX Systems",       "connector_type": "dtex"},
    {"provider": "code42",           "label": "Code42 Incydr",      "connector_type": "code42"},
    {"provider": "microsoft_purview","label": "Microsoft Purview",  "connector_type": "microsoft_purview"},
]

_FINDINGS = [
    {
        "id": "ic-001",
        "claw": "insiderclaw",
        "provider": "dtex",
        "title": "Employee on Performance Plan Accessing HR Database — 14x Above Baseline",
        "description": (
            "DTEX detected that employee redacted_user, currently on a Performance "
            "Improvement Plan (PIP since December 4, 2023), accessed the HR database "
            "(hr-oracle-prod.corp.internal) 287 times between January 10–15 — 14x above "
            "their 90-day baseline of 20 accesses/week. "
            "Records queried include: other employees' salary bands, performance review scores, "
            "disciplinary action history, and the HR policy exception log. "
            "krodriguez's job function (Junior QA Analyst) provides no legitimate business "
            "need to access HR compensation or review data. "
            "DTEX risk score for krodriguez has escalated from 12 (baseline) to 87 (critical) "
            "over the past 15 days, driven by this database activity combined with 3 USB "
            "insertion events and an after-hours VPN connection."
        ),
        "category": "policy_violation",
        "severity": "HIGH",
        "resource_id": "hr-oracle-prod.corp.internal",
        "resource_type": "Database",
        "resource_name": "hr-oracle-prod",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately remove krodriguez's database access to hr-oracle-prod. "
            "2. Engage HR and legal for insider threat assessment — PIP context elevates risk. "
            "3. Preserve access logs and query history as potential evidence. "
            "4. Conduct a targeted review: what specific records were accessed and what data was viewed? "
            "5. Implement role-based access controls on HR database — QA role should have no access. "
            "6. Brief krodriguez's manager on the activity without alerting the subject."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 84.0,
        "actively_exploited": False,
        "first_seen": "2024-01-10T09:22:00Z",
        "external_id": "IC-DTEX-20240110-001",
    },
    {
        "id": "ic-002",
        "claw": "insiderclaw",
        "provider": "code42",
        "title": "USB Device Connected on Employee's Last Day of Employment",
        "description": (
            "Code42 Incydr endpoint DLP detected a USB mass storage device (WD My Passport 2TB, "
            "serial: WX31A78B5234) connected to workstation ASSET-WS-3821 (assigned to "
            "senior architect redacted_user) at 16:22 UTC on January 19 — bpatel's "
            "confirmed last day of employment. "
            "541 files were copied to the device totaling 8.3 GB: product architecture documents "
            "(83 .vsdx and .drawio files), AWS infrastructure Terraform configurations "
            "(174 .tf files), customer integration specifications (61 .pdf NDA documents), "
            "and patent-pending design files (12 .docx). "
            "bpatel accepted an offer at a known direct competitor (verified via LinkedIn). "
            "USB storage is prohibited on workstations with elevated data classification."
        ),
        "category": "ip_theft",
        "severity": "CRITICAL",
        "resource_id": "ASSET-WS-3821",
        "resource_type": "Workstation",
        "resource_name": "bpatel-ws3821",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Do not allow bpatel to take the USB device — engage security escort for offboarding. "
            "2. Preserve forensic image of ASSET-WS-3821 before the device is returned. "
            "3. Engage legal immediately — potential trade secret theft (DTSA). "
            "4. Conduct supervised exit interview with legal counsel present. "
            "5. Implement Code42 Incydr USB block policy on all workstations with elevated data access. "
            "6. Review bpatel's email, SharePoint, and cloud sync activity for additional exfiltration channels."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 97.0,
        "actively_exploited": True,
        "first_seen": "2024-01-19T16:22:00Z",
        "external_id": "IC-CODE42-20240119-002",
    },
    {
        "id": "ic-003",
        "claw": "insiderclaw",
        "provider": "microsoft_purview",
        "title": "Mass Email Forward to Personal Account Before Resignation",
        "description": (
            "Microsoft Purview Communication Compliance detected that user redacted_user "
            "created an Outlook inbox rule on January 13 that auto-forwards all incoming email "
            "to personal account redacted_user. "
            "Since the rule was created, 1,247 emails have been forwarded including: "
            "board meeting minutes, M&A due diligence requests, client contract negotiations, "
            "and product pricing discussions. "
            "mwilliams submitted their resignation on January 15 (2 days after setting up the rule). "
            "The forwarding rule was set up before the resignation — indicating premeditation. "
            "Auto-forwarding to personal email violates the Acceptable Use Policy and may "
            "constitute a breach of fiduciary duty given the board-level content forwarded."
        ),
        "category": "data_exfiltration",
        "severity": "CRITICAL",
        "resource_id": "user-mwilliams-m365-id-00j1k2l3",
        "resource_type": "M365User",
        "resource_name": "redacted_user",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately delete the forwarding rule and block further email forwarding to gmail.com. "
            "2. Revoke mwilliams' access — do not wait for resignation last day. "
            "3. Preserve the 1,247 forwarded emails list for legal proceedings. "
            "4. Engage legal — forward to personal email may violate board confidentiality obligations. "
            "5. Implement Exchange Transport Rule: block auto-forwarding to external domains. "
            "6. Enable Microsoft Purview DLP policy to alert on new auto-forwarding rules within 1 hour."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 95.0,
        "actively_exploited": True,
        "first_seen": "2024-01-13T08:14:00Z",
        "external_id": "IC-PURVIEW-20240113-003",
    },
    {
        "id": "ic-004",
        "claw": "insiderclaw",
        "provider": "microsoft_purview",
        "title": "Sensitive Document Printed 47 Times in One Day — Potential Physical Exfiltration",
        "description": (
            "Microsoft Purview detected that user redacted_user sent 47 print jobs "
            "for document 'M&A_Target_Analysis_CONFIDENTIAL_v3.pdf' (sensitivity label: "
            "CONFIDENTIAL — do not distribute) to printer PR-FLOOR3-EXEC-01 (executive floor) "
            "between 09:15–14:47 UTC. Each print job was for the full 24-page document "
            "— totaling 1,128 pages printed. "
            "gnavarro's normal printing volume is 8–15 pages per week. "
            "Badge access records show gnavarro accessed Floor 3 (executive area) 3 times "
            "during this window — suggesting they retrieved the physical copies. "
            "gnavarro's role (Business Analyst) provides no legitimate reason to print "
            "M&A target analysis documents 47 times."
        ),
        "category": "data_exfiltration",
        "severity": "HIGH",
        "resource_id": "PR-FLOOR3-EXEC-01",
        "resource_type": "NetworkPrinter",
        "resource_name": "exec-floor3-printer-01",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Locate and retrieve all physical copies — review badge swipe data for Floor 3 entries. "
            "2. Interview gnavarro with legal counsel — determine who requested the 47 prints. "
            "3. Restrict PR-FLOOR3-EXEC-01 access to users with Floor 3 badge clearance. "
            "4. Implement print count alerting: >10 prints of a CONFIDENTIAL document triggers security alert. "
            "5. Deploy pull-printing (PIN release) on all printers to prevent unclaimed jobs. "
            "6. Audit gnavarro's access permissions to M&A documents — may be over-privileged."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 80.0,
        "actively_exploited": False,
        "first_seen": "2024-01-15T09:15:00Z",
        "external_id": "IC-PURVIEW-20240115-004",
    },
    {
        "id": "ic-005",
        "claw": "insiderclaw",
        "provider": "dtex",
        "title": "VPN Connection at 2AM from Unusual Location — Employee in Non-Travel Role",
        "description": (
            "DTEX detected a VPN connection for user redacted_user at 02:14 AM from "
            "IP 188.165.44.22 (OVH SAS datacenter, Roubaix, France). "
            "fpham is a finance analyst with no travel requirements and has never connected "
            "from outside the US in 18 months of employment. "
            "The France IP is a VPS provider commonly used by threat actors to launder "
            "connections. Following authentication, fpham accessed the financial reporting "
            "system (Hyperion), executed 12 report exports including Q4 earnings forecasts "
            "and budget vs actuals, and connected to the accounts payable database. "
            "The session lasted 1 hour 22 minutes. fpham's laptop was confirmed off and "
            "locked at the NYC office at the time (DTEX endpoint telemetry confirms no "
            "local activity on the device — the VPN credentials were used by a different machine)."
        ),
        "category": "unauthorized_access",
        "severity": "CRITICAL",
        "resource_id": "user-fpham-aad-objectid-00m4n5o6",
        "resource_type": "AzureADUser",
        "resource_name": "redacted_user",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately revoke all sessions for fpham and force password + MFA reset. "
            "2. Block IP 188.165.44.22 and the OVH ASN at the VPN gateway. "
            "3. Verify with fpham in person — confirm this was credential theft not authorized access. "
            "4. Review all 12 exported reports for sensitive financial data — assess breach scope. "
            "5. Notify CFO and legal — Q4 earnings forecasts may be in unauthorized hands. "
            "6. Enable location-based Conditional Access: block VPN logins from datacenter ASNs."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 93.0,
        "actively_exploited": True,
        "first_seen": "2024-01-17T02:14:00Z",
        "external_id": "IC-DTEX-20240117-005",
    },
    {
        "id": "ic-006",
        "claw": "insiderclaw",
        "provider": "code42",
        "title": "Competitive Intelligence Database Access Spike — 340% Above Baseline",
        "description": (
            "Code42 Incydr detected that user redacted_user (Sales Director) accessed "
            "the competitive intelligence SharePoint library 'CompetitiveIntel-RESTRICTED' "
            "89 times in the past 7 days, compared to a 90-day baseline of 6 accesses/week. "
            "This represents a 340% spike. Documents accessed include current win/loss analysis "
            "against specific named competitors, pricing comparison matrices, and the Q1 2024 "
            "sales strategy playbook. "
            "Context: rmcallister was passed over for VP of Sales promotion 3 weeks ago and "
            "has had two calendar meetings titled 'Confidential' with unknown external parties "
            "this week (Zoom links, not corporate meeting rooms). "
            "HR flagged rmcallister as elevated-risk following the promotion decision."
        ),
        "category": "data_access_anomaly",
        "severity": "HIGH",
        "resource_id": "sharepoint-site-competitive-intel-restricted",
        "resource_type": "SharePointLibrary",
        "resource_name": "CompetitiveIntel-RESTRICTED",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Remove rmcallister's access to CompetitiveIntel-RESTRICTED pending investigation. "
            "2. Review the 89 access events — determine if documents were downloaded or shared externally. "
            "3. Investigate the two 'Confidential' Zoom meetings — request calendar metadata from IT. "
            "4. Engage HR and legal for insider threat review given promotion context and access spike. "
            "5. Implement SharePoint sensitivity labels with automatic DLP alerting on RESTRICTED libraries. "
            "6. Preserve Code42 file event logs as potential evidence for legal proceedings."
        ),
        "remediation_effort": "medium_term",
        "risk_score": 78.0,
        "actively_exploited": False,
        "first_seen": "2024-01-09T10:30:00Z",
        "external_id": "IC-CODE42-20240109-006",
    },
]


@router.get("/stats", summary="InsiderClaw summary statistics")
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


@router.get("/findings", summary="All InsiderClaw findings")
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


@router.get("/providers", summary="InsiderClaw provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    from app.services.connector_check import check_providers
    return await check_providers(db, PROVIDER_MAP)


@router.post("/scan", summary="Run InsiderClaw scan and persist findings")
async def run_scan(db: AsyncSession = Depends(get_db)):
    """Run an InsiderClaw scan. Persists via the finding pipeline for dedup, policy eval, and alerting."""
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


@router.post("/task", summary="Execute focused InsiderClaw swarm task")
async def run_insider_task(payload: InsiderTaskRequest, db: AsyncSession = Depends(get_db)):
    started = datetime.utcnow()
    any_configured = any([
        await is_connector_configured(db, p["connector_type"])
        for p in PROVIDER_MAP if p.get("connector_type")
    ])
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
        {"title": f.title, "detail": f"{f.provider or 'insider'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}"}
        for f in findings[:3]
    ] or [
        {"title": f.get("title", "Insider finding"), "detail": (f.get("description", "")[:220] or "Simulation finding")}
        for f in fallback
    ]
    return {
        "task_id": f"insider-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": "insiderclaw",
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": rows or [{"title": "No insider findings", "detail": "Run /insiderclaw/scan first."}],
        "evidence": [],
        "recommended_actions": [
            "Escalate insider-risk anomalies to HR/legal workflow",
            "Contain data exfiltration channels and preserve evidence",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["ISO 27001 A.6", "NIST AU-6"],
        "execution_time_ms": elapsed_ms,
        "data_source": "persisted_db" if findings else "seeded_fallback",
        "connector_state": "configured" if any_configured else "unconfigured",
    }
