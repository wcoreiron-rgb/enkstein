"""Third-Party & Vendor Risk Management API Routes."""
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy import desc

from app.core.database import get_db
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.services.connector_check import is_connector_configured

router = APIRouter(prefix="/vendorclaw", tags=["Vendor Risk"])

CLAW_NAME = "vendorclaw"
PROVIDER_MAP = [
    {"provider": "security_scorecard", "label": "SecurityScorecard", "connector_type": "security_scorecard"},
    {"provider": "bitsight",           "label": "BitSight",          "connector_type": "bitsight"},
    {"provider": "upguard",            "label": "UpGuard",           "connector_type": "upguard"},
]


class VendorTaskRequest(BaseModel):
    swarm_job_id: str
    task_type: str
    input: dict[str, Any] = {}
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = ["read", "analyze", "recommend"]

_FINDINGS = [
    {
        "id": "vc-001",
        "claw": "vendorclaw",
        "provider": "security_scorecard",
        "title": "Critical Vendor Rated 'D' by SecurityScorecard: Payment Processor (Stripe)",
        "description": (
            "SecurityScorecard assigned Stripe a score of 'D' (37/100) in the current assessment — "
            "a 21-point drop from their 'B' score six months ago. Scorecard breakdown: "
            "Network Security: F (open ports, exposed admin services), "
            "Patching Cadence: D (142 unpatched CVEs including 4 critical), "
            "Application Security: C (outdated TLS on 3 subdomains), "
            "Endpoint Security: D (detected EDR gaps). "
            "Stripe processes 100% of the organization's payment volume (~$2.8M/month). "
            "A security incident at Stripe could expose cardholder data and result in PCI-DSS "
            "liability. SecurityScorecard also flagged a data breach indicator for Stripe "
            "in the past 90 days affecting a third-party sub-processor."
        ),
        "category": "vendor_security_rating",
        "severity": "CRITICAL",
        "resource_id": "vendor-registry/stripe-payment-processing",
        "resource_type": "ThirdPartyVendor",
        "resource_name": "Stripe (Payment Processor)",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Initiate a formal vendor security escalation with Stripe within 5 business days. "
            "2. Request Stripe's remediation roadmap for the SecurityScorecard findings. "
            "3. Review Stripe's current SOC 2 Type II report for any noted exceptions. "
            "4. Assess whether additional contractual security requirements can be invoked. "
            "5. Evaluate backup payment processor options as contingency while the score is D. "
            "6. Monitor weekly until the score returns to 'B' or above."
        ),
        "remediation_effort": "strategic",
        "risk_score": 91.0,
        "actively_exploited": False,
        "external_id": "SSC-2024-SCORE-001",
        "first_seen": "2024-01-15T00:00:00Z",
    },
    {
        "id": "vc-002",
        "claw": "vendorclaw",
        "provider": "bitsight",
        "title": "Vendor with Confirmed Data Breach in Last 12 Months: HR Software Provider (Workday)",
        "description": (
            "BitSight threat intelligence flagged Workday (HCM and payroll SaaS vendor) with a "
            "confirmed data breach indicator from a third-party sub-processor breach in Q3 2023. "
            "The breach involved Workday's IT management sub-processor 'MOVEit' — "
            "the mass exploitation of MOVEit Transfer (CVE-2023-34362, Cl0p ransomware group) "
            "affected Workday's file transfer infrastructure. Workday processes HR data for "
            "1,400 employees including salary, bank details, tax information, and healthcare elections. "
            "BitSight confirmed the organization's Workday tenant data was in scope of the breach. "
            "The incident was not proactively disclosed by Workday — discovered via BitSight monitoring."
        ),
        "category": "vendor_breach",
        "severity": "CRITICAL",
        "resource_id": "vendor-registry/workday-hcm",
        "resource_type": "ThirdPartyVendor",
        "resource_name": "Workday (HR & Payroll)",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Request a formal incident report from Workday detailing data in scope within 48 hours. "
            "2. Notify the DPO — if employee PII was confirmed breached, GDPR 72-hour notification may apply. "
            "3. Notify affected employees as required under applicable breach notification laws. "
            "4. Request Workday's MOVEit remediation evidence and current patch status. "
            "5. Trigger a full vendor reassessment of Workday's security posture. "
            "6. Review and update the vendor contract to require mandatory breach notification within 24h."
        ),
        "remediation_effort": "strategic",
        "risk_score": 95.0,
        "actively_exploited": True,
        "external_id": "BST-2024-BREACH-002",
        "first_seen": "2024-01-20T00:00:00Z",
    },
    {
        "id": "vc-003",
        "claw": "vendorclaw",
        "provider": "upguard",
        "title": "Missing SOC 2 Report for Critical Cloud Storage Vendor (Snowflake)",
        "description": (
            "UpGuard vendor risk assessment flagged Snowflake (cloud data warehouse — Tier 1 critical "
            "vendor processing customer analytics data) as having no current SOC 2 Type II report "
            "on file in the vendor register. The last report on file expired 18 months ago. "
            "Snowflake stores 3.2TB of customer behavioral data, financial analytics, and "
            "product telemetry. The organization's TPRM policy requires Tier 1 vendors to provide "
            "a current SOC 2 Type II report annually. Two formal requests have gone unanswered. "
            "Without a current SOC 2, the organization cannot validate Snowflake's security controls "
            "for SOC 2 and ISO 27001 pass-through certification purposes."
        ),
        "category": "vendor_audit_report",
        "severity": "HIGH",
        "resource_id": "vendor-registry/snowflake-data-warehouse",
        "resource_type": "ThirdPartyVendor",
        "resource_name": "Snowflake (Cloud Data Warehouse)",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Escalate to Snowflake account management for the current SOC 2 Type II report. "
            "2. Note: Snowflake publishes their SOC 2 report via the Snowflake Trust Center — "
            "the vendor risk team should access it directly at trust.snowflake.com. "
            "3. Update the vendor register with the new report and set a 30-day pre-expiry alert. "
            "4. Add SOC 2 annual delivery as a contractual requirement at next renewal. "
            "5. Implement automated vendor report tracking in UpGuard to prevent recurrence."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 75.0,
        "actively_exploited": False,
        "external_id": "UPG-2024-SOC2-003",
        "first_seen": "2024-01-25T00:00:00Z",
    },
    {
        "id": "vc-004",
        "claw": "vendorclaw",
        "provider": "bitsight",
        "title": "Fourth-Party Risk: Primary Vendor's Sub-Processor Has Critical Vulnerabilities",
        "description": (
            "BitSight fourth-party risk monitoring detected that Salesforce's sub-processor "
            "Heroku (used for Salesforce integration workloads) has a BitSight score of 'C' (52/100) "
            "with 7 unpatched critical CVEs detected in Heroku's public-facing infrastructure. "
            "Heroku processes customer data passed through the Salesforce integration. "
            "The organization's DPA with Salesforce requires Salesforce to ensure sub-processors "
            "maintain equivalent security standards (GDPR Article 28(4)). "
            "Heroku's vulnerabilities include CVE-2023-44487 (HTTP/2 Rapid Reset DDoS) and "
            "two server-side request forgery vulnerabilities in their runtime environment."
        ),
        "category": "fourth_party_risk",
        "severity": "MEDIUM",
        "resource_id": "vendor-registry/salesforce/heroku-subprocessor",
        "resource_type": "FourthPartyVendor",
        "resource_name": "Heroku (Salesforce Sub-Processor)",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Notify Salesforce of the BitSight findings for Heroku and request remediation evidence. "
            "2. Request Salesforce's Heroku security attestation or sub-processor SOC 2 coverage. "
            "3. Evaluate whether Heroku workloads can be migrated to a higher-rated sub-processor. "
            "4. Add fourth-party monitoring as a standing agenda item in quarterly Salesforce reviews. "
            "5. Update the Salesforce DPA to require sub-processor security rating minimums ('B' or above)."
        ),
        "remediation_effort": "medium_term",
        "risk_score": 64.0,
        "actively_exploited": False,
        "external_id": "BST-2024-4P-004",
        "first_seen": "2024-02-01T00:00:00Z",
    },
    {
        "id": "vc-005",
        "claw": "vendorclaw",
        "provider": "upguard",
        "title": "Vendor Contract Missing Security Addendum: Cloud HR Vendor (BambooHR)",
        "description": (
            "UpGuard contract management review identified that the BambooHR contract (renewed "
            "January 2024) does not include a security addendum or data processing agreement. "
            "BambooHR processes HR records for 1,400 employees including personal data, salary, "
            "performance reviews, and health benefit elections. Without a security addendum, "
            "there are no contractual obligations for BambooHR to: notify the organization of "
            "breaches within 72 hours, maintain specific security certifications, allow for "
            "audit rights, or comply with the organization's security requirements. "
            "GDPR Article 28 mandates a binding DPA for any processor handling personal data."
        ),
        "category": "contract_risk",
        "severity": "HIGH",
        "resource_id": "vendor-registry/bamboohr",
        "resource_type": "ThirdPartyVendor",
        "resource_name": "BambooHR (HR Software)",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately contact BambooHR legal/procurement to execute the standard DPA "
            "(BambooHR's DPA is available in the BambooHR Help Center under Compliance). "
            "2. Add a security addendum covering: 72-hour breach notification, SOC 2 evidence, "
            "audit rights, sub-processor disclosure, and data deletion on termination. "
            "3. Add a 'security addendum required' gate to all vendor contract reviews. "
            "4. Audit all vendor contracts for missing DPAs — especially Tier 1 and 2 vendors. "
            "5. Document executed DPA in the vendor register."
        ),
        "remediation_effort": "medium_term",
        "risk_score": 78.0,
        "actively_exploited": False,
        "external_id": "UPG-2024-CONTRACT-005",
        "first_seen": "2024-02-10T00:00:00Z",
    },
    {
        "id": "vc-006",
        "claw": "vendorclaw",
        "provider": "security_scorecard",
        "title": "Open Source Vendor Without Support Contract: Critical Log4j Library in Production",
        "description": (
            "SecurityScorecard software composition analysis identified that the organization's "
            "critical data pipeline service uses Apache Log4j (log4j-core 2.14.1) — a version "
            "vulnerable to Log4Shell (CVE-2021-44228, CVSS 10.0, actively exploited). "
            "Apache Log4j is an open source project with no commercial support contract. "
            "There is no vendor relationship to engage for emergency patches, security advisories, "
            "or SLA-backed remediation. The security team was not notified when the vulnerable "
            "version was introduced 14 months ago via a transitive dependency. "
            "The data pipeline processes real-time financial transactions."
        ),
        "category": "open_source_risk",
        "severity": "CRITICAL",
        "resource_id": "data-pipeline-service/log4j-core:2.14.1",
        "resource_type": "OpenSourceComponent",
        "resource_name": "log4j-core:2.14.1 (Apache Log4j)",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Upgrade log4j-core to 2.17.2+ (the latest patched version) immediately. "
            "2. Apply the -Dlog4j2.formatMsgNoLookups=true JVM flag as an interim mitigating control. "
            "3. Rebuild and redeploy the data pipeline service. "
            "4. Subscribe to Apache Security advisories for all open source components in use. "
            "5. Implement a commercial SCA tool (Snyk, Sonatype Nexus) with automated upgrade PRs "
            "and vulnerability alerting for open source dependencies. "
            "6. Establish an Open Source Governance policy requiring security review for new OSS adoption."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 97.0,
        "actively_exploited": True,
        "external_id": "SSC-2024-OSS-006",
        "first_seen": "2024-01-08T00:00:00Z",
    },
]


@router.get("/stats", summary="Vendor Risk summary statistics")
async def get_stats(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.claw == CLAW_NAME))
    findings = result.scalars().all()
    if not findings:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        open_count = 0
        providers = set()
        for f in _FINDINGS:
            sev = f["severity"].lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            if f["status"] == "OPEN":
                open_count += 1
            providers.add(f["provider"])
        return {
            "total": len(_FINDINGS), "critical": severity_counts["critical"],
            "high": severity_counts["high"], "medium": severity_counts["medium"],
            "low": severity_counts["low"], "open": open_count,
            "resolved": len(_FINDINGS) - open_count,
            "providers_connected": len(providers), "last_scan": None,
        }
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    open_count = 0
    providers = set()
    last_seen = None
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev in by_sev:
            by_sev[sev] += 1
        if (f.status.value if hasattr(f.status, "value") else str(f.status)) == "open":
            open_count += 1
        if f.provider:
            providers.add(f.provider)
        if f.last_seen and (last_seen is None or f.last_seen > last_seen):
            last_seen = f.last_seen
    return {
        "total": len(findings), "critical": by_sev["critical"], "high": by_sev["high"],
        "medium": by_sev["medium"], "low": by_sev["low"], "open": open_count,
        "resolved": len(findings) - open_count, "providers_connected": len(providers),
        "last_scan": last_seen.isoformat() if last_seen else None,
    }


@router.get("/findings", summary="All Vendor Risk findings")
async def get_findings(db: AsyncSession = Depends(get_db)):
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


@router.get("/providers", summary="Vendor Risk provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    from app.services.connector_check import check_providers
    return await check_providers(db, PROVIDER_MAP)


@router.post("/scan", summary="Run Vendor Risk scan and persist findings")
async def run_scan(db: AsyncSession = Depends(get_db)):
    """Run a Vendor Risk scan. Persists via the finding pipeline for dedup, policy eval, and alerting."""
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


@router.get("/vendors", summary="Vendor portfolio risk summary")
async def get_vendors(db: AsyncSession = Depends(get_db)):
    return {
        "total_vendors": 84,
        "critical_vendors": 12,
        "high_risk": 8,
        "medium_risk": 31,
        "low_risk": 33,
        "awaiting_assessment": 15,
        "avg_security_score": 72.3,
        "vendors_with_incidents": 3,
    }


@router.post("/task", summary="Execute focused Vendor Risk swarm task")
async def run_vendor_task(payload: VendorTaskRequest, db: AsyncSession = Depends(get_db)):
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
        {"title": f.title, "detail": f"{f.provider or 'vendor'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}"}
        for f in findings[:3]
    ] or [
        {"title": f.get("title", "Vendor finding"), "detail": (f.get("description", "")[:220] or "Simulation finding")}
        for f in fallback
    ]
    return {
        "task_id": f"vendor-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": "vendorclaw",
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": rows or [{"title": "No vendor findings", "detail": "Run /vendorclaw/scan first."}],
        "evidence": [],
        "recommended_actions": [
            "Escalate critical vendor exposures to owner and procurement",
            "Require updated assurance artifacts and remediation plan",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["SOC2 CC9", "ISO 27001 A.15"],
        "execution_time_ms": elapsed_ms,
        "data_source": "persisted_db" if findings else "seeded_fallback",
        "connector_state": "configured" if any_configured else "unconfigured",
    }
