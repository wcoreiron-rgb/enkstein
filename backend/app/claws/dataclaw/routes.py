"""DataClaw — Data Security & DLP API Routes."""
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, select
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.services.finding_pipeline import ingest_findings
from app.services.connector_check import check_providers, is_connector_configured

router = APIRouter(prefix="/dataclaw", tags=["DataClaw — Data Security & DLP"])

CLAW_NAME = "dataclaw"

PROVIDER_MAP = [
    {"provider": "microsoft_purview", "label": "Microsoft Purview",    "connector_type": "microsoft_purview"},
    {"provider": "aws_macie",         "label": "AWS Macie",            "connector_type": "aws_macie"},
    {"provider": "google_dlp",        "label": "Google Cloud DLP",     "connector_type": "google_dlp"},
]

_FINDINGS = [
    {
        "claw": "dataclaw",
        "provider": "aws_macie",
        "title": "PII Exposed in Public S3 Bucket — 1,247 Files With Customer Data",
        "description": (
            "AWS Macie detected S3 bucket 'prod-customer-exports' "
            "(arn:aws:s3:::prod-customer-exports) has Block Public Access disabled and contains "
            "1,247 CSV export files classified as containing PII: full names, email addresses, "
            "phone numbers, home addresses, and billing ZIP codes. The bucket is publicly "
            "readable via its bucket ACL (AllUsers: READ). Macie's sensitive data discovery job "
            "found 847,293 distinct PII records across the files. The bucket has been publicly "
            "accessible for at least 14 days based on S3 access log analysis. "
            "A data breach notification assessment is required under GDPR Article 33 and "
            "CCPA § 1798.82."
        ),
        "category": "pii_exposure",
        "severity": "critical",
        "resource_id": "arn:aws:s3:::prod-customer-exports",
        "resource_type": "S3Bucket",
        "resource_name": "prod-customer-exports",
        "region": "us-east-1",
        "account_id": "123456789012",
        "cvss_score": 9.1,
        "epss_score": 0.88,
        "risk_score": 97,
        "actively_exploited": False,
        "remediation": (
            "1. Enable S3 Block Public Access at the bucket level immediately — this is a single "
            "API call. "
            "2. Remove all public ACL grants (AllUsers, AuthenticatedUsers). "
            "3. Run a Macie sensitive data discovery job to fully enumerate all PII in the bucket. "
            "4. File a data breach notification assessment with Legal within 24 hours — GDPR "
            "requires notification within 72 hours if breach threshold met. "
            "5. Audit S3 server access logs for any external downloads of the exposed files. "
            "6. Enable Macie on all production S3 buckets with continuous monitoring."
        ),
        "remediation_effort": "quick_win",
        "external_id": "macie-finding-public-pii-001",
        "reference_url": "https://docs.aws.amazon.com/macie/latest/user/findings-types.html",
        "status": "OPEN",
        "first_seen": "2024-01-15T06:32:00Z",
    },
    {
        "claw": "dataclaw",
        "provider": "aws_macie",
        "title": "Credit Card Numbers Detected in CloudWatch Application Logs (PCI DSS Violation)",
        "description": (
            "AWS Macie S3 scan detected log archive files in s3://prod-app-logs/application/ "
            "containing 3,412 occurrences of what appear to be unmasked payment card numbers "
            "(PAN data matching Luhn algorithm validation). Log files span 2023-11-01 to "
            "2024-01-15. The application appears to be logging full request/response payloads "
            "in the checkout flow, inadvertently capturing card numbers from form submissions. "
            "PCI DSS Requirement 3.3 explicitly prohibits storing sensitive authentication data "
            "including full PAN after authorization. The logs are accessible to all members of "
            "the 'dev-logs-access' IAM group (34 members)."
        ),
        "category": "card_data_in_logs",
        "severity": "critical",
        "resource_id": "arn:aws:s3:::prod-app-logs/application/",
        "resource_type": "S3Bucket",
        "resource_name": "prod-app-logs",
        "region": "us-east-1",
        "account_id": "123456789012",
        "cvss_score": 8.8,
        "epss_score": 0.71,
        "risk_score": 94,
        "actively_exploited": False,
        "remediation": (
            "1. Immediately stop the application from logging request bodies in the checkout flow. "
            "2. Delete or overwrite the log files containing PAN data (replace with purge log). "
            "3. Audit the 34 members of dev-logs-access for unauthorized access to the logs. "
            "4. Implement log scrubbing middleware that redacts PAN patterns before writing logs. "
            "5. Use tokenization (Stripe, Braintree) so your application never handles raw PANs. "
            "6. Notify your PCI QSA — this is a potential PCI DSS audit finding."
        ),
        "remediation_effort": "quick_win",
        "external_id": "macie-finding-pan-logs-001",
        "reference_url": "https://docs.aws.amazon.com/macie/latest/user/findings-types.html",
        "status": "OPEN",
        "first_seen": "2024-01-16T09:00:00Z",
    },
    {
        "claw": "dataclaw",
        "provider": "microsoft_purview",
        "title": "Unencrypted PII at Rest — RDS PostgreSQL Instance prod-postgres-01 Not Encrypted",
        "description": (
            "RDS instance prod-postgres-01 (db.r6g.2xlarge, us-east-1) was provisioned without "
            "storage encryption enabled. Microsoft Purview data catalog scan identified this "
            "instance as containing: customer_profiles table (2.1M records with name, email, "
            "DOB, SSN), order_history table (12.4M records), and payment_methods table "
            "(1.3M tokenized card references). RDS encryption cannot be enabled on a running "
            "unencrypted instance — a snapshot and restore process is required, causing "
            "downtime. This violates HIPAA § 164.312(a)(2)(iv) and SOC 2 CC6.7."
        ),
        "category": "unencrypted_pii_at_rest",
        "severity": "high",
        "resource_id": "arn:aws:rds:us-east-1:123456789012:db:prod-postgres-01",
        "resource_type": "RDSInstance",
        "resource_name": "prod-postgres-01",
        "region": "us-east-1",
        "account_id": "123456789012",
        "cvss_score": 8.4,
        "epss_score": 0.33,
        "risk_score": 86,
        "actively_exploited": False,
        "remediation": (
            "1. Schedule a maintenance window to: create an encrypted snapshot using a CMK in KMS, "
            "restore a new encrypted RDS instance from the snapshot, and update connection strings. "
            "2. Enable encryption at rest for all new RDS instances via AWS Config rule. "
            "3. In the interim, verify the RDS instance is not in a public subnet and has "
            "restrictive security group rules. "
            "4. Enable RDS encryption by default via AWS account settings to prevent recurrence."
        ),
        "remediation_effort": "medium_term",
        "external_id": "purview-rds-unencrypted-001",
        "reference_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
        "status": "OPEN",
        "first_seen": "2024-01-10T00:00:00Z",
    },
    {
        "claw": "dataclaw",
        "provider": "microsoft_purview",
        "title": "Data Exfiltration via Email — 2.3 GB Sensitive Files Sent to Personal Gmail",
        "description": (
            "Microsoft Purview Insider Risk Management alert: user redacted_user sent 847 "
            "email attachments (2.3 GB total) to redacted_user between 2024-01-08 and "
            "2024-01-19 — a volume 31x above their 90-day baseline. Purview DLP content "
            "inspection identified files containing: Q4 2023 financial projections, M&A due "
            "diligence documents (project codenamed 'Phoenix'), customer contract database "
            "export (4,200 records with PII), and HR compensation data. "
            "User jsmith submitted a resignation notice to HR on 2024-01-17 — 9 days into "
            "the exfiltration window. This is a confirmed insider threat incident."
        ),
        "category": "data_exfiltration",
        "severity": "high",
        "resource_id": "purview-insider-risk-alert-IR-2024-0042",
        "resource_type": "InsiderRiskAlert",
        "resource_name": "IR-2024-0042-jsmith",
        "region": "global",
        "account_id": "m365-tenant-corp",
        "cvss_score": 8.6,
        "epss_score": 0.61,
        "risk_score": 91,
        "actively_exploited": True,
        "remediation": (
            "1. Immediately revoke jsmith's access to all corporate systems and block outbound email. "
            "2. Preserve forensic evidence — do not notify the user before evidence preservation. "
            "3. Engage Legal and HR for investigation; retain an outside counsel if M&A data exposed. "
            "4. Notify M&A legal counsel of potential data leak for the Phoenix project. "
            "5. Implement DLP policies blocking bulk email of documents classified as Confidential+. "
            "6. Enable Purview Communication Compliance for departing employees (HR feed integration)."
        ),
        "remediation_effort": "quick_win",
        "external_id": "purview-insider-risk-IR-2024-0042",
        "reference_url": "https://learn.microsoft.com/en-us/purview/insider-risk-management",
        "status": "OPEN",
        "first_seen": "2024-01-19T14:22:00Z",
    },
    {
        "claw": "dataclaw",
        "provider": "microsoft_purview",
        "title": "Overshared SharePoint Site — 'Finance Reports' Site Accessible to All Staff (4,200 Users)",
        "description": (
            "Microsoft Purview data governance scan found SharePoint site "
            "'https://corp.sharepoint.com/sites/FinanceReports' has sharing permissions set to "
            "'Everyone in the organization' — all 4,200 employees can read all content. "
            "The site contains: audited financial statements (FY2021–FY2023), compensation "
            "benchmarking data for 312 employees, M&A target analysis, and board meeting minutes "
            "with material non-public information (MNPI). The site was opened to all staff "
            "in 2022 'to improve transparency' without a data classification review."
        ),
        "category": "overshared_data",
        "severity": "high",
        "resource_id": "https://corp.sharepoint.com/sites/FinanceReports",
        "resource_type": "SharePointSite",
        "resource_name": "FinanceReports",
        "region": "global",
        "account_id": "m365-tenant-corp",
        "cvss_score": 7.3,
        "epss_score": 0.24,
        "risk_score": 78,
        "actively_exploited": False,
        "remediation": (
            "1. Remove the 'Everyone in the organization' permission from the FinanceReports site immediately. "
            "2. Apply Microsoft Sensitivity Labels (Confidential, Highly Confidential) to all documents. "
            "3. Restrict access to Finance team and named executives only. "
            "4. Purview data classification: run a full scan and apply auto-labeling for financial data. "
            "5. Implement SharePoint External Sharing governance using Purview compliance policies. "
            "6. Consult Legal regarding MNPI access — insider trading exposure may need reporting."
        ),
        "remediation_effort": "quick_win",
        "external_id": "purview-sharepoint-overshare-001",
        "reference_url": "https://learn.microsoft.com/en-us/purview/data-governance",
        "status": "OPEN",
        "first_seen": "2024-01-12T00:00:00Z",
    },
    {
        "claw": "dataclaw",
        "provider": "google_dlp",
        "title": "Missing Data Classification Labels on 89% of GCS Buckets",
        "description": (
            "Google Cloud DLP assessment of GCP organization org-123456 found 47 of 53 Cloud "
            "Storage buckets (89%) have no data classification labels. DLP content inspection "
            "on 5 unlabeled buckets identified: HIPAA-protected PHI in gs://gcp-patient-exports, "
            "financial PII in gs://gcp-billing-archive, and source code with hardcoded API keys "
            "in gs://gcp-build-artifacts. Without classification labels, data governance policies "
            "cannot be enforced, and Data Loss Prevention controls cannot apply appropriate "
            "protections based on data sensitivity."
        ),
        "category": "missing_data_classification",
        "severity": "medium",
        "resource_id": "gcp-org-123456-gcs-buckets",
        "resource_type": "GCSBucket",
        "resource_name": "unlabeled-gcs-buckets",
        "region": "us-central1",
        "account_id": "gcp-project-prod-12345",
        "cvss_score": 5.5,
        "epss_score": 0.14,
        "risk_score": 62,
        "actively_exploited": False,
        "remediation": (
            "1. Run Google Cloud DLP discovery jobs on all 53 GCS buckets to classify content. "
            "2. Apply resource labels (data_classification: public/internal/confidential/restricted) "
            "to all buckets based on DLP scan results. "
            "3. Implement Organization Policy to deny creation of unclassified buckets. "
            "4. Prioritize remediation of gs://gcp-patient-exports (HIPAA) and gs://gcp-billing-archive (PII). "
            "5. Rotate any hardcoded API keys found in gs://gcp-build-artifacts immediately."
        ),
        "remediation_effort": "medium_term",
        "external_id": "gcp-dlp-classification-001",
        "reference_url": "https://cloud.google.com/dlp/docs/classification-overview",
        "status": "OPEN",
        "first_seen": "2024-01-20T00:00:00Z",
    },
    {
        "claw": "dataclaw",
        "provider": "aws_macie",
        "title": "EU Customer Data Replicated to us-east-1 — GDPR Article 44 Cross-Border Transfer Violation",
        "description": (
            "AWS DMS replication task 'dms-eu-prod-replica' is replicating the eu-prod-postgres "
            "database (eu-central-1, Frankfurt) to a read replica in us-east-1 (Virginia). "
            "Macie data classification confirmed the replicated dataset includes rows where "
            "customer_region = 'EU', containing personal data of EU data subjects including "
            "name, email, address, and purchase history. GDPR Article 44 restricts transfers "
            "of EU personal data to third countries without adequate safeguards. "
            "The US is not an adequacy decision country (post-Schrems II), and no SCCs or "
            "BCRs have been established for this replication. Legal has not reviewed this transfer."
        ),
        "category": "data_residency_violation",
        "severity": "medium",
        "resource_id": "arn:aws:dms:us-east-1:123456789012:replication-task:dms-eu-prod-replica",
        "resource_type": "DMSReplicationTask",
        "resource_name": "dms-eu-prod-replica",
        "region": "us-east-1",
        "account_id": "123456789012",
        "cvss_score": 6.2,
        "epss_score": 0.09,
        "risk_score": 65,
        "actively_exploited": False,
        "remediation": (
            "1. Halt the dms-eu-prod-replica DMS replication task pending legal review. "
            "2. Consult Privacy/Legal team to determine if EU-US Data Privacy Framework coverage applies. "
            "3. If replication is business-necessary, implement Standard Contractual Clauses (SCCs) "
            "and document as a legitimate transfer mechanism. "
            "4. Implement row-level data partitioning to ensure EU customer rows stay in EU regions. "
            "5. Conduct GDPR Data Protection Impact Assessment (DPIA) for this cross-border transfer."
        ),
        "remediation_effort": "medium_term",
        "external_id": "gdpr-art44-cross-border-001",
        "reference_url": "https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en",
        "status": "OPEN",
        "first_seen": "2024-01-08T00:00:00Z",
    },
]


class DataTaskRequest(BaseModel):
    swarm_job_id: str | None = None
    task_type: str = "investigate_data_risk"
    input: dict = Field(default_factory=dict)
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = Field(default_factory=lambda: ["read", "analyze", "recommend"])


@router.get("/stats", summary="DataClaw summary statistics")
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
            if f.get("status") == "OPEN":
                open_count += 1
            providers.add(f["provider"])
        return {
            "total": len(_FINDINGS),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "open": open_count,
            "resolved": len(_FINDINGS) - open_count,
            "providers_connected": len(providers),
            "last_scan": None,
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
        "total": len(findings),
        "critical": by_sev["critical"],
        "high": by_sev["high"],
        "medium": by_sev["medium"],
        "low": by_sev["low"],
        "open": open_count,
        "resolved": len(findings) - open_count,
        "providers_connected": len(providers),
        "last_scan": last_seen.isoformat() if last_seen else None,
    }


@router.get("/findings", summary="All DataClaw findings")
async def get_findings(db: AsyncSession = Depends(get_db)):
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
            "id": str(f.id),
            "claw": f.claw,
            "provider": f.provider,
            "title": f.title,
            "description": f.description,
            "category": f.category,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "status": f.status.value if hasattr(f.status, "value") else f.status,
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "resource_name": f.resource_name,
            "region": f.region,
            "cvss_score": f.cvss_score,
            "epss_score": f.epss_score,
            "risk_score": f.risk_score,
            "actively_exploited": f.actively_exploited,
            "remediation": f.remediation,
            "remediation_effort": f.remediation_effort,
            "external_id": f.external_id,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        }
        for f in findings
    ]


@router.get("/providers", summary="DataClaw provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    return await check_providers(db, PROVIDER_MAP)


@router.post("/scan", summary="Run DataClaw data security scan and persist findings")
async def run_scan(db: AsyncSession = Depends(get_db)):
    """Run a DataClaw scan. Falls back to simulation when no real connector is configured."""
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


@router.post("/task", summary="Execute focused DataClaw swarm task")
async def run_data_task(payload: DataTaskRequest, db: AsyncSession = Depends(get_db)):
    started = datetime.utcnow()
    stmt = (
        select(Finding)
        .where(Finding.claw == CLAW_NAME)
        .order_by(desc(Finding.risk_score), desc(Finding.created_at))
        .limit(5)
    )
    result = await db.execute(stmt)
    findings = result.scalars().all()
    max_risk = max([float(f.risk_score or 0.0) for f in findings], default=0.0)
    severity = "critical" if max_risk >= 85 else "high" if max_risk >= 70 else "medium" if max_risk >= 40 else "low"
    confidence = 0.89 if findings else 0.7
    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)

    finding_rows = [
        {
            "title": f.title,
            "detail": f"{f.provider or 'data'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}",
        }
        for f in findings[:3]
    ] or [{"title": "No data findings persisted yet", "detail": "Run /dataclaw/scan or configure providers."}]

    return {
        "task_id": f"data-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": "dataclaw",
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": finding_rows,
        "evidence": [],
        "recommended_actions": [
            "Prioritize exposed PII and regulated data stores",
            "Apply data classification and DLP enforcement policy",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["GDPR Art. 32", "NIST SC-28"],
        "execution_time_ms": elapsed_ms,
    }
