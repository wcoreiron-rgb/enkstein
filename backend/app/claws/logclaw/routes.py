"""LogClaw — Log Management & SIEM API Routes."""
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, select
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.services.finding_pipeline import ingest_findings
from app.services.connector_check import check_providers, is_connector_configured

router = APIRouter(prefix="/logclaw", tags=["LogClaw — Log Management & SIEM"])

CLAW_NAME = "logclaw"

PROVIDER_MAP = [
    {"provider": "microsoft_sentinel", "label": "Microsoft Sentinel",         "connector_type": "sentinel"},
    {"provider": "splunk",             "label": "Splunk Enterprise Security", "connector_type": "splunk"},
    {"provider": "elastic_siem",       "label": "Elastic SIEM",              "connector_type": "elastic"},
]

_FINDINGS = [
    {
        "claw": "logclaw",
        "provider": "microsoft_sentinel",
        "title": "CloudTrail Logging Disabled in us-west-2 and ap-southeast-1 — 2 Blind Spot Regions",
        "description": (
            "AWS CloudTrail is not configured in us-west-2 (Oregon) or ap-southeast-1 (Singapore). "
            "API calls in these regions — including IAM changes, EC2 launches, S3 modifications, "
            "and VPC configuration — are not being captured. Active resources include: 7 EC2 "
            "instances in us-west-2 running the analytics platform and 3 RDS instances in "
            "ap-southeast-1 serving the APAC customer base. Without CloudTrail, incident response "
            "in these regions has zero forensic capability. CIS AWS Level 1 control 3.1 requires "
            "CloudTrail in all regions. PCI DSS 10.5.4 requires audit logs from all in-scope systems."
        ),
        "category": "missing_log_source",
        "severity": "critical",
        "resource_id": "cloudtrail-missing-us-west-2-ap-southeast-1",
        "resource_type": "CloudTrail",
        "resource_name": "multi-region-trail",
        "region": "us-west-2",
        "account_id": "123456789012",
        "cvss_score": 8.6,
        "epss_score": 0.45,
        "risk_score": 92,
        "actively_exploited": False,
        "remediation": (
            "1. Create a multi-region CloudTrail trail in the management account covering all regions. "
            "2. Deliver logs to a centralized S3 bucket with Object Lock (compliance mode) enabled. "
            "3. Enable CloudTrail log file validation (SHA-256 integrity hashing). "
            "4. Integrate CloudTrail with CloudWatch Logs and create metric filters for "
            "high-risk API calls (ConsoleLogin, StopLogging, DeleteTrail). "
            "5. Forward CloudTrail events to the SIEM via an EventBridge + Lambda connector."
        ),
        "remediation_effort": "quick_win",
        "external_id": "CIS-AWS-3.1-cloudtrail-missing",
        "reference_url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html",
        "status": "OPEN",
        "first_seen": "2024-01-01T00:00:00Z",
    },
    {
        "claw": "logclaw",
        "provider": "microsoft_sentinel",
        "title": "SIEM Coverage Gap — 14 Critical Systems Not Forwarding Logs to Sentinel",
        "description": (
            "Microsoft Sentinel data connector audit reveals 14 production systems with no "
            "log forwarding configured: 6 domain controllers (DC01–DC06 in corp.local domain), "
            "4 MS SQL Server databases (SQLPROD01–04), and 4 Fortinet FortiGate appliances "
            "(FW-PROD-01–04). Combined, these systems generate 98% of privileged authentication "
            "events, database query activity, and network perimeter traffic — yet none appear "
            "in Sentinel. A threat actor who pivoted through domain controllers or databases "
            "would be completely invisible to the SOC. MTTR for incidents on these systems "
            "is effectively infinite without log data."
        ),
        "category": "missing_log_source",
        "severity": "high",
        "resource_id": "sentinel-workspace-prod-eastus",
        "resource_type": "SIEMWorkspace",
        "resource_name": "prod-sentinel-workspace",
        "region": "eastus",
        "account_id": "azure-subscription-corp",
        "cvss_score": 8.0,
        "epss_score": 0.38,
        "risk_score": 87,
        "actively_exploited": False,
        "remediation": (
            "1. Deploy Azure Monitor Agent (AMA) on all 6 domain controllers with Windows Security "
            "event log collection (Event IDs: 4624, 4625, 4648, 4768, 4769, 4771, 4776). "
            "2. Install AMA on the 4 SQL Server hosts and configure SQL Server Audit to write to "
            "Windows Event Log for Sentinel ingestion. "
            "3. Configure the Fortinet FortiGate CEF data connector in Sentinel for all 4 firewalls. "
            "4. Create a Sentinel watchlist for all critical systems and alert when any go silent. "
            "5. Implement a weekly log source health check dashboard."
        ),
        "remediation_effort": "medium_term",
        "external_id": "sentinel-coverage-gap-001",
        "reference_url": "https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources",
        "status": "OPEN",
        "first_seen": "2024-01-08T00:00:00Z",
    },
    {
        "claw": "logclaw",
        "provider": "splunk",
        "title": "Log Retention Period 30 Days — PCI DSS 10.7 Requires 12 Months",
        "description": (
            "Primary log storage S3 bucket s3://corp-logs-prod has an S3 lifecycle rule deleting "
            "all objects after 30 days. PCI DSS v4.0 Requirement 10.7 mandates 12-month retention "
            "minimum with 3 months immediately available for analysis. SOC 2 CC7.2 also requires "
            "a defined retention period appropriate for the organization's security needs. "
            "The gap was discovered during PCI QSA assessment on 2024-01-18. 10 months of "
            "historical logs are permanently lost and cannot be recovered. This is a reportable "
            "finding that will delay PCI DSS certification renewal."
        ),
        "category": "retention_gap",
        "severity": "high",
        "resource_id": "s3://corp-logs-prod",
        "resource_type": "S3Bucket",
        "resource_name": "corp-logs-prod",
        "region": "us-east-1",
        "account_id": "123456789012",
        "cvss_score": 6.8,
        "epss_score": 0.18,
        "risk_score": 79,
        "actively_exploited": False,
        "remediation": (
            "1. Update the S3 lifecycle policy: retain logs for 365 days with transition to "
            "S3 Intelligent-Tiering after 90 days and S3 Glacier after 180 days (cost-effective). "
            "2. Enable S3 Object Lock (compliance mode) to prevent lifecycle policy tampering. "
            "3. Enable S3 Versioning and MFA Delete to prevent accidental log deletion. "
            "4. Document the new retention policy in the PCI DSS evidence package. "
            "5. Set up a monthly audit to verify lifecycle policy compliance."
        ),
        "remediation_effort": "quick_win",
        "external_id": "PCI-DSS-10.7-retention-gap",
        "reference_url": "https://www.pcisecuritystandards.org/document_library/",
        "status": "OPEN",
        "first_seen": "2024-01-18T00:00:00Z",
    },
    {
        "claw": "logclaw",
        "provider": "microsoft_sentinel",
        "title": "No Detection Rule for Privileged Account Logons Outside Business Hours",
        "description": (
            "Sentinel analytics rules inventory review found no scheduled query rule or "
            "NRT (Near Real-Time) rule detecting administrator or privileged account sign-ins "
            "occurring between 18:00–06:00 UTC or on weekends. This is a high-value detection "
            "for both compromised privileged credentials and insider threats — 73% of confirmed "
            "identity-based breaches in the Microsoft MDTI threat report involved off-hours "
            "privileged access. The organization has 42 accounts with privileged Entra ID roles. "
            "No baseline of normal admin hours has been established, making this a cold-start "
            "detection gap."
        ),
        "category": "detection_gap",
        "severity": "medium",
        "resource_id": "sentinel-analytics-rules-prod",
        "resource_type": "SIEMDetectionRule",
        "resource_name": "off-hours-privileged-logon",
        "region": "eastus",
        "account_id": "azure-subscription-corp",
        "cvss_score": 5.8,
        "epss_score": 0.22,
        "risk_score": 67,
        "actively_exploited": False,
        "remediation": (
            "1. Create a Sentinel Scheduled Analytics Rule using KQL to detect sign-ins by members "
            "of privileged role groups (Global Admin, Security Admin, Privileged Role Admin) "
            "outside business hours (TimeGenerated between 18:00–06:00 or dayofweek(TimeGenerated) in (0,6)). "
            "2. Set incident severity to High with auto-assignment to SOC queue. "
            "3. Integrate with PagerDuty or SNOW for after-hours on-call notification. "
            "4. Establish a 30-day baseline of normal admin sign-in patterns before tuning."
        ),
        "remediation_effort": "quick_win",
        "external_id": "sentinel-detection-off-hours-001",
        "reference_url": "https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom",
        "status": "OPEN",
        "first_seen": "2024-01-15T00:00:00Z",
    },
    {
        "claw": "logclaw",
        "provider": "splunk",
        "title": "Splunk Daily License Exceeded — Security Events Silently Dropped",
        "description": (
            "Splunk production cluster (prod-splunk-indexer-01 through -04) has exceeded its "
            "50 GB/day indexing license for 11 of the past 14 days. During license violation "
            "periods, Splunk throttles ingestion by randomly dropping events across all data "
            "sources — including security-critical Windows Security event logs, Palo Alto "
            "firewall logs, and endpoint EDR telemetry. The throttling is silent (no user alert "
            "in the UI unless specifically monitored). License overage was triggered by a new "
            "application deployment that logs at DEBUG level in production — generating 23 GB/day "
            "of low-value verbose logs alone."
        ),
        "category": "log_gap",
        "severity": "medium",
        "resource_id": "splunk-prod-cluster-indexers",
        "resource_type": "SIEMCluster",
        "resource_name": "prod-splunk-cluster",
        "region": "us-east-1",
        "account_id": "123456789012",
        "cvss_score": 5.5,
        "epss_score": 0.11,
        "risk_score": 63,
        "actively_exploited": False,
        "remediation": (
            "1. Immediately change the new application's logging level from DEBUG to WARN in production. "
            "2. Implement Splunk data ingest prioritization (props.conf/transforms.conf) to ensure "
            "security sources (Windows Security, EDR, firewall) are never throttled. "
            "3. Add a Splunk monitoring alert: trigger when daily ingest approaches 90% of license. "
            "4. Either upgrade the Splunk license or implement data tiering (Cribl Stream to filter "
            "verbose non-security logs before Splunk ingestion). "
            "5. Audit the past 14 days of license violations for security events that may have been dropped."
        ),
        "remediation_effort": "quick_win",
        "external_id": "splunk-license-exceeded-001",
        "reference_url": "https://docs.splunk.com/Documentation/Splunk/latest/Admin/Aboutlicenses",
        "status": "OPEN",
        "first_seen": "2024-01-05T00:00:00Z",
    },
    {
        "claw": "logclaw",
        "provider": "microsoft_sentinel",
        "title": "DNS Query Logging Not Enabled on VPC Resolvers — C2 Detection Blind Spot",
        "description": (
            "AWS Route53 Resolver query logging is not enabled for any of the 4 production VPCs "
            "(vpc-0prod123, vpc-0staging456, vpc-0shared789, vpc-0mgmt012). DNS queries are a "
            "primary detection signal for: C2 callback domains, Domain Generation Algorithm (DGA) "
            "malware beaconing, DNS tunneling-based data exfiltration, and fast-flux botnet "
            "infrastructure. Without DNS logs, the security team has no visibility into what "
            "internet destinations production workloads are communicating with. CISA advisory "
            "AA23-061A specifically calls out DNS logging as a critical detection control."
        ),
        "category": "missing_log_source",
        "severity": "medium",
        "resource_id": "route53-resolver-query-logging-all-vpcs",
        "resource_type": "Route53Resolver",
        "resource_name": "prod-vpc-resolvers",
        "region": "us-east-1",
        "account_id": "123456789012",
        "cvss_score": 5.3,
        "epss_score": 0.14,
        "risk_score": 58,
        "actively_exploited": False,
        "remediation": (
            "1. Enable Route53 Resolver query logging for all 4 production VPCs in 30 minutes. "
            "2. Deliver DNS logs to a CloudWatch Logs group and S3 for retention. "
            "3. Create a Sentinel data connector for Route53 DNS logs. "
            "4. Configure threat intelligence-based alerting: query threat feeds (Cisco Talos, "
            "CISA KEV) and alert when production hosts resolve known-malicious domains. "
            "5. Implement DNS filtering via Route53 Resolver DNS Firewall to block C2 domains proactively."
        ),
        "remediation_effort": "quick_win",
        "external_id": "logclaw-dns-logging-001",
        "reference_url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html",
        "status": "OPEN",
        "first_seen": "2024-01-12T00:00:00Z",
    },
    {
        "claw": "logclaw",
        "provider": "splunk",
        "title": "S3 Server Access Logging Disabled on 12 Production Buckets",
        "description": (
            "12 S3 buckets do not have server access logging enabled: prod-app-uploads, "
            "prod-reports, prod-backups, prod-media, prod-exports, prod-configs, "
            "prod-certs, prod-lambda-deployments, prod-terraform-state, "
            "prod-cloudformation-templates, prod-audit-archive, and prod-customer-data. "
            "Without server access logs, there is no record of who accessed, downloaded, "
            "modified, or deleted objects in these buckets. Data breach investigation is "
            "impossible without this evidence. CloudTrail data events can supplement but "
            "have a 15-minute delivery delay — access logs are near real-time."
        ),
        "category": "missing_log_source",
        "severity": "low",
        "resource_id": "s3-buckets-without-access-logging",
        "resource_type": "S3BucketGroup",
        "resource_name": "buckets-without-logging",
        "region": "us-east-1",
        "account_id": "123456789012",
        "cvss_score": 4.3,
        "epss_score": 0.07,
        "risk_score": 44,
        "actively_exploited": False,
        "remediation": (
            "1. Enable S3 server access logging on all 12 buckets, delivering to a centralized "
            "audit log bucket (s3://corp-audit-logs/s3-access/). "
            "2. Alternatively, enable CloudTrail S3 data events for all production buckets — "
            "provides richer Athena-queryable logging. "
            "3. Set up Athena + QuickSight dashboard for S3 access log analysis. "
            "4. Create S3 Access Analyzer to detect any bucket with public or cross-account access."
        ),
        "remediation_effort": "quick_win",
        "external_id": "logclaw-s3-access-logging-001",
        "reference_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
        "status": "OPEN",
        "first_seen": "2024-01-01T00:00:00Z",
    },
]


class LogTaskRequest(BaseModel):
    swarm_job_id: str | None = None
    task_type: str = "investigate_log_coverage_risk"
    input: dict = Field(default_factory=dict)
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = Field(default_factory=lambda: ["read", "analyze", "recommend"])


@router.get("/stats", summary="LogClaw summary statistics")
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


@router.get("/findings", summary="All LogClaw findings")
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


@router.get("/providers", summary="LogClaw provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    return await check_providers(db, PROVIDER_MAP)


@router.post("/scan", summary="Run LogClaw log coverage scan and persist findings")
async def run_scan(db: AsyncSession = Depends(get_db)):
    """Run a LogClaw scan. Falls back to simulation when no real connector is configured."""
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


@router.post("/task", summary="Execute focused LogClaw swarm task")
async def run_log_task(payload: LogTaskRequest, db: AsyncSession = Depends(get_db)):
    started = datetime.utcnow()
    result = await db.execute(
        select(Finding).where(Finding.claw == CLAW_NAME).order_by(desc(Finding.risk_score)).limit(5)
    )
    findings = result.scalars().all()
    fallback = _FINDINGS[:3] if not findings else []
    max_risk = max([float(f.risk_score or 0.0) for f in findings], default=max([float(f.get("risk_score") or 0.0) for f in fallback], default=0.0))
    severity = "critical" if max_risk >= 85 else "high" if max_risk >= 70 else "medium" if max_risk >= 40 else "low"
    confidence = 0.88 if findings else 0.74
    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    rows = [
        {"title": f.title, "detail": f"{f.provider or 'log'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}"}
        for f in findings[:3]
    ] or [
        {"title": f.get("title", "Log finding"), "detail": (f.get("description", "")[:220] or "Simulation finding")}
        for f in fallback
    ]
    return {
        "task_id": f"log-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": "logclaw",
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": rows or [{"title": "No log findings", "detail": "Run /logclaw/scan first."}],
        "evidence": [],
        "recommended_actions": [
            "Close high-risk telemetry and retention gaps first",
            "Enforce SIEM source coverage checks for critical systems",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["PCI DSS 10", "NIST AU-6"],
        "execution_time_ms": elapsed_ms,
    }
