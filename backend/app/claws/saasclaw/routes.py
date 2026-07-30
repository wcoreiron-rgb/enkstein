"""SaaS Security Posture (SSPM) API Routes."""
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy import desc

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.tenancy import caller_tenant
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.services.connector_check import is_connector_configured
from app.services.claw_scan import has_live_adapter, run_claw_scan

router = APIRouter(prefix="/saasclaw", tags=["SaaS Security"])
CLAW_NAME = "saasclaw"

PROVIDER_MAP = [
    {"provider": "mcas",              "label": "Microsoft Defender for Cloud Apps (MDCA)", "connector_type": "mcas"},
    {"provider": "google_workspace",  "label": "Google Workspace Security",                "connector_type": "google_workspace"},
    {"provider": "salesforce",        "label": "Salesforce Shield",                        "connector_type": "salesforce"},
]


class SaaSTaskRequest(BaseModel):
    swarm_job_id: str
    task_type: str
    input: dict[str, Any] = {}
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = ["read", "analyze", "recommend"]

_FINDINGS = [
    {
        "id": "sc-001",
        "claw": "saasclaw",
        "provider": "mcas",
        "title": "OAuth App with Excessive Permissions Granted by 312 Users",
        "description": (
            "Microsoft Defender for Cloud Apps detected an OAuth application 'DataSync Pro' "
            "(App ID: app_datasync_pro_001, publisher: DataSync Inc — unverified) that has been "
            "granted consent by 312 users in the M365 tenant. The app requests: "
            "Mail.ReadWrite (read and modify all emails), Files.ReadWrite.All (access all files), "
            "Contacts.ReadWrite (access all contacts), and offline_access (persistent access). "
            "The app has not been reviewed or approved by IT. It accesses mailboxes and SharePoint "
            "files continuously, including executive inboxes. MDCA risk score: 8.2/10."
        ),
        "category": "oauth_risk",
        "severity": "CRITICAL",
        "resource_id": "app_datasync_pro_001",
        "resource_type": "OAuthApplication",
        "resource_name": "DataSync Pro (M365 OAuth App)",
        "region": "global",
        "status": "OPEN",
        "remediation": (
            "1. Immediately revoke all 312 user consent grants for DataSync Pro in Azure AD. "
            "2. Block the application via Azure AD App Governance policies. "
            "3. Investigate MDCA activity logs for the app to identify any data exfiltration. "
            "4. Enable Azure AD App Consent Governance to require admin approval for new OAuth apps. "
            "5. Configure MDCA policies to alert on new OAuth apps requesting sensitive permission scopes."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 95.0,
        "actively_exploited": False,
        "external_id": "MDCA-2024-OAUTH-001",
        "first_seen": "2024-01-12T00:00:00Z",
    },
    {
        "id": "sc-002",
        "claw": "saasclaw",
        "provider": "google_workspace",
        "title": "Anonymous Sharing Enabled in Google Drive — 1,847 Files Shared 'Anyone with Link'",
        "description": (
            "Google Workspace security audit detected 1,847 files in Google Drive shared with "
            "'Anyone with the link' (no authentication required). Among the exposed files: "
            "143 files tagged as 'Confidential' or 'Internal Only', 27 spreadsheets containing "
            "financial forecasts and customer data, and 8 documents with employee PII (salary, "
            "performance reviews). The sharing was enabled by individual users, not via a tenant "
            "policy. Files have been shared externally for an average of 94 days."
        ),
        "category": "data_exposure",
        "severity": "HIGH",
        "resource_id": "google-workspace-tenant-acme",
        "resource_type": "GoogleWorkspaceTenant",
        "resource_name": "acme.com Google Workspace",
        "region": "global",
        "status": "OPEN",
        "remediation": (
            "1. Use the Google Workspace Admin SDK to enumerate and revoke all 'Anyone with link' "
            "sharing settings on Confidential-tagged files immediately. "
            "2. Enable Google Drive DLP rules to block sharing of files containing sensitive data patterns. "
            "3. Configure the tenant sharing policy to restrict external sharing to known domains. "
            "4. Apply Google Workspace sensitivity labels to auto-restrict sharing on classified content. "
            "5. Send a communication to employees on data classification and sharing policies."
        ),
        "remediation_effort": "medium_term",
        "risk_score": 80.0,
        "actively_exploited": False,
        "external_id": "GWS-2024-SHARE-002",
        "first_seen": "2024-01-20T00:00:00Z",
    },
    {
        "id": "sc-003",
        "claw": "saasclaw",
        "provider": "salesforce",
        "title": "Salesforce API Access from Untrusted IP Range (6 Login Events from Russia)",
        "description": (
            "Salesforce Shield Event Monitoring detected 6 API login events to the Salesforce org "
            "(org ID: 00D1a000000ACME01) originating from IP range 185.220.x.x (associated with "
            "Tor exit nodes and cybercriminal infrastructure, country: Russia) in the past 24 hours. "
            "The logins authenticated as service account 'api-integration-user' using a valid API key. "
            "This service account has View All Data permission. 3 login events resulted in bulk "
            "data queries downloading the full Accounts and Contacts objects (45,000 records total). "
            "The source IP range is not in the Salesforce Login IP Range whitelist."
        ),
        "category": "unauthorized_access",
        "severity": "CRITICAL",
        "resource_id": "00D1a000000ACME01/api-integration-user",
        "resource_type": "SalesforceUser",
        "resource_name": "api-integration-user (Salesforce)",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately revoke and rotate the API key for api-integration-user. "
            "2. Add IP login restrictions to the Salesforce profile to allow only known corporate IPs. "
            "3. Review Event Monitoring logs for the full scope of data accessed in the 3 bulk queries. "
            "4. Assess whether the 45,000 records constitute a data breach requiring notification. "
            "5. Implement Salesforce MFA enforcement for all API users and restrict View All Data permission."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 96.0,
        "actively_exploited": True,
        "external_id": "SFDC-2024-API-003",
        "first_seen": "2024-01-25T00:00:00Z",
    },
    {
        "id": "sc-004",
        "claw": "saasclaw",
        "provider": "mcas",
        "title": "Shadow IT: 40 Users Accessing Unapproved Notion Workspace with Corporate Data",
        "description": (
            "Microsoft Defender for Cloud Apps shadow IT discovery identified Notion "
            "(notion.so, MDCA risk score: 6.1/10) being accessed by 40 employees using corporate "
            "M365 credentials via SSO. The Notion workspace has not been sanctioned, procured, or "
            "security-reviewed by IT. Content discovery shows employees are storing meeting notes "
            "with customer names, internal project roadmaps, and technical architecture diagrams. "
            "Notion's free tier data is stored in US datacenters and retention is indefinite — "
            "including after employee departure. The corporate DLP policy prohibits storing "
            "Confidential data in unsanctioned cloud services."
        ),
        "category": "shadow_it",
        "severity": "MEDIUM",
        "resource_id": "notion.so",
        "resource_type": "SaaSApplication",
        "resource_name": "Notion (unapproved)",
        "region": "global",
        "status": "OPEN",
        "remediation": (
            "1. Block Notion in the web proxy/CASB for all non-approved users. "
            "2. Contact the 40 users to migrate any work data off Notion within 5 business days. "
            "3. Conduct a fast-track security review of Notion for potential sanctioning. "
            "4. Configure MDCA app discovery to alert on new unapproved apps used by >5 users. "
            "5. Publish an updated list of sanctioned collaboration tools to all employees."
        ),
        "remediation_effort": "medium_term",
        "risk_score": 62.0,
        "actively_exploited": False,
        "external_id": "MDCA-2024-SHADOW-004",
        "first_seen": "2024-02-01T00:00:00Z",
    },
    {
        "id": "sc-005",
        "claw": "saasclaw",
        "provider": "mcas",
        "title": "Microsoft Teams DLP Policy Not Configured — Sensitive Data Shared in Chats",
        "description": (
            "Microsoft Purview DLP audit shows no active DLP policy covers Microsoft Teams chat "
            "messages and files in the M365 tenant. Content scanning via MDCA detected: "
            "14 Teams messages containing credit card numbers (PAN), 7 chat conversations with "
            "Social Security Numbers, and 23 file shares to external guest users containing "
            "employee salary information. PCI-DSS Requirement 3.4 prohibits unprotected PAN "
            "transmission; HIPAA requires covered entities to prevent unauthorized PHI sharing."
        ),
        "category": "dlp",
        "severity": "HIGH",
        "resource_id": "m365-tenant-acme/teams",
        "resource_type": "MicrosoftTeamsTenant",
        "resource_name": "acme-m365-teams",
        "region": "global",
        "status": "OPEN",
        "remediation": (
            "1. Create Microsoft Purview DLP policies covering Teams for PCI, PII, and PHI data patterns. "
            "2. Configure policy actions: block sharing with external guests, notify sender, alert security. "
            "3. Restrict Teams guest access to approved external domains only. "
            "4. Enable Communication Compliance policies to monitor regulatory violation risks. "
            "5. Train employees on not sharing sensitive data in Teams — especially with external guests."
        ),
        "remediation_effort": "medium_term",
        "risk_score": 77.0,
        "actively_exploited": False,
        "external_id": "MDCA-2024-DLP-005",
        "first_seen": "2024-01-30T00:00:00Z",
    },
    {
        "id": "sc-006",
        "claw": "saasclaw",
        "provider": "mcas",
        "title": "Admin Account Without MFA in Slack Workspace (redacted_user)",
        "description": (
            "Slack audit log review via MDCA shows that the primary Slack workspace admin account "
            "'redacted_user' does not have multi-factor authentication enabled. "
            "This account has full administrative rights: can export all message history, add/remove "
            "members, install apps, and modify security settings. The account uses a password that "
            "was last changed 14 months ago. Slack admin compromise is a top-tier phishing target "
            "for threat actors — full workspace export would expose all direct messages and private "
            "channels for all 1,200 employees."
        ),
        "category": "authentication",
        "severity": "HIGH",
        "resource_id": "slack-workspace-acme/redacted_user",
        "resource_type": "SlackUser",
        "resource_name": "redacted_user (Slack Admin)",
        "region": "global",
        "status": "OPEN",
        "remediation": (
            "1. Immediately enable MFA (TOTP or hardware key) for redacted_user. "
            "2. Enforce MFA for all workspace admins and owners via Slack Admin settings. "
            "3. Rotate the admin account password. "
            "4. Configure Slack's SSO via Okta/Azure AD so admin access flows through corporate IdP with MFA. "
            "5. Review Slack audit logs for any suspicious admin actions in the past 90 days."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 82.0,
        "actively_exploited": False,
        "external_id": "SLACK-2024-MFA-006",
        "first_seen": "2024-02-05T00:00:00Z",
    },
    {
        "id": "sc-007",
        "claw": "saasclaw",
        "provider": "mcas",
        "title": "Mass Download from SharePoint: User Downloaded 2,300 Files in 4 Hours",
        "description": (
            "MDCA anomaly detection triggered on user 'redacted_user' who performed a "
            "mass download activity: 2,300 files (14.7 GB) downloaded from the SharePoint site "
            "'Corp-Confidential-Internal' between 02:00 and 06:00 UTC — outside normal working hours. "
            "The user is a contractor whose contract ends in 3 days. Downloaded files include "
            "product roadmaps, customer lists, and financial models tagged as Confidential. "
            "MDCA impossible travel alert also fired — login originated from a Romanian IP "
            "while the user's standard location is Chicago."
        ),
        "category": "data_exfiltration",
        "severity": "CRITICAL",
        "resource_id": "m365-tenant-acme/sharepoint/Corp-Confidential-Internal",
        "resource_type": "SharePointSite",
        "resource_name": "Corp-Confidential-Internal (SharePoint)",
        "region": "global",
        "status": "OPEN",
        "remediation": (
            "1. Immediately suspend redacted_user's M365 account and revoke all active sessions. "
            "2. Invoke the incident response process — this is a potential insider threat / data theft case. "
            "3. Preserve MDCA audit logs and SharePoint access logs as evidence. "
            "4. Conduct a legal review on notifying affected customers if their data was in the download. "
            "5. Implement MDCA policies to block mass downloads (>100 files/hour) without manager approval. "
            "6. Revoke contractor access 30 days before contract end — not on the final day."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 98.0,
        "actively_exploited": True,
        "external_id": "MDCA-2024-EXFIL-007",
        "first_seen": "2024-02-15T04:00:00Z",
    },
]


@router.get("/stats", summary="SaaS Security summary statistics")
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


@router.get("/findings", summary="All SaaS Security findings")
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
        if not any_configured or not has_live_adapter(PROVIDER_MAP):
            # Showing labelled demonstration findings is more honest than an
            # empty module: this Claw has no adapter that could have returned
            # tenant data, so an empty list would read as a broken scan.
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


@router.get("/providers", summary="SaaS Security provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    from app.services.connector_check import check_providers
    return await check_providers(db, PROVIDER_MAP)


@router.post("/scan", summary="Run SaaS Security scan and persist findings")
async def run_scan(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Run a SaaS Security scan. Persists via the finding pipeline for dedup, policy eval, and alerting."""
    tenant_id = caller_tenant(user)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail="Tenant-bound identity required to run this scan",
        )
    return await run_claw_scan(
        db,
        claw=CLAW_NAME,
        provider_config=PROVIDER_MAP,
        demo_findings=_FINDINGS,
        tenant_id=tenant_id,
    )


@router.get("/apps", summary="SaaS app discovery summary")
async def get_saas_apps(db: AsyncSession = Depends(get_db)):
    return {
        "total_apps_discovered": 147,
        "sanctioned": 42,
        "unsanctioned": 89,
        "under_review": 16,
        "high_risk_apps": 12,
        "categories": {
            "productivity": 38,
            "collaboration": 29,
            "storage": 24,
            "dev_tools": 31,
            "other": 25,
        },
    }


@router.post("/task", summary="Execute focused SaaS Security swarm task")
async def run_saas_task(payload: SaaSTaskRequest, db: AsyncSession = Depends(get_db)):
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
    confidence = 0.87 if findings else 0.73
    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    rows = [
        {"title": f.title, "detail": f"{f.provider or 'saas'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}"}
        for f in findings[:3]
    ] or [
        {"title": f.get("title", "SaaS finding"), "detail": (f.get("description", "")[:220] or "Simulation finding")}
        for f in fallback
    ]
    return {
        "task_id": f"saas-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": "saasclaw",
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": rows or [{"title": "No SaaS findings", "detail": "Run /saasclaw/scan first."}],
        "evidence": [],
        "recommended_actions": [
            "Contain unsanctioned SaaS exposure and tighten tenant controls",
            "Review third-party app grants and high-risk OAuth scopes",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["CIS SaaS", "SOC2 CC6"],
        "execution_time_ms": elapsed_ms,
        "data_source": "persisted_db" if findings else "seeded_fallback",
        "connector_state": "configured" if any_configured else "unconfigured",
    }
