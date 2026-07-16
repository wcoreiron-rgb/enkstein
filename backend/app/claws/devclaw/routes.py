"""DevSecOps & CI/CD Security API Routes."""
from datetime import datetime
import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, select
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.models.finding import Finding

router = APIRouter(prefix="/devclaw", tags=["Developer Security"])
logger = logging.getLogger("devclaw")
CLAW_NAME = "devclaw"


def _normalize_risk_score(value) -> float:
    try:
        score = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return round(score * 100, 2) if 0 < score <= 1 else round(score, 2)


PROVIDER_MAP = [
    {"provider": "github", "label": "GitHub",           "connector_type": "github"},
    {"provider": "aws",    "label": "AWS Security Hub / IAM", "connector_type": "aws_security_hub", "connector_types": ["aws_security_hub", "aws_iam"]},
]

_FINDINGS = [
    {
        "id": "dc-001",
        "claw": "devclaw",
        "provider": "github",
        "title": "AWS Secret Access Key Hardcoded in GitHub Repository (Committed 3 Days Ago)",
        "description": (
            "GitHub secret scanning detected an active AWS secret access key committed to the "
            "repository 'corp/payment-service' in file 'config/local.env' at commit sha a3f9c21 "
            "on January 13, 2024. The credential (AKIA...WXYZ format, confirmed active via AWS STS "
            "GetCallerIdentity) belongs to IAM user 'dev-build-automation' "
            "(arn:aws:iam::123456789012:user/dev-build-automation). "
            "The commit is on the 'main' branch and is visible to all 142 engineering org members. "
            "The key has been live for 72 hours. CloudTrail shows 23 API calls using this key in the "
            "past 24 hours from IP addresses not associated with corporate infrastructure."
        ),
        "category": "secret_exposure",
        "severity": "CRITICAL",
        "resource_id": "github-corp-payment-service-commit-a3f9c21",
        "resource_type": "GitRepository",
        "resource_name": "corp/payment-service",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Immediately deactivate the exposed AWS key via IAM console. "
            "2. Rotate and issue a new key — do NOT just delete the old one without revoking it. "
            "3. Investigate the 23 external API calls in CloudTrail for unauthorized activity. "
            "4. Remove the secret from git history using 'git filter-repo' (not just delete the file). "
            "5. Enable GitHub secret scanning with push protection to block future commits. "
            "6. Move all secrets to AWS Secrets Manager and reference via environment injection at runtime."
        ),
        "remediation_effort": "High",
        "risk_score": 0.99,
        "actively_exploited": True,
        "first_seen": "2024-01-13T10:45:00Z",
    },
    {
        "id": "dc-002",
        "claw": "devclaw",
        "provider": "github",
        "title": "SAST Scan Bypassed with --skip-checks Flag in Production Pipeline",
        "description": (
            "GitHub Actions workflow 'ci-security-scan.yml' was modified in PR #847 (merged Jan 14) "
            "to add '--skip-checks CWE-89,CWE-79,CWE-22' to the Semgrep SAST invocation. "
            "CWE-89 is SQL Injection, CWE-79 is Cross-Site Scripting, and CWE-22 is Path Traversal — "
            "three of the OWASP Top 10 most critical vulnerability classes. "
            "The PR was approved by a single reviewer (the same team as the author) without "
            "a security review. Since the merge, 3 additional commits have added code to the "
            "payment processing module that would have triggered these disabled rules."
        ),
        "category": "sast_bypass",
        "severity": "HIGH",
        "resource_id": "github-actions-ci-security-scan-yml",
        "resource_type": "CICDPipeline",
        "resource_name": "ci-security-scan.yml",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Revert the --skip-checks modification and re-run SAST on all 3 subsequent commits. "
            "2. Triage any SQL injection, XSS, or path traversal findings identified. "
            "3. Add branch protection rule: security pipeline configuration changes require "
            "approval from the Security team (CODEOWNERS). "
            "4. Prohibit --skip-checks flags in pipeline definitions via policy-as-code check. "
            "5. Run immediate SAST scan on main branch with full ruleset enabled."
        ),
        "remediation_effort": "Medium",
        "risk_score": 0.85,
        "actively_exploited": False,
        "first_seen": "2024-01-14T15:30:00Z",
    },
    {
        "id": "dc-003",
        "claw": "devclaw",
        "provider": "aws",
        "title": "Container Base Image Contains 47 Known CVEs Including 3 Critical RCEs",
        "description": (
            "Container image 'node:16-alpine' (digest sha256:a4b9c2d1...) used as the base in "
            "12 production microservices has 47 known CVEs identified by Trivy scan: "
            "3 CRITICAL (CVE-2023-44487 HTTP/2 RCE, CVE-2023-4863 libwebp heap overflow, "
            "CVE-2022-37434 zlib RCE), 18 HIGH, 22 MEDIUM, 4 LOW. "
            "node:16 reached end-of-life on September 11, 2023 — it is no longer receiving "
            "security patches from the Node.js Foundation. "
            "The image has not been updated in 187 days. All 12 services are deployed in production "
            "handling customer traffic including the payment API and authentication service."
        ),
        "category": "vulnerable_dependency",
        "severity": "CRITICAL",
        "resource_id": "node:16-alpine@sha256:a4b9c2d1",
        "resource_type": "ContainerImage",
        "resource_name": "node:16-alpine",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Update all 12 services to node:20-alpine (current LTS, actively patched). "
            "2. Rebuild and redeploy all affected container images. "
            "3. Add Trivy or Grype image scanning to the CI pipeline with a critical CVE gate. "
            "4. Implement a policy: no EOL base images in production. "
            "5. Subscribe to Node.js security advisories and automate base image update PRs "
            "via Renovate or Dependabot."
        ),
        "remediation_effort": "High",
        "risk_score": 0.94,
        "actively_exploited": True,
        "first_seen": "2024-01-01T00:00:00Z",
    },
    {
        "id": "dc-004",
        "claw": "devclaw",
        "provider": "aws",
        "title": "No Container Image Signing — Supply Chain Attack Risk on All Production Images",
        "description": (
            "None of the 34 container images deployed to the production ECS cluster "
            "(cluster: prod-ecs-cluster-us-east-1) are signed with Notation, Cosign, or "
            "Docker Content Trust. The ECR repository policy does not require image signatures "
            "for deployment. This means any image pushed to ECR — including a malicious image "
            "resulting from a compromised CI/CD pipeline or a registry hijack — could be "
            "deployed to production without cryptographic verification of its integrity or origin. "
            "The SolarWinds and Codecov supply chain attacks exploited this exact gap."
        ),
        "category": "supply_chain",
        "severity": "HIGH",
        "resource_id": "prod-ecs-cluster-us-east-1",
        "resource_type": "ECSCluster",
        "resource_name": "prod-ecs-cluster-us-east-1",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Implement Cosign image signing in the CI pipeline: sign all images at build time "
            "with a KMS-backed key. "
            "2. Enable AWS ECR image signing verification via ECR lifecycle policy. "
            "3. Deploy Kyverno or OPA Gatekeeper admission controller to reject unsigned images. "
            "4. Sign all 34 existing production images retroactively. "
            "5. Add SLSA provenance attestations to CI pipeline for full build traceability."
        ),
        "remediation_effort": "High",
        "risk_score": 0.82,
        "actively_exploited": False,
        "first_seen": "2024-01-01T00:00:00Z",
    },
    {
        "id": "dc-005",
        "claw": "devclaw",
        "provider": "aws",
        "title": "Terraform State File Exposes Production Database Password in Plaintext",
        "description": (
            "Terraform state file 'terraform.tfstate' in S3 bucket "
            "s3://corp-terraform-state-prod contains the production RDS master password "
            "in plaintext within the 'aws_db_instance.prod_rds' resource block "
            "(key: 'password': 'Pr0d-DB-P@ssw0rd-2023!'). "
            "The S3 bucket has versioning enabled (all historical states also contain the password) "
            "and is accessible to the 'terraform-developers' IAM group (23 members). "
            "Server-side encryption is enabled but this does not prevent authorized bucket "
            "readers from extracting the plaintext value."
        ),
        "category": "secret_exposure",
        "severity": "CRITICAL",
        "resource_id": "s3://corp-terraform-state-prod/terraform.tfstate",
        "resource_type": "TerraformStateFile",
        "resource_name": "corp-terraform-state-prod/terraform.tfstate",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Rotate the RDS master password immediately (the current value is compromised). "
            "2. Migrate the password to AWS Secrets Manager and reference via "
            "data 'aws_secretsmanager_secret_version' in Terraform — the state will then "
            "contain only the secret ARN, not the value. "
            "3. Restrict s3://corp-terraform-state-prod access to only the CI/CD role — "
            "remove developer access. "
            "4. Enable S3 Object Lock to prevent accidental state deletion. "
            "5. Audit all Terraform state files for other embedded secrets."
        ),
        "remediation_effort": "Medium",
        "risk_score": 0.93,
        "actively_exploited": False,
        "first_seen": "2024-01-05T00:00:00Z",
    },
    {
        "id": "dc-006",
        "claw": "devclaw",
        "provider": "github",
        "title": "npm Dependency with Known Backdoor Found in Production Build Tree",
        "description": (
            "Dependency scanning detected that npm package 'event-stream@3.3.6' is present "
            "in the transitive dependency tree of 'corp/analytics-service' "
            "(path: analytics-service -> flatmap-stream@0.1.1 -> event-stream@3.3.6). "
            "event-stream@3.3.6 contains a confirmed backdoor (CVE-2018-16487) that targets "
            "the Copay cryptocurrency wallet — however, the malicious flatmap-stream dependency "
            "was added by a supply chain attacker who gained maintainer rights on npm. "
            "The package is in the production build and ships to customer-facing analytics dashboards. "
            "This version has been flagged as malicious by npm security since November 2018."
        ),
        "category": "supply_chain",
        "severity": "CRITICAL",
        "resource_id": "npm-event-stream-3.3.6",
        "resource_type": "NPMPackage",
        "resource_name": "event-stream@3.3.6",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Remove event-stream@3.3.6 and flatmap-stream@0.1.1 from the dependency tree immediately. "
            "2. Find the direct dependency that pulls in flatmap-stream and update or replace it. "
            "3. Rebuild and redeploy analytics-service. "
            "4. Add npm audit --audit-level=critical to the CI pipeline as a blocking gate. "
            "5. Implement a software composition analysis (SCA) tool (Snyk, Socket.dev) with "
            "real-time malicious package detection. "
            "6. Pin all transitive dependencies with a lockfile and enable integrity checksums."
        ),
        "remediation_effort": "Medium",
        "risk_score": 0.95,
        "actively_exploited": True,
        "first_seen": "2024-01-14T00:00:00Z",
    },
    {
        "id": "dc-007",
        "claw": "devclaw",
        "provider": "aws",
        "title": "Missing SBOM for All 34 Production Container Images — Supply Chain Blind Spot",
        "description": (
            "No Software Bill of Materials (SBOM) has been generated for any of the 34 container "
            "images currently running in production ECS cluster prod-ecs-cluster-us-east-1. "
            "Without SBOMs, the organization cannot: rapidly determine blast radius when a new "
            "CVE is published (e.g., Log4Shell required knowing which services used log4j), "
            "comply with Executive Order 14028 SBOM requirements for federal-facing services, "
            "or meet customer contractual requirements (3 enterprise customers require SBOM "
            "delivery per their SLAs). The audit team flagged this as a compliance gap in "
            "the Q4 2023 security review."
        ),
        "category": "supply_chain",
        "severity": "MEDIUM",
        "resource_id": "prod-ecs-cluster-us-east-1",
        "resource_type": "ECSCluster",
        "resource_name": "prod-ecs-cluster-us-east-1",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Integrate Syft or Amazon Inspector SBOM generation into the CI pipeline "
            "to produce CycloneDX or SPDX format SBOMs at every image build. "
            "2. Store SBOMs in ECR as OCI attestations alongside the image. "
            "3. Generate retroactive SBOMs for all 34 current production images. "
            "4. Set up a vulnerability correlation pipeline: when a new CVE is published, "
            "automatically query SBOMs to find affected services. "
            "5. Deliver SBOMs to the 3 enterprise customers requiring them per SLA."
        ),
        "remediation_effort": "Medium",
        "risk_score": 0.68,
        "actively_exploited": False,
        "first_seen": "2024-01-01T00:00:00Z",
    },
    {
        "id": "dc-008",
        "claw": "devclaw",
        "provider": "github",
        "title": "Pipeline Allows Force Push to Main Branch Without Code Review",
        "description": (
            "GitHub repository 'corp/core-platform' branch protection rules for 'main' do NOT "
            "enforce: required pull request reviews, status checks before merging, or restrictions "
            "on force pushes. Currently 7 users with 'Maintain' role and all 4 users with 'Admin' "
            "role can force push directly to main, bypassing the CI security pipeline, peer review, "
            "and SAST scanning. Force pushes also rewrite git history, which can permanently destroy "
            "audit trails. In the past 90 days, 12 direct commits to main were made without review — "
            "3 of which introduced security-relevant changes to authentication and session management code."
        ),
        "category": "pipeline_misconfiguration",
        "severity": "HIGH",
        "resource_id": "github-corp-core-platform-main",
        "resource_type": "GitBranch",
        "resource_name": "corp/core-platform:main",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": (
            "1. Enable branch protection on main: require at least 2 PR approvals including "
            "1 from the Security team for auth-related paths (via CODEOWNERS). "
            "2. Require all status checks to pass before merging (CI, SAST, tests). "
            "3. Restrict force pushes: only allow for branch administrators, require justification ticket. "
            "4. Enable 'Require linear history' to prevent merge commits that obscure changes. "
            "5. Audit the 3 unreviewed auth/session commits — manually review for vulnerabilities."
        ),
        "remediation_effort": "Low",
        "risk_score": 0.80,
        "actively_exploited": False,
        "first_seen": "2024-01-01T00:00:00Z",
    },
]


class DevTaskRequest(BaseModel):
    swarm_job_id: str | None = None
    task_type: str = "investigate_devsecops_risk"
    input: dict = Field(default_factory=dict)
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = Field(default_factory=lambda: ["read", "analyze", "recommend"])


@router.get("/stats", summary="Developer Security summary statistics")
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
            if f["status"] == "OPEN": open_count += 1
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


@router.get("/findings", summary="All Developer Security findings")
async def get_findings(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    from app.models.finding import Finding
    from app.services.connector_check import is_connector_configured
    result = await db.execute(
        select(Finding).where(Finding.claw == CLAW_NAME).order_by(Finding.risk_score.desc())
    )
    findings = result.scalars().all()
    if not findings:
        # Only show demo data if NO real connector is configured
        any_configured = any([
            await is_connector_configured(db, p["connector_type"])
            for p in PROVIDER_MAP if p.get("connector_type")
        ])
        if not any_configured:
            return [{**f, "risk_score": _normalize_risk_score(f.get("risk_score"))} for f in _FINDINGS]
        return []   # connector configured but no findings yet — return clean empty list
    return [
        {
            "id": str(f.id), "claw": f.claw, "provider": f.provider,
            "title": f.title, "description": f.description, "category": f.category,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "status": f.status.value if hasattr(f.status, "value") else f.status,
            "resource_id": f.resource_id, "resource_type": f.resource_type,
            "resource_name": f.resource_name, "region": f.region,
            "risk_score": _normalize_risk_score(f.risk_score), "actively_exploited": f.actively_exploited,
            "remediation": f.remediation, "remediation_effort": f.remediation_effort,
            "external_id": f.external_id,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        }
        for f in findings
    ]


@router.get("/providers", summary="Developer Security provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    from app.services.connector_check import check_providers
    return await check_providers(db, PROVIDER_MAP)


@router.post("/scan", summary="Run Developer Security scan and persist findings")
async def run_scan(db: AsyncSession = Depends(get_db)):
    """Run a Developer Security scan. Uses real GitHub API when configured, otherwise falls back to simulation."""
    from app.services.finding_pipeline import ingest_findings
    from app.services.connector_check import is_connector_configured

    github_configured = await is_connector_configured(db, "github")

    if github_configured:
        # Real scan via GitHub REST API
        from app.claws.devclaw.github_scanner import fetch_github_findings
        from sqlalchemy import delete
        from app.models.finding import Finding
        try:
            pipeline_findings = await fetch_github_findings(db)
        except ValueError:
            return {"status": "error", "message": "Invalid connector configuration", "findings_created": 0, "findings_updated": 0, "critical": 0, "high": 0}
        except Exception:
            logger.exception("GitHub scan failed")
            return {"status": "error", "message": "GitHub scan failed", "findings_created": 0, "findings_updated": 0, "critical": 0, "high": 0}

        # Purge simulation findings (no external_id = ingested from _FINDINGS demo data)
        await db.execute(
            delete(Finding).where(
                Finding.claw == CLAW_NAME,
                Finding.external_id.is_(None),
            )
        )
        await db.commit()
    else:
        # Simulation fallback
        pipeline_findings = []
        for f in _FINDINGS:
            entry = dict(f)
            entry.setdefault("claw", CLAW_NAME)
            entry.setdefault("provider", "github")
            if "severity" in entry:
                entry["severity"] = str(entry["severity"]).lower()
            pipeline_findings.append(entry)

    if not pipeline_findings:
        return {"status": "completed", "findings_created": 0, "findings_updated": 0, "critical": 0, "high": 0, "message": "No findings from GitHub (all clean or no alerts enabled)"}

    summary = await ingest_findings(db, CLAW_NAME, pipeline_findings)
    return {
        "status": "completed",
        "findings_created": summary["created"],
        "findings_updated": summary["updated"],
        "critical": summary["critical"],
        "high": summary["high"],
    }


@router.post("/task", summary="Execute focused Developer Security swarm task")
async def run_dev_task(payload: DevTaskRequest, db: AsyncSession = Depends(get_db)):
    from app.services.connector_check import is_connector_configured
    from app.claws.devclaw.github_scanner import fetch_github_findings

    started = datetime.utcnow()
    selected = payload.input.get("selected_finding") or payload.input.get("finding_context")
    if not isinstance(selected, dict):
        selected = {
            key: payload.input.get(key)
            for key in ("finding_id", "claw", "provider", "title", "repo", "package", "severity", "risk_score")
            if payload.input.get(key) is not None
        }
    if selected and selected.get("risk_score") is not None:
        try:
            selected["risk_score"] = _normalize_risk_score(selected.get("risk_score"))
        except (TypeError, ValueError):
            selected.pop("risk_score", None)

    stmt = (
        select(Finding)
        .where(Finding.claw == CLAW_NAME)
        .order_by(desc(Finding.risk_score), desc(Finding.created_at))
        .limit(5)
    )
    result = await db.execute(stmt)
    findings = result.scalars().all()
    live_rows = []
    live_risks = []
    github_configured = await is_connector_configured(db, "github")
    if not findings and github_configured:
        try:
            raw = await fetch_github_findings(db)
        except Exception:
            raw = []
        for row in raw[:3]:
            live_rows.append(
                {
                    "title": row.get("title") or "GitHub live finding",
                    "detail": (row.get("description") or "Connector-backed task finding")[:220],
                }
            )
            live_risks.append(_normalize_risk_score(row.get("risk_score")))

    max_risk = max([_normalize_risk_score(f.risk_score) for f in findings], default=0.0)
    if live_risks:
        max_risk = max(max_risk, max(live_risks))
    if selected:
        selected_risk = float(selected.get("risk_score") or 0.0)
        severity_floor = {"critical": 90.0, "high": 75.0, "medium": 50.0, "low": 25.0}.get(
            str(selected.get("severity") or "").lower(),
            0.0,
        )
        max_risk = max(max_risk, selected_risk, severity_floor)
    severity = "critical" if max_risk >= 85 else "high" if max_risk >= 70 else "medium" if max_risk >= 40 else "low"
    confidence = 0.92 if live_rows else (0.9 if findings else 0.7)
    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)

    persisted_rows = [
        {
            "title": f.title,
            "detail": f"{f.provider or 'dev'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}",
        }
        for f in findings[:3]
    ]
    selected_rows = []
    if selected:
        selected_rows = [
            {
                "title": selected.get("title") or "Selected GitHub finding",
                "detail": (
                    f"Selected finding context; provider={selected.get('provider', 'unknown')}; "
                    f"repo={selected.get('repo') or selected.get('repository') or 'unknown'}; "
                    f"package={selected.get('package') or selected.get('dependency') or 'unknown'}; "
                    f"severity={selected.get('severity', 'unknown')}"
                ),
                "selected_finding_id": selected.get("finding_id") or selected.get("id"),
                "provider": selected.get("provider"),
                "repo": selected.get("repo") or selected.get("repository"),
                "package": selected.get("package") or selected.get("dependency"),
                "severity": selected.get("severity"),
            }
        ]
    finding_rows = selected_rows or live_rows or persisted_rows or [{"title": "No dev findings persisted yet", "detail": "Run /devclaw/scan or configure providers."}]
    data_source = "live_connector" if live_rows else ("persisted_db" if persisted_rows else "seeded_fallback")
    connector_state = "configured" if github_configured else "unconfigured"

    return {
        "task_id": f"dev-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": "devclaw",
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": finding_rows,
        "evidence": ([{"type": "selected_finding_context", "finding": selected}] if selected else []),
        "recommended_actions": [
            "Rotate exposed secrets and enforce pre-commit scanning",
            "Block unsigned or vulnerable artifacts in CI/CD",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["SLSA", "NIST SA-11"],
        "execution_time_ms": elapsed_ms,
        "data_source": data_source,
        "connector_state": connector_state,
        "selected_finding": selected or None,
        "investigation_scope": "selected_finding" if selected else "broad_task",
    }
