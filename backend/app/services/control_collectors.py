"""Evidence collectors: which connector proves which control.

A control is only assessable when something can observe the system state it
asserts. This module is that binding. Each baseline control names the
connector types capable of producing its evidence, and an evaluator key naming
the collector that interprets it.

Keeping the binding here rather than inside each Capability Node matters
because it makes coverage answerable in one query: an Arm's real coverage is
the share of its controls whose collector has a configured connector. A
control whose connector is absent reports NOT_ASSESSED, which is the honest
answer, instead of silently counting as a pass.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.connector import Connector
from app.models.control import Control

logger = logging.getLogger("controls.collectors")

# evaluator_key -> (connector types that can satisfy it, human description).
# The connector list is an OR: any one of them provides the evidence.
COLLECTORS: dict[str, dict[str, Any]] = {
    "identity.entra": {
        "connectors": ["entra_id", "azure_ad", "okta", "exabeam", "securonix"],
        "domain": "identity",
        "description": "Directory, privileged role, and sign-in risk state from the identity provider.",
    },
    "identity.privilege": {
        "connectors": [
            "entra_id", "azure_ad", "okta", "aws_iam",
            "cyberark", "hashicorp_vault", "auth0", "ping_identity", "duo",
            "dtex", "code42",
        ],
        "domain": "identity",
        "description": "Privileged assignment and standing-access review evidence.",
    },
    "endpoint.posture": {
        "connectors": [
            "defender_endpoint", "crowdstrike", "sentinelone", "intune",
            "tanium", "carbonblack",
        ],
        "domain": "endpoint",
        "description": "Managed device inventory, compliance state, and agent health.",
    },
    "network.exposure": {
        "connectors": [
            "aws_security_hub", "azure_defender", "gcp_scc", "shodan", "censys",
            "tenable", "qualys", "rapid7",
        ],
        "domain": "network",
        "description": "Internet-facing surface and boundary enforcement evidence.",
    },
    "network.segmentation": {
        "connectors": [
            "aws_security_hub", "azure_defender", "gcp_scc", "paloalto",
            "zscaler", "cloudflare", "cisco_umbrella", "fortinet",
        ],
        "domain": "network",
        "description": "Deny-by-default boundary and traffic-encryption configuration.",
    },
    "data.classification": {
        "connectors": [
            "purview", "mcas", "aws_security_hub", "gcp_scc",
            "varonis", "nightfall", "bigid", "onetrust", "transcend",
        ],
        "domain": "data",
        "description": "Sensitive-data discovery, labelling, and handling enforcement.",
    },
    "data.access": {
        "connectors": [
            "purview", "mcas", "entra_id", "aws_security_hub",
            "netskope", "google_workspace", "salesforce", "slack", "ms_teams",
        ],
        "domain": "data",
        "description": "Access to classified data by identity and stated purpose.",
    },
    "application.appsec": {
        "connectors": ["github", "gitlab", "checkmarx", "veracode", "snyk"],
        "domain": "application",
        "description": "Application authorization and input-handling defects from code analysis.",
    },
    "application.supplychain": {
        "connectors": ["github", "gitlab", "snyk", "dependabot", "jenkins"],
        "domain": "application",
        "description": "Dependency, branch-protection, and secret-scanning state.",
    },
    "cloud.posture": {
        "connectors": [
            "prowler", "aws_security_hub", "azure_defender", "gcp_scc",
            "wiz", "azure_arm", "gcp_iam",
        ],
        "domain": "cloud",
        "description": "Cloud configuration posture from a read-only scanner.",
    },
    "cloud.logging": {
        "connectors": [
            "aws_security_hub", "azure_defender", "gcp_scc", "splunk", "sentinel",
            "elastic", "datadog", "qradar", "sumologic",
        ],
        "domain": "cloud",
        "description": "Security-relevant audit event collection and retention.",
    },
    "terraclaw.rule": {
        "connectors": ["terraform_mcp", "tfsec", "checkov", "terraform_cloud"],
        "domain": "application",
        "description": "Deterministic infrastructure-as-code rule evaluation.",
    },
    "arcclaw.pattern": {
        "connectors": [],  # Local scanner; needs no external connector.
        "domain": "application",
        "description": "Local AI input/output pattern scanner.",
        "local": True,
    },
    # Collectors for the eight Capability Nodes whose baseline control shipped
    # with no evaluator, which left every connector feeding those nodes
    # reporting an empty control scope even when it had a working adapter.
    "cloud.attackpath": {
        "connectors": ["wiz", "orca", "aws_security_hub", "azure_defender", "gcp_scc"],
        "domain": "cloud",
        "description": "Exploitable chains correlated across identity, exposure, and workload state.",
    },
    "automation.governance": {
        "connectors": ["jenkins", "terraform_cloud", "servicenow"],
        "domain": "automation",
        "description": "Scope, approval, and audit evidence for automated pipelines and jobs.",
    },
    "compliance.evidence": {
        "connectors": ["drata", "vanta", "servicenow"],
        "domain": "governance",
        "description": "Traceable control evidence from a compliance automation platform.",
    },
    "threat.intelligence": {
        "connectors": ["cisa_kev", "recorded_future", "misp", "threatfox", "crowdstrike_intel"],
        "domain": "visibility",
        "description": "Indicator source, confidence, and freshness provenance.",
    },
    "threat.detection": {
        "connectors": ["virustotal", "crowdstrike", "defender_endpoint", "sentinel", "splunk"],
        "domain": "visibility",
        "description": "Indicator correlation against observable detections.",
    },
    "application.release": {
        "connectors": ["github", "gitlab", "jenkins", "terraform_cloud"],
        "domain": "application",
        "description": "Build provenance, artifact signing, and deployment-gate evidence.",
    },
    "vendor.assurance": {
        "connectors": ["bitsight", "security_scorecard", "upguard", "servicenow", "jira"],
        "domain": "governance",
        "description": "Third-party posture ratings and contractual assurance records.",
    },
    "recovery.readiness": {
        "connectors": ["aws_security_hub", "azure_defender", "gcp_scc", "servicenow"],
        "domain": "governance",
        "description": "Backup coverage and tested recovery-objective evidence.",
    },
    "prowler.aws": {"connectors": ["prowler"], "domain": "cloud", "description": "Prowler AWS checks."},
    "prowler.azure": {"connectors": ["prowler"], "domain": "cloud", "description": "Prowler Azure checks."},
    "prowler.gcp": {"connectors": ["prowler"], "domain": "cloud", "description": "Prowler GCP checks."},
    "prowler.kubernetes": {"connectors": ["prowler"], "domain": "cloud", "description": "Prowler Kubernetes checks."},
    "prowler.github": {"connectors": ["prowler"], "domain": "cloud", "description": "Prowler GitHub checks."},
}

# Baseline control slug -> evaluator key. These are the recommendation-only
# controls from the control pack that now have a real collector behind them.
BASELINE_EVALUATORS: dict[str, str] = {
    "enkstein:identityclaw:identity-lifecycle": "identity.entra",
    "enkstein:identityclaw:identity-authentication": "identity.entra",
    "enkstein:accessclaw:privilege-least": "identity.privilege",
    "enkstein:accessclaw:privilege-jit": "identity.privilege",
    "enkstein:userclaw:user-risk": "identity.entra",
    "enkstein:insiderclaw:insider-separation": "identity.privilege",
    "enkstein:endpointclaw:device-inventory": "endpoint.posture",
    "enkstein:endpointclaw:device-posture": "endpoint.posture",
    "enkstein:netclaw:network-segmentation": "network.segmentation",
    "enkstein:netclaw:network-encryption": "network.segmentation",
    "enkstein:exposureclaw:external-exposure": "network.exposure",
    "enkstein:cloudclaw:cloud-identity": "cloud.posture",
    "enkstein:cloudclaw:cloud-encryption": "cloud.posture",
    "enkstein:cloudclaw:cloud-logging": "cloud.logging",
    "enkstein:appclaw:app-authz": "application.appsec",
    "enkstein:appclaw:app-validation": "application.appsec",
    "enkstein:devclaw:dev-review": "application.supplychain",
    "enkstein:devclaw:dev-secrets": "application.supplychain",
    "enkstein:terraclaw:iac-network": "terraclaw.rule",
    "enkstein:terraclaw:iac-data": "terraclaw.rule",
    "enkstein:configclaw:configuration-baseline": "cloud.posture",
    "enkstein:dataclaw:data-classification": "data.classification",
    "enkstein:dataclaw:data-access": "data.access",
    "enkstein:privacyclaw:privacy-minimization": "data.classification",
    "enkstein:saasclaw:saas-audit": "data.access",
    "enkstein:logclaw:telemetry-integrity": "cloud.logging",
    "enkstein:arcclaw:ai-input": "arcclaw.pattern",
    "enkstein:arcclaw:ai-output": "arcclaw.pattern",
    # Previously unevaluated nodes. Each is bound to the collector whose
    # connectors genuinely produce that node's evidence, so a control here is
    # assessable rather than permanently recommendation-only.
    "enkstein:attackpathclaw:attack-path": "cloud.attackpath",
    "enkstein:automationclaw:automation-governance": "automation.governance",
    "enkstein:complianceclaw:control-evidence": "compliance.evidence",
    "enkstein:intelclaw:intel-provenance": "threat.intelligence",
    "enkstein:recoveryclaw:recovery-test": "recovery.readiness",
    "enkstein:releaseclaw:release-integrity": "application.release",
    "enkstein:threatclaw:threat-detection": "threat.detection",
    "enkstein:vendorclaw:vendor-assurance": "vendor.assurance",
}

# Controls whose remediation the platform can actually execute. Anything not
# listed stays recommendation-only rather than implying a fix Enkstein cannot
# perform.
BASELINE_REMEDIATION: dict[str, str] = {
    "enkstein:identityclaw:identity-lifecycle": "revoke_sessions",
    "enkstein:identityclaw:identity-authentication": "force_mfa_reset",
    "enkstein:accessclaw:privilege-least": "remove_group_member",
    "enkstein:userclaw:user-risk": "revoke_sessions",
    "enkstein:insiderclaw:insider-separation": "revoke_sessions",
    "enkstein:endpointclaw:device-posture": "quarantine_device",
    "enkstein:cloudclaw:cloud-identity": "deactivate_access_key",
    "enkstein:devclaw:dev-secrets": "create_jira_ticket",
}


async def configured_connectors(db: AsyncSession, *, tenant_id: str | None = None) -> set[str]:
    """Connector types that currently have stored credentials.

    A connector row means "this integration exists"; only a stored credential
    means it can actually be called. Readiness uses the credential, so an
    unconfigured connector cannot inflate control coverage.
    """
    from app.services import secrets_manager

    try:
        stored = {str(item) for item in secrets_manager.list_configured()}
    except Exception:
        logger.warning("Credential store unavailable; treating all collectors as unconfigured")
        return set()
    statement = select(Connector)
    if tenant_id is not None:
        statement = statement.where(Connector.tenant_id == tenant_id)
    rows = (await db.execute(statement)).scalars().all()
    active: set[str] = set()
    for row in rows:
        status = str(getattr(row.status, "value", row.status) or "").lower()
        if status in {"disabled", "revoked", "error"} or not row.connector_type:
            continue
        connector_type = str(row.connector_type)
        # Credentials are keyed by connector type or by connector id.
        if connector_type in stored or str(row.id) in stored:
            active.add(connector_type)
    return active


def collector_ready(evaluator_key: str | None, active: set[str]) -> bool:
    """Whether a collector can produce evidence with what is configured."""
    if not evaluator_key:
        return False
    spec = COLLECTORS.get(evaluator_key)
    if spec is None:
        return False
    if spec.get("local"):
        return True
    return any(connector in active for connector in spec["connectors"])


async def attach_evaluators(db: AsyncSession) -> dict[str, int]:
    """Bind collectors and executable remediation onto baseline controls.

    Run after the baseline pack is installed. Idempotent: a control that
    already carries the intended evaluator is left untouched.
    """
    rows = (await db.execute(
        select(Control).where(Control.control_id.in_(list(BASELINE_EVALUATORS)))
    )).scalars().all()
    attached = remediable = 0
    for row in rows:
        evaluator = BASELINE_EVALUATORS.get(row.control_id)
        if evaluator and row.evaluator_key != evaluator:
            row.evaluator_key = evaluator
            spec = COLLECTORS.get(evaluator, {})
            row.evidence_method = str(spec.get("description") or row.evidence_method)
            attached += 1
        action = BASELINE_REMEDIATION.get(row.control_id)
        if action and row.remediation_action != action:
            row.remediation_action = action
            row.remediation_mode = "governed_action"
            row.recommendation_only = False
            remediable += 1
    await db.commit()
    return {"examined": len(rows), "evaluators_attached": attached, "remediation_linked": remediable}


async def readiness(db: AsyncSession, *, tenant_id: str | None = None) -> dict[str, Any]:
    """Which collectors can run right now, and which need a connector."""
    active = await configured_connectors(db, tenant_id=tenant_id)
    ready, blocked = [], []
    for key, spec in sorted(COLLECTORS.items()):
        entry = {
            "evaluator_key": key,
            "domain": spec["domain"],
            "description": spec["description"],
            "connectors": spec["connectors"],
            "local": bool(spec.get("local")),
        }
        (ready if collector_ready(key, active) else blocked).append(entry)
    return {
        "configured_connectors": sorted(active),
        "ready": ready,
        "blocked": blocked,
        "ready_count": len(ready),
        "total": len(COLLECTORS),
    }
