"""Zero Trust release and deployment control plane.

Release Governance normalizes CI/CD, cloud SDK/CLI, IaC, Kubernetes, and script-driven
deployments into one governed preflight/evidence contract. It intentionally does
not execute arbitrary scripts directly; execution is represented as a Trust
Fabric-gated handoff to CI/CD systems or ExecChannels.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.trust_fabric import ActionRequest, enforce

router = APIRouter(prefix="/releaseclaw", tags=["Governed Deployments"])

CLAW_NAME = "releaseclaw"

DeploymentSource = Literal[
    "github_actions",
    "gitlab_ci",
    "jenkins",
    "azure_devops",
    "argocd",
    "terraform_cloud",
    "aws_cli",
    "azure_cli",
    "gcloud_cli",
    "kubernetes",
    "helm",
    "docker",
    "docker_compose",
    "bash",
    "powershell",
    "python",
    "node",
    "ansible",
    "webhook",
    "custom",
]

DeploymentType = Literal[
    "kubernetes",
    "terraform",
    "serverless",
    "vm",
    "container",
    "full_stack",
    "ai_stack",
    "database",
    "network",
    "custom_script",
]

DeploymentMode = Literal[
    "DRY_RUN",
    "PLAN_ONLY",
    "APPROVAL_REQUIRED",
    "CANARY",
    "BLUE_GREEN",
    "ROLLING",
    "EMERGENCY_PATCH",
    "FULL_STACK_PROVISION",
    "AI_STACK_DEPLOY",
    "ROLLBACK_ONLY",
]


ADAPTERS: dict[str, dict[str, Any]] = {
    "github_actions": {
        "label": "GitHub Actions",
        "category": "ci_cd",
        "execution_channel": "ci_runner",
        "allowed_actions": ["workflow_dispatch", "environment_deploy", "deployment_status"],
        "controls": ["branch_protection", "signed_commits", "dependency_review", "secret_scan", "required_checks"],
    },
    "gitlab_ci": {
        "label": "GitLab CI",
        "category": "ci_cd",
        "execution_channel": "ci_runner",
        "allowed_actions": ["pipeline_run", "environment_deploy"],
        "controls": ["protected_branch", "protected_environment", "dependency_scan", "secret_detection"],
    },
    "jenkins": {
        "label": "Jenkins",
        "category": "ci_cd",
        "execution_channel": "ci_runner",
        "allowed_actions": ["job_build", "promotion"],
        "controls": ["job_acl", "credential_scope", "artifact_fingerprint", "approval_gate"],
    },
    "azure_devops": {
        "label": "Azure DevOps",
        "category": "ci_cd",
        "execution_channel": "ci_runner",
        "allowed_actions": ["pipeline_run", "release_deploy"],
        "controls": ["environment_approvals", "branch_policy", "service_connection_scope"],
    },
    "argocd": {
        "label": "ArgoCD",
        "category": "gitops",
        "execution_channel": "kubernetes_controller",
        "allowed_actions": ["sync", "rollback", "health_check"],
        "controls": ["manifest_diff", "sync_window", "project_rbac", "image_provenance"],
    },
    "terraform_cloud": {
        "label": "Terraform Cloud",
        "category": "iac",
        "execution_channel": "terraform_workspace",
        "allowed_actions": ["plan", "apply", "policy_check"],
        "controls": ["plan_review", "sentinel_policy", "iam_change_detection", "public_exposure_detection"],
    },
    "aws_cli": {
        "label": "AWS CLI / SDK",
        "category": "cloud_cli",
        "execution_channel": "exec_channel",
        "allowed_actions": ["cloudformation_deploy", "ecs_update", "lambda_update", "iam_change"],
        "controls": ["security_hub_check", "iam_least_privilege", "cloudtrail_enabled", "rollback_artifact"],
    },
    "azure_cli": {
        "label": "Azure CLI / SDK",
        "category": "cloud_cli",
        "execution_channel": "exec_channel",
        "allowed_actions": ["arm_deploy", "aks_update", "function_update", "role_assignment"],
        "controls": ["defender_check", "rbac_least_privilege", "activity_log_enabled", "rollback_artifact"],
    },
    "gcloud_cli": {
        "label": "Google Cloud CLI / SDK",
        "category": "cloud_cli",
        "execution_channel": "exec_channel",
        "allowed_actions": ["cloud_run_deploy", "gke_update", "iam_policy_change"],
        "controls": ["scc_check", "iam_least_privilege", "audit_log_enabled", "rollback_artifact"],
    },
    "kubernetes": {
        "label": "Kubernetes",
        "category": "runtime",
        "execution_channel": "kubernetes_job",
        "allowed_actions": ["apply", "rollout", "rollback"],
        "controls": ["pod_security", "network_policy", "resource_limits", "image_signature"],
    },
    "helm": {
        "label": "Helm",
        "category": "runtime",
        "execution_channel": "kubernetes_job",
        "allowed_actions": ["upgrade", "rollback", "diff"],
        "controls": ["values_scan", "manifest_diff", "image_provenance", "rollback_revision"],
    },
    "docker": {
        "label": "Docker",
        "category": "runtime",
        "execution_channel": "docker_runner",
        "allowed_actions": ["image_build", "image_run", "compose_up"],
        "controls": ["base_image_scan", "secret_scan", "no_privileged_container", "artifact_digest"],
    },
    "docker_compose": {
        "label": "Docker Compose",
        "category": "runtime",
        "execution_channel": "docker_runner",
        "allowed_actions": ["compose_plan", "compose_up", "compose_down"],
        "controls": ["compose_config_scan", "secret_scan", "network_scope", "volume_scope"],
    },
    "bash": {
        "label": "Bash",
        "category": "script",
        "execution_channel": "sandboxed_shell",
        "allowed_actions": ["script_plan", "script_handoff"],
        "controls": ["command_allowlist", "path_scope", "network_scope", "secret_redaction"],
    },
    "powershell": {
        "label": "PowerShell",
        "category": "script",
        "execution_channel": "sandboxed_shell",
        "allowed_actions": ["script_plan", "script_handoff"],
        "controls": ["command_allowlist", "path_scope", "network_scope", "secret_redaction"],
    },
    "python": {
        "label": "Python",
        "category": "script",
        "execution_channel": "sandboxed_interpreter",
        "allowed_actions": ["script_plan", "script_handoff"],
        "controls": ["dependency_scan", "path_scope", "network_scope", "secret_redaction"],
    },
    "node": {
        "label": "Node.js",
        "category": "script",
        "execution_channel": "sandboxed_interpreter",
        "allowed_actions": ["script_plan", "script_handoff"],
        "controls": ["package_scan", "path_scope", "network_scope", "secret_redaction"],
    },
    "ansible": {
        "label": "Ansible",
        "category": "automation",
        "execution_channel": "automation_runner",
        "allowed_actions": ["playbook_check", "playbook_run"],
        "controls": ["inventory_scope", "vault_secret_scope", "diff_review", "rollback_playbook"],
    },
    "webhook": {
        "label": "Webhook/API",
        "category": "api",
        "execution_channel": "webhook",
        "allowed_actions": ["signed_callback", "deployment_trigger"],
        "controls": ["signature_required", "egress_allowlist", "payload_schema", "idempotency_key"],
    },
    "custom": {
        "label": "Custom Deployment Adapter",
        "category": "custom",
        "execution_channel": "exec_channel",
        "allowed_actions": ["plan", "handoff"],
        "controls": ["manifest_required", "scope_review", "approval_gate", "rollback_required"],
    },
}


TEMPLATES: dict[str, dict[str, Any]] = {
    "github-actions-prod": {
        "label": "GitHub Actions Production Release",
        "source": "github_actions",
        "deployment_type": "container",
        "mode": "APPROVAL_REQUIRED",
        "required_claws": ["devclaw", "appclaw", "threatclaw", "complianceclaw", "automationclaw"],
        "required_controls": ["branch_protection", "required_checks", "secret_scan", "dependency_review", "ticket_linked"],
    },
    "terraform-cloud-apply": {
        "label": "Terraform Cloud Apply",
        "source": "terraform_cloud",
        "deployment_type": "terraform",
        "mode": "APPROVAL_REQUIRED",
        "required_claws": ["cloudclaw", "configclaw", "accessclaw", "complianceclaw"],
        "required_controls": ["plan_review", "iam_change_detection", "public_exposure_detection", "rollback_artifact"],
    },
    "argocd-sync": {
        "label": "ArgoCD Kubernetes Sync",
        "source": "argocd",
        "deployment_type": "kubernetes",
        "mode": "CANARY",
        "required_claws": ["devclaw", "appclaw", "configclaw", "cloudclaw", "recoveryclaw"],
        "required_controls": ["manifest_diff", "image_provenance", "pod_security", "rollback_revision"],
    },
    "full-stack-app": {
        "label": "Full Stack Application Deployment",
        "source": "custom",
        "deployment_type": "full_stack",
        "mode": "APPROVAL_REQUIRED",
        "required_claws": ["devclaw", "appclaw", "cloudclaw", "configclaw", "accessclaw", "dataclaw", "complianceclaw"],
        "required_controls": ["sbom", "secret_scan", "iac_plan", "least_privilege", "data_classification", "rollback_artifact"],
    },
    "ai-service-stack": {
        "label": "AI/LLM Service Stack Deployment",
        "source": "custom",
        "deployment_type": "ai_stack",
        "mode": "AI_STACK_DEPLOY",
        "required_claws": ["arcclaw", "modelclaw", "devclaw", "appclaw", "dataclaw", "complianceclaw"],
        "required_controls": [
            "approved_model_profile",
            "prompt_injection_audit",
            "data_redaction",
            "output_rescan",
            "model_call_audit",
            "tool_permission_review",
        ],
    },
    "scripted-emergency-patch": {
        "label": "Scripted Emergency Patch",
        "source": "bash",
        "deployment_type": "custom_script",
        "mode": "EMERGENCY_PATCH",
        "required_claws": ["devclaw", "endpointclaw", "threatclaw", "recoveryclaw", "complianceclaw"],
        "required_controls": ["command_allowlist", "path_scope", "rollback_artifact", "two_operator_approval"],
    },
}

DEPLOYMENTS: dict[str, dict[str, Any]] = {}

SENSITIVE_MARKERS = ("password", "secret", "token", "api_key", "private_key", "credential")
HIGH_RISK_ACTIONS = ("delete", "destroy", "drop", "iam", "root", "public", "privileged", "sudo", "chmod 777")


class Artifact(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    type: str = Field(default="generic", max_length=80)
    uri: str | None = Field(default=None, max_length=512)
    digest: str | None = Field(default=None, max_length=160)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeploymentRequest(BaseModel):
    requested_by: str = Field(default="portal-user", min_length=2, max_length=255)
    source: DeploymentSource = "custom"
    environment: str = Field(default="staging", min_length=2, max_length=80)
    application: str = Field(default="application", min_length=2, max_length=160)
    change_ref: str = Field(default="manual", min_length=1, max_length=256)
    deployment_type: DeploymentType = "custom_script"
    mode: DeploymentMode = "DRY_RUN"
    template_id: str | None = Field(default=None, max_length=120)
    artifacts: list[Artifact] = Field(default_factory=list)
    required_controls: list[str] = Field(default_factory=list)
    execution_plan: list[dict[str, Any]] = Field(default_factory=list)
    rollback_plan: list[dict[str, Any]] = Field(default_factory=list)
    model_profile: str | None = Field(default=None, max_length=120)
    target_cloud: str | None = Field(default=None, max_length=80)
    target_region: str | None = Field(default=None, max_length=80)
    classification: str = Field(default="internal", max_length=64)
    tenant_id: str = Field(default="default", max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("environment")
    @classmethod
    def normalize_environment(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("required_controls")
    @classmethod
    def clean_controls(cls, value: list[str]) -> list[str]:
        return sorted({str(v).strip()[:120] for v in value if str(v).strip()})


class ApprovalRequest(BaseModel):
    note: str | None = Field(default=None, max_length=500)
    tenant_id: str = Field(default="default", max_length=120)


class ReleaseTaskRequest(BaseModel):
    swarm_job_id: str | None = None
    task_type: str = "deployment_preflight"
    input: dict[str, Any] = Field(default_factory=dict)
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = Field(default_factory=lambda: ["read", "analyze", "recommend"])


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[redacted]" if any(marker in key.lower() for marker in SENSITIVE_MARKERS) else _redact(val)
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        lower = value.lower()
        if any(marker in lower for marker in (
            "password=",
            "token=",
            "secret=",
            "api_key=",
            "private_key=",
            "ghp_",
            "github_pat_",
            "xoxb-",
            "akia",
            "-----begin",
        )):
            return "[redacted]"
    return value


def _template_for(body: DeploymentRequest) -> dict[str, Any] | None:
    if body.template_id:
        return TEMPLATES.get(body.template_id)
    for template in TEMPLATES.values():
        if template["source"] == body.source and template["deployment_type"] == body.deployment_type:
            return template
    return None


def _score_preflight(body: DeploymentRequest, template: dict[str, Any] | None) -> tuple[int, list[str], list[str]]:
    risk = 20
    blockers: list[str] = []
    warnings: list[str] = []

    if body.environment in {"prod", "production"}:
        risk += 25
        warnings.append("production_environment")
    if body.mode in {"EMERGENCY_PATCH", "FULL_STACK_PROVISION", "AI_STACK_DEPLOY"}:
        risk += 15
        warnings.append(f"elevated_mode:{body.mode}")
    if body.deployment_type in {"full_stack", "ai_stack", "network"}:
        risk += 12
    if ADAPTERS[body.source]["category"] == "script":
        risk += 18
        warnings.append("scripted_deployment_requires_sandbox_handoff")
    if not body.rollback_plan and body.mode not in {"PLAN_ONLY", "DRY_RUN"}:
        risk += 15
        blockers.append("rollback_plan_missing")
    if not body.artifacts:
        risk += 8
        warnings.append("no_artifacts_declared")
    if body.classification.lower() in {"confidential", "restricted", "regulated"}:
        risk += 10
        warnings.append(f"classified_data:{body.classification.lower()}")
    if body.deployment_type == "ai_stack" and not body.model_profile:
        risk += 12
        blockers.append("model_profile_required_for_ai_stack")

    raw_plan_text = json.dumps(body.execution_plan, sort_keys=True).lower()
    if any(term in raw_plan_text for term in HIGH_RISK_ACTIONS):
        risk += 18
        warnings.append("high_risk_operation_detected")
    if any(marker in raw_plan_text for marker in SENSITIVE_MARKERS):
        risk += 20
        blockers.append("possible_secret_in_execution_plan")

    required = set(body.required_controls)
    if template:
        required.update(template.get("required_controls", []))
    if "secret_scan" not in required and body.source in {"github_actions", "gitlab_ci", "docker", "docker_compose", "bash", "powershell", "python", "node"}:
        risk += 8
        warnings.append("secret_scan_not_declared")
    if "approval_gate" not in required and body.environment in {"prod", "production"}:
        warnings.append("approval_gate_recommended")

    return min(risk, 100), blockers, warnings


def _decision_from_risk(risk: int, blockers: list[str], fabric_allowed: bool, fabric_outcome: str) -> str:
    if blockers or not fabric_allowed or fabric_outcome == "blocked":
        return "blocked"
    if risk >= 70 or fabric_outcome == "requires_approval":
        return "approval_required"
    if risk >= 45:
        return "conditional"
    return "allowed"


def _deployment_record(
    body: DeploymentRequest,
    risk: int,
    blockers: list[str],
    warnings: list[str],
    policy: dict[str, Any],
) -> dict[str, Any]:
    template = _template_for(body)
    required_controls = sorted(set(body.required_controls) | set((template or {}).get("required_controls", [])))
    required_claws = (template or {}).get("required_claws", _default_claws_for(body))
    deployment_id = f"dep_{uuid.uuid4().hex[:12]}"
    now = datetime.utcnow().isoformat()
    status = _decision_from_risk(risk, blockers, policy["allowed"], policy["outcome"])
    execution_handoff = {
        "mode": "dry_run" if body.mode in {"DRY_RUN", "PLAN_ONLY"} else "approval_gated_handoff",
        "channel": ADAPTERS[body.source]["execution_channel"],
        "adapter": body.source,
        "direct_script_execution": False,
        "note": "Release Governance never executes arbitrary scripts directly; use governed ExecChannels or CI/CD adapters.",
    }
    evidence = {
        "deployment_id": deployment_id,
        "generated_at": now,
        "application": body.application,
        "environment": body.environment,
        "source": body.source,
        "change_ref": body.change_ref,
        "required_controls": required_controls,
        "required_claws": required_claws,
        "policy_decision": policy,
        "risk_score": risk,
        "blockers": blockers,
        "warnings": warnings,
        "artifacts": [_redact(a.model_dump()) for a in body.artifacts],
        "execution_handoff": execution_handoff,
    }
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    evidence["chain_of_custody"] = {
        "hash_algorithm": "sha256",
        "bundle_hash": hashlib.sha256(canonical.encode()).hexdigest(),
        "generated_by": CLAW_NAME,
    }
    return {
        "id": deployment_id,
        "status": status,
        "created_at": now,
        "updated_at": now,
        "requested_by": body.requested_by,
        "tenant_id": body.tenant_id,
        "approved_by": None,
        "application": body.application,
        "environment": body.environment,
        "source": body.source,
        "source_label": ADAPTERS[body.source]["label"],
        "deployment_type": body.deployment_type,
        "mode": body.mode,
        "template_id": body.template_id,
        "risk_score": risk,
        "blockers": blockers,
        "warnings": warnings,
        "required_controls": required_controls,
        "required_claws": required_claws,
        "rollback_required": body.mode not in {"DRY_RUN", "PLAN_ONLY"},
        "execution_handoff": execution_handoff,
        "policy_decision": policy,
        "request": _redact(body.model_dump()),
        "evidence": evidence,
    }


def _default_claws_for(body: DeploymentRequest) -> list[str]:
    claws = ["devclaw", "appclaw", "complianceclaw"]
    if body.source in {"aws_cli", "azure_cli", "gcloud_cli", "terraform_cloud", "argocd", "kubernetes", "helm"}:
        claws.extend(["cloudclaw", "configclaw", "accessclaw"])
    if body.deployment_type == "ai_stack":
        claws.extend(["arcclaw", "modelclaw", "dataclaw"])
    if body.mode in {"EMERGENCY_PATCH", "ROLLBACK_ONLY"}:
        claws.extend(["threatclaw", "recoveryclaw"])
    return sorted(set(claws))


def _policy_dict(decision: Any) -> dict[str, Any]:
    return {
        "allowed": bool(decision.allowed),
        "outcome": decision.outcome.value,
        "risk_score": decision.risk_score,
        "severity": decision.severity.value,
        "policy_name": decision.policy_name,
        "reason": decision.reason,
        "anomalies": decision.anomalies,
    }


def _principal(current_user: dict) -> str:
    return str(
        current_user.get("sub")
        or current_user.get("email")
        or current_user.get("id")
        or "unknown"
    )


@router.get("/stats")
async def get_stats():
    counts = {"allowed": 0, "conditional": 0, "approval_required": 0, "blocked": 0, "executed": 0}
    for dep in DEPLOYMENTS.values():
        if dep["status"] in counts:
            counts[dep["status"]] += 1
    return {
        "total_deployments": len(DEPLOYMENTS),
        "by_status": counts,
        "templates": len(TEMPLATES),
        "adapters": len(ADAPTERS),
        "supported_sources": sorted(ADAPTERS.keys()),
    }


@router.get("/adapters")
async def get_adapters():
    return [{"id": key, **value} for key, value in sorted(ADAPTERS.items())]


@router.get("/providers")
async def get_providers():
    return [
        {
            "provider": key,
            "label": value["label"],
            "category": value["category"],
            "configured": True,
            "execution_channel": value["execution_channel"],
        }
        for key, value in sorted(ADAPTERS.items())
    ]


@router.get("/templates")
async def get_templates():
    return [{"id": key, **value} for key, value in sorted(TEMPLATES.items())]


@router.get("/findings")
async def get_findings(tenant_id: str = "default"):
    rows = []
    for dep in sorted(DEPLOYMENTS.values(), key=lambda item: item["created_at"], reverse=True):
        if dep.get("tenant_id", "default") != tenant_id:
            continue
        rows.append(
            {
                "id": dep["id"],
                "claw": CLAW_NAME,
                "provider": dep["source"],
                "title": f"{dep['application']} deployment gate: {dep['status']}",
                "description": "; ".join(dep.get("blockers") or dep.get("warnings") or ["release preflight completed"]),
                "category": "deployment_governance",
                "severity": "critical" if dep["risk_score"] >= 85 else "high" if dep["risk_score"] >= 70 else "medium",
                "status": "open" if dep["status"] in {"blocked", "approval_required", "conditional"} else "resolved",
                "resource_id": dep["id"],
                "resource_type": "deployment",
                "resource_name": dep["application"],
                "region": dep["request"].get("target_region"),
                "risk_score": dep["risk_score"],
                "actively_exploited": False,
                "remediation": "Resolve release blockers, add rollback evidence, and route execution through a governed channel.",
                "remediation_effort": "quick_win" if dep["risk_score"] < 70 else "medium_term",
                "external_id": dep["id"],
                "first_seen": dep["created_at"],
                "last_seen": dep["updated_at"],
            }
        )
    return rows


@router.post("/scan")
async def run_scan():
    """Compatibility scan endpoint for left-blade testing.

    Release Governance scans deployment definitions/templates rather than external findings.
    """
    return {
        "status": "completed",
        "findings_created": 0,
        "findings_updated": 0,
        "templates_checked": len(TEMPLATES),
        "adapters_checked": len(ADAPTERS),
        "message": "Release Governance deployment template/control catalog scan complete.",
    }


@router.get("/deployments")
async def list_deployments(limit: int = 50, tenant_id: str = "default"):
    rows = [
        dep for dep in sorted(DEPLOYMENTS.values(), key=lambda item: item["created_at"], reverse=True)
        if dep.get("tenant_id", "default") == tenant_id
    ]
    return rows[: max(1, min(limit, 200))]


@router.get("/deployments/{deployment_id}")
async def get_deployment(deployment_id: str, tenant_id: str = "default"):
    deployment = DEPLOYMENTS.get(deployment_id)
    if not deployment or deployment.get("tenant_id", "default") != tenant_id:
        raise HTTPException(status_code=404, detail="Deployment not found")
    return deployment


@router.get("/deployments/{deployment_id}/evidence")
async def get_evidence(deployment_id: str, tenant_id: str = "default"):
    deployment = DEPLOYMENTS.get(deployment_id)
    if not deployment or deployment.get("tenant_id", "default") != tenant_id:
        raise HTTPException(status_code=404, detail="Deployment not found")
    return deployment["evidence"]


@router.post("/preflight")
async def preflight_deployment(
    body: DeploymentRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    requester = _principal(current_user)
    body = body.model_copy(update={"requested_by": requester})
    template = _template_for(body)
    risk, blockers, warnings = _score_preflight(body, template)
    fabric = await enforce(
        db=db,
        request=ActionRequest(
            module=CLAW_NAME,
            actor_id=body.requested_by,
            actor_name=body.requested_by,
            actor_type="human",
            action="deployment_preflight",
            target=f"{body.application}:{body.environment}",
            target_type="deployment",
            context={
                "environment": body.environment,
                "source": body.source,
                "deployment_type": body.deployment_type,
                "mode": body.mode,
                "classification": body.classification,
                "risk_score": risk,
                "blockers": blockers,
                "enforce_ring_policy": body.mode not in {"DRY_RUN", "PLAN_ONLY"},
                "channel": ADAPTERS[body.source]["execution_channel"],
                "caller_role": "operator",
                "trust_score": 80,
            },
        ),
        ip_address=request.client.host if request.client else None,
    )
    record = _deployment_record(body, risk, blockers, warnings, _policy_dict(fabric))
    DEPLOYMENTS[record["id"]] = record
    return record


@router.post("/deployments/{deployment_id}/approve")
async def approve_deployment(
    deployment_id: str,
    body: ApprovalRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    deployment = DEPLOYMENTS.get(deployment_id)
    if not deployment or deployment.get("tenant_id", "default") != body.tenant_id:
        raise HTTPException(status_code=404, detail="Deployment not found")
    if deployment["status"] == "blocked":
        raise HTTPException(status_code=409, detail="Blocked deployments require a new clean preflight")
    approver = _principal(current_user)
    if approver == deployment["requested_by"]:
        raise HTTPException(status_code=403, detail="Self-approval is not allowed for deployment releases")
    decision = await enforce(
        db=db,
        request=ActionRequest(
            module=CLAW_NAME,
            actor_id=approver,
            actor_name=approver,
            actor_type="human",
            action="approve_deployment",
            target=deployment_id,
            target_type="deployment",
            context={
                "environment": deployment["environment"],
                "risk_score": deployment["risk_score"],
                "classification": deployment["request"].get("classification"),
                "caller_role": "approver",
                "trust_score": 85,
            },
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not decision.allowed:
        raise HTTPException(status_code=403, detail="Deployment approval blocked by Trust Fabric policy")
    deployment["approved_by"] = approver
    deployment["approval_note"] = body.note
    deployment["status"] = "approved"
    deployment["updated_at"] = datetime.utcnow().isoformat()
    deployment["evidence"]["approval"] = {
        "approved_by": approver,
        "approved_at": deployment["updated_at"],
        "policy_decision": _policy_dict(decision),
    }
    return deployment


@router.post("/deployments/{deployment_id}/execute")
async def execute_deployment(
    deployment_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = "default",
):
    deployment = DEPLOYMENTS.get(deployment_id)
    if not deployment or deployment.get("tenant_id", "default") != tenant_id:
        raise HTTPException(status_code=404, detail="Deployment not found")
    if deployment["status"] in {"blocked", "executed"}:
        raise HTTPException(status_code=409, detail=f"Deployment status does not allow execute: {deployment['status']}")
    if deployment["status"] == "approval_required" and not deployment.get("approved_by"):
        raise HTTPException(status_code=403, detail="Deployment requires approval before execution handoff")
    if deployment["risk_score"] >= 45 and not deployment.get("approved_by"):
        raise HTTPException(status_code=403, detail="Deployment requires approval before execution handoff")
    executor = _principal(current_user)

    decision = await enforce(
        db=db,
        request=ActionRequest(
            module=CLAW_NAME,
            actor_id=executor,
            actor_name=executor,
            actor_type="human",
            action="execute_deployment_handoff",
            target=deployment_id,
            target_type="deployment",
            context={
                "environment": deployment["environment"],
                "source": deployment["source"],
                "execution_channel": deployment["execution_handoff"]["channel"],
                "risk_score": deployment["risk_score"],
                "enforce_ring_policy": True,
                "channel": deployment["execution_handoff"]["channel"],
                "caller_role": "operator",
                "trust_score": 85,
            },
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not decision.allowed:
        raise HTTPException(status_code=403, detail="Deployment execution handoff blocked by Trust Fabric policy")
    now = datetime.utcnow().isoformat()
    deployment["status"] = "executed"
    deployment["updated_at"] = now
    deployment["execution_result"] = {
        "status": "handoff_ready",
        "executed_at": now,
        "direct_execution": False,
        "handoff": deployment["execution_handoff"],
        "policy_decision": _policy_dict(decision),
    }
    deployment["evidence"]["execution_result"] = deployment["execution_result"]
    return deployment


@router.post("/task", summary="Execute focused Release Governance swarm task")
async def run_release_task(payload: ReleaseTaskRequest, db: AsyncSession = Depends(get_db)):
    started = datetime.utcnow()
    body = DeploymentRequest(**{
        "requested_by": "swarm-releaseclaw",
        "source": payload.input.get("source", "custom"),
        "environment": payload.input.get("environment", "staging"),
        "application": payload.input.get("application", "swarm-target"),
        "change_ref": payload.input.get("change_ref", payload.swarm_job_id or "swarm"),
        "deployment_type": payload.input.get("deployment_type", "custom_script"),
        "mode": payload.input.get("mode", "PLAN_ONLY"),
        "template_id": payload.input.get("template_id"),
        "artifacts": payload.input.get("artifacts", []),
        "required_controls": payload.input.get("required_controls", []),
        "execution_plan": payload.input.get("execution_plan", []),
        "rollback_plan": payload.input.get("rollback_plan", []),
        "model_profile": payload.model_profile or payload.input.get("model_profile"),
        "classification": payload.classification,
    })
    template = _template_for(body)
    risk, blockers, warnings = _score_preflight(body, template)
    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    severity = "critical" if risk >= 85 else "high" if risk >= 70 else "medium" if risk >= 45 else "low"
    return {
        "task_id": f"release-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": CLAW_NAME,
        "status": "completed",
        "severity": severity,
        "confidence": 0.88,
        "risk_score": risk,
        "findings": [
            {
                "title": f"Deployment preflight: {body.application} → {body.environment}",
                "detail": f"{body.source} / {body.deployment_type} mode={body.mode}",
            }
        ],
        "evidence": [{"type": "release_preflight", "blockers": blockers, "warnings": warnings}],
        "recommended_actions": [
            "Run a ReleaseClaw preflight before production deployment",
            "Require rollback artifact and approval for high-risk release modes",
        ],
        "blocked_actions": blockers,
        "policy_decisions": [],
        "compliance_mappings": ["SOC2 CC8", "ISO 27001 A.8.32", "NIST CM-3"],
        "execution_time_ms": elapsed_ms,
        "data_source": "release_plan",
        "connector_state": "configured",
    }
