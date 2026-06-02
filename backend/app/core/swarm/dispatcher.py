from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.claws.arcclaw.routes import ArcTaskRequest, run_arc_task
from app.claws.accessclaw.routes import AccessTaskRequest, run_access_task
from app.claws.attackpathclaw.routes import AttackPathTaskRequest, run_attackpath_task
from app.claws.appclaw.routes import AppTaskRequest, run_app_task
from app.claws.automationclaw.routes import AutomationTaskRequest, run_automation_task
from app.claws.cloudclaw.routes import CloudTaskRequest, run_cloud_task
from app.claws.complianceclaw.routes import ComplianceTaskRequest, run_compliance_task
from app.claws.configclaw.routes import ConfigTaskRequest, run_config_task
from app.claws.customclaw.routes import CustomTaskRequest, run_custom_task
from app.claws.dataclaw.routes import DataTaskRequest, run_data_task
from app.claws.devclaw.routes import DevTaskRequest, run_dev_task
from app.claws.endpointclaw.routes import EndpointTaskRequest, run_endpoint_task
from app.claws.exposureclaw.routes import ExposureTaskRequest, run_exposure_task
from app.claws.identityclaw.routes import IdentityTaskRequest, run_identity_task
from app.claws.intelclaw.routes import IntelTaskRequest, run_intel_task
from app.claws.logclaw.routes import LogTaskRequest, run_log_task
from app.claws.netclaw.routes import NetTaskRequest, run_net_task
from app.claws.privacyclaw.routes import PrivacyTaskRequest, run_privacy_task
from app.claws.recoveryclaw.routes import RecoveryTaskRequest, run_recovery_task
from app.claws.releaseclaw.routes import ReleaseTaskRequest, run_release_task
from app.claws.saasclaw.routes import SaaSTaskRequest, run_saas_task
from app.claws.threatclaw.routes import ThreatTaskRequest, run_task as run_threat_task
from app.claws.userclaw.routes import UserTaskRequest, run_user_task
from app.claws.insiderclaw.routes import InsiderTaskRequest, run_insider_task
from app.claws.vendorclaw.routes import VendorTaskRequest, run_vendor_task
from app.fabric.providers.agt import get_agt_adapter
from app.models.swarm import SwarmTask, SwarmTaskStatus
from app.services.memory_runtime import build_swarm_memory_context

logger = logging.getLogger("swarm_dispatcher")


def _severity_from_risk(risk_score: float) -> str:
    if risk_score >= 70:
        return "critical"
    if risk_score >= 50:
        return "high"
    if risk_score >= 25:
        return "medium"
    if risk_score > 0:
        return "low"
    return "info"


def _risk_from_severity(severity: str | None) -> float:
    sev = (severity or "").lower()
    if sev == "critical":
        return 90.0
    if sev == "high":
        return 75.0
    if sev == "medium":
        return 50.0
    if sev == "low":
        return 25.0
    return 0.0


def _normalize_risk_score(value: Any) -> float:
    try:
        score = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    if 0 < score <= 1:
        return round(score * 100, 2)
    return score


def _selected_finding_context(task_input: dict[str, Any]) -> dict[str, Any] | None:
    selected = task_input.get("selected_finding") or task_input.get("finding_context")
    if not isinstance(selected, dict):
        selected = {
            key: task_input.get(key)
            for key in ("finding_id", "claw", "provider", "title", "repo", "package", "severity", "risk_score")
            if task_input.get(key) is not None
        }
    if not selected or not selected.get("title"):
        return None
    normalized = dict(selected)
    if normalized.get("risk_score") is not None:
        normalized["risk_score"] = _normalize_risk_score(normalized.get("risk_score"))
    return normalized


def _focus_output_on_selected_finding(
    output: dict[str, Any],
    selected: dict[str, Any] | None,
    claw: str,
) -> dict[str, Any]:
    if not selected:
        output["risk_score"] = _normalize_risk_score(output.get("risk_score"))
        output["severity"] = output.get("severity") or _severity_from_risk(float(output.get("risk_score") or 0.0))
        return output

    prior_findings = output.get("findings") if isinstance(output.get("findings"), list) else []
    evidence = output.get("evidence") if isinstance(output.get("evidence"), list) else []
    selected_risk = max(
        _normalize_risk_score(selected.get("risk_score")),
        _risk_from_severity(selected.get("severity")),
    )
    output_risk = max(_normalize_risk_score(output.get("risk_score")), selected_risk)
    selected_title = str(selected.get("title") or "Selected finding")
    selected_provider = selected.get("provider") or "unknown provider"
    repo = selected.get("repo") or selected.get("repository") or selected.get("resource_name") or selected.get("resource_id")
    package = selected.get("package") or selected.get("dependency") or selected.get("component")

    detail_bits = [
        f"{claw} investigated the selected {selected_provider} finding",
        f"severity={selected.get('severity', 'unknown')}",
    ]
    if repo:
        detail_bits.append(f"repo={repo}")
    if package:
        detail_bits.append(f"package={package}")

    output["selected_finding"] = selected
    output["risk_score"] = output_risk
    output["severity"] = _severity_from_risk(output_risk)
    output["findings"] = [
        {
            "title": f"{claw}: {selected_title}",
            "detail": "; ".join(detail_bits),
            "selected_finding_id": selected.get("finding_id") or selected.get("id"),
            "provider": selected_provider,
            "repo": repo,
            "package": package,
            "severity": selected.get("severity"),
        }
    ]
    evidence.append({"type": "selected_finding_context", "finding": selected})
    if prior_findings:
        evidence.append({"type": "related_context_sample", "items": prior_findings[:3]})
    output["evidence"] = evidence
    output["investigation_scope"] = "selected_finding"
    return output


async def execute_task(db: AsyncSession, task: SwarmTask) -> dict[str, Any]:
    """
    Sprint 1 dispatcher.
    Uses deterministic local execution so swarm flows are testable before
    connector-backed task execution is fully implemented.
    """
    started = datetime.utcnow()
    task.status = SwarmTaskStatus.RUNNING
    task.started_at = started
    await db.commit()

    try:
        task_input = json.loads(task.input_json) if task.input_json else {}
    except Exception:
        task_input = {}
    selected_finding = _selected_finding_context(task_input)
    if selected_finding:
        task_input = {**task_input, "selected_finding": selected_finding, "investigation_scope": "selected_finding"}
    memory_context = await build_swarm_memory_context(db, task_input, task.claw)
    if memory_context.get("loaded"):
        task_input = {**task_input, "memory_context": memory_context}

    real_output = await _execute_real_task_if_supported(
        db=db,
        claw=task.claw,
        task_id=str(task.id),
        swarm_job_id=str(task.swarm_job_id),
        task_type=task.task_type,
        model_profile=task.model_profile,
        task_input=task_input,
    )
    if real_output is not None:
        output = _focus_output_on_selected_finding(real_output, selected_finding, task.claw)
        output.setdefault("execution_mode", "real_task_handler")
        output["memory_context_loaded"] = bool(memory_context.get("loaded"))
    else:
        # Fallback simulation for claws that have not shipped /task yet.
        logger.warning("Swarm task %s using simulated fallback for unsupported claw '%s'", task.id, task.claw)
        base = (sum(ord(c) for c in task.claw) % 30) + 40
        simulated_ms = base * 10
        await asyncio.sleep(min(simulated_ms / 1000.0, 0.45))

        risk_score = float(base)
        severity = _severity_from_risk(risk_score)
        confidence = round(min(0.99, 0.60 + (risk_score / 200.0)), 2)
        output = {
            "task_id": str(task.id),
            "swarm_job_id": str(task.swarm_job_id),
            "claw": task.claw,
            "status": "completed",
            "severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "findings": [
                {
                    "title": f"{task.claw} simulated analysis",
                    "detail": f"Deterministic fallback task result for {task.task_type}.",
                }
            ],
            "evidence": [],
            "recommended_actions": [],
            "blocked_actions": [],
            "policy_decisions": [],
            "compliance_mappings": [],
            "execution_time_ms": simulated_ms,
            "execution_mode": "simulated_fallback",
            "fallback_reason": f"Unsupported claw '{task.claw}' does not provide /task handler",
            "memory_context_loaded": bool(memory_context.get("loaded")),
        }
        output = _focus_output_on_selected_finding(output, selected_finding, task.claw)

    adapter = get_agt_adapter()
    secure_channel = adapter.send_secure_message(
        sender=task.claw,
        recipient="swarm_judge",
        message_type="TASK_RESULT",
        payload={
            "task_id": str(task.id),
            "swarm_job_id": str(task.swarm_job_id),
            "severity": output.get("severity"),
            "risk_score": output.get("risk_score"),
        },
    )
    if secure_channel.get("enabled"):
        output["secure_channel"] = secure_channel
        output["policy_decisions"].append(
            {
                "action": "E2E_MESSAGE",
                "outcome": secure_channel.get("status"),
                "provider": secure_channel.get("provider"),
            }
        )

    task.status = SwarmTaskStatus.COMPLETED
    task.severity = output.get("severity")
    task.confidence = output.get("confidence")
    task.risk_score = output.get("risk_score")
    task.execution_time_ms = int(output.get("execution_time_ms") or 0)
    task.output_json = json.dumps(output)
    task.completed_at = datetime.utcnow()
    await db.commit()
    return output


async def _execute_real_task_if_supported(
    db: AsyncSession,
    claw: str,
    task_id: str,
    swarm_job_id: str,
    task_type: str,
    model_profile: str | None,
    task_input: dict[str, Any],
) -> dict[str, Any] | None:
    payload = {
        "swarm_job_id": swarm_job_id,
        "task_type": task_type,
        "input": task_input,
        "classification": "internal",
        "model_profile": model_profile,
        "allowed_actions": ["read", "analyze", "recommend"],
    }

    if claw == "identityclaw":
        output = await run_identity_task(IdentityTaskRequest(**payload), db)
    elif claw == "cloudclaw":
        output = await run_cloud_task(CloudTaskRequest(**payload), db)
    elif claw == "threatclaw":
        output = await run_threat_task(ThreatTaskRequest(**payload), db)
    elif claw == "arcclaw":
        output = await run_arc_task(ArcTaskRequest(**payload), db)
    elif claw == "accessclaw":
        output = await run_access_task(AccessTaskRequest(**payload), db)
    elif claw == "dataclaw":
        output = await run_data_task(DataTaskRequest(**payload), db)
    elif claw == "devclaw":
        output = await run_dev_task(DevTaskRequest(**payload), db)
    elif claw == "endpointclaw":
        output = await run_endpoint_task(EndpointTaskRequest(**payload), db)
    elif claw == "appclaw":
        output = await run_app_task(AppTaskRequest(**payload), db)
    elif claw == "logclaw":
        output = await run_log_task(LogTaskRequest(**payload), db)
    elif claw == "netclaw":
        output = await run_net_task(NetTaskRequest(**payload), db)
    elif claw == "complianceclaw":
        output = await run_compliance_task(ComplianceTaskRequest(**payload), db)
    elif claw == "intelclaw":
        output = await run_intel_task(IntelTaskRequest(**payload), db)
    elif claw == "recoveryclaw":
        output = await run_recovery_task(RecoveryTaskRequest(**payload), db)
    elif claw == "releaseclaw":
        output = await run_release_task(ReleaseTaskRequest(**payload), db)
    elif claw == "saasclaw":
        output = await run_saas_task(SaaSTaskRequest(**payload), db)
    elif claw == "privacyclaw":
        output = await run_privacy_task(PrivacyTaskRequest(**payload), db)
    elif claw == "userclaw":
        output = await run_user_task(UserTaskRequest(**payload), db)
    elif claw == "insiderclaw":
        output = await run_insider_task(InsiderTaskRequest(**payload), db)
    elif claw == "vendorclaw":
        output = await run_vendor_task(VendorTaskRequest(**payload), db)
    elif claw == "attackpathclaw":
        output = await run_attackpath_task(AttackPathTaskRequest(**payload), db)
    elif claw == "automationclaw":
        output = await run_automation_task(AutomationTaskRequest(**payload), db)
    elif claw == "configclaw":
        output = await run_config_task(ConfigTaskRequest(**payload), db)
    elif claw == "exposureclaw":
        output = await run_exposure_task(ExposureTaskRequest(**payload), db)
    elif claw == "customclaw":
        output = await run_custom_task(CustomTaskRequest(**payload), db)
    else:
        return None

    # Normalize identity keys from claw-local task IDs to swarm task identity.
    output["task_id"] = task_id
    output["swarm_job_id"] = swarm_job_id
    output["claw"] = claw
    return output


async def execute_task_by_id(task_id: UUID) -> dict[str, Any] | None:
    """
    Execute a task in an isolated DB session.
    Used by background swarm execution for real parallelism.
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(SwarmTask).where(SwarmTask.id == task_id))
        task = result.scalar_one_or_none()
        if not task:
            return None
        return await execute_task(db, task)
