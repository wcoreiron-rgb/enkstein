from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.claws.arcclaw.routes import ArcTaskRequest, run_arc_task
from app.claws.accessclaw.routes import AccessTaskRequest, run_access_task
from app.claws.appclaw.routes import AppTaskRequest, run_app_task
from app.claws.cloudclaw.routes import CloudTaskRequest, run_cloud_task
from app.claws.complianceclaw.routes import ComplianceTaskRequest, run_compliance_task
from app.claws.dataclaw.routes import DataTaskRequest, run_data_task
from app.claws.devclaw.routes import DevTaskRequest, run_dev_task
from app.claws.endpointclaw.routes import EndpointTaskRequest, run_endpoint_task
from app.claws.identityclaw.routes import IdentityTaskRequest, run_identity_task
from app.claws.logclaw.routes import LogTaskRequest, run_log_task
from app.claws.netclaw.routes import NetTaskRequest, run_net_task
from app.claws.threatclaw.routes import ThreatTaskRequest, run_task as run_threat_task
from app.fabric.providers.agt import get_agt_adapter
from app.models.swarm import SwarmTask, SwarmTaskStatus


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
        output = real_output
    else:
        # Fallback simulation for claws that have not shipped /task yet.
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
        }

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
