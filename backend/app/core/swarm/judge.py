from __future__ import annotations

import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.modelclaw.gateway import execute_cortex_gateway
from app.core.modelclaw.schemas import CortexGatewayRequest, CortexMessage

def judge_swarm_result(job_name: str, aggregate: dict[str, Any], task_count: int) -> dict[str, Any]:
    severity = aggregate.get("overall_severity", "info")
    confidence = float(aggregate.get("confidence", 0.0))
    risk_score = float(aggregate.get("risk_score", 0.0))
    requires_approval = severity in {"high", "critical"} or risk_score >= 60

    summary = (
        f"Swarm job '{job_name}' completed with {task_count} tasks. "
        f"Overall severity: {severity}. Confidence: {confidence:.2f}. "
        f"Average risk score: {risk_score:.1f}."
    )

    return {
        "overall_severity": severity,
        "confidence": confidence,
        "executive_summary": summary,
        "timeline": [],
        "root_cause": "Deterministic Sprint 1 execution baseline.",
        "blast_radius": "Limited to analyzed entities in the job input.",
        "top_findings": aggregate.get("top_findings", []),
        "recommended_actions": aggregate.get("recommended_actions", []),
        "requires_human_approval": requires_approval,
        "compliance_impact": [],
        "next_steps": [],
    }


async def judge_swarm_result_with_modelclaw(
    db: AsyncSession,
    job_name: str,
    aggregate: dict[str, Any],
    task_count: int,
    *,
    classification: str = "internal",
    swarm_job_id: str | None = None,
) -> dict[str, Any]:
    """
    Swarm Judge with Model Cortex synthesis.
    Falls back to deterministic judge when Model Cortex route is denied/unavailable.
    """
    judged = judge_swarm_result(job_name, aggregate, task_count)

    prompt = (
        "Summarize this swarm result for security operators as executive summary, root cause, "
        "blast radius, and next steps.\n"
        f"job_name={job_name}\n"
        f"aggregate={json.dumps(aggregate)}\n"
        f"task_count={task_count}\n"
    )
    try:
        routed = await execute_cortex_gateway(
            db,
            CortexGatewayRequest(
                mode="security",
                messages=[CortexMessage(role="user", content=prompt[:12000])],
                source="profile:swarm_judge_profile",
                capability="swarm_judge",
                data_classification=classification,
                workspace_id=swarm_job_id,
                context={"purpose": "swarm_summary_synthesis"},
            ),
        )
        if routed["status"] == "completed" and routed.get("response"):
            judged["executive_summary"] = routed["response"]
            judged["next_steps"] = [
                "Review Cortex Gateway synthesis",
                "Validate top findings and recommended actions",
            ]
            judged["judge_model"] = {
                "provider": routed.get("provider"),
                "model": routed.get("model"),
                "profile": str(routed.get("source") or "").removeprefix("profile:"),
                "policy_outcome": routed["governance"]["outcome"],
            }
        else:
            judged["judge_model"] = {
                "blocked": True,
                "policy_name": routed["governance"]["policy_name"],
                "reason": routed["governance"]["reason"],
            }
    except Exception as exc:  # pragma: no cover - defensive fallback
        judged["judge_model"] = {
            "error": "Cortex Gateway synthesis unavailable",
            "error_type": type(exc).__name__,
        }
    return judged
