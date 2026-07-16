"""CoreOS — Dashboard summary endpoint."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from pydantic import BaseModel

from app.core.database import get_db
from app.models.identity import Identity
from app.models.module import Module, ModuleStatus
from app.models.connector import Connector, ConnectorStatus
from app.models.event import Event, EventOutcome, EventSeverity
from app.models.agent import Agent, AgentStatus, Schedule, ScheduleStatus
from app.models.swarm import SwarmJob, SwarmJobStatus
from app.models.channel_gateway import ChannelMessage
from app.models.exec_channels import ExecRequest
from app.models.audit import AuditLog
from app.claws.arcclaw.models import AIEvent
from app.claws.identityclaw.models import PrivilegedAction
from app.trust_fabric.agt_bridge import agt_status, scan_requirements

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


class DashboardStats(BaseModel):
    total_modules: int
    active_modules: int
    total_identities: int
    total_connectors: int
    pending_connectors: int
    high_risk_events: int
    blocked_actions_24h: int
    pending_approvals: int
    platform_risk_score: float
    recent_events: list[dict]


class ControlCenterSummary(BaseModel):
    pending_commands: int
    running_swarms: int
    blocked_swarms: int
    remote_agents_total: int
    remote_agents_online: int
    schedules_active: int
    schedules_total: int
    channel_messages_24h: int
    channel_blocked_24h: int
    channel_replies_sent_24h: int
    channel_replies_pending_24h: int
    execution_pending_approval: int
    execution_blocked_24h: int
    blocked_actions_24h: int


@router.get("", response_model=DashboardStats, summary="Platform-wide dashboard stats")
async def get_dashboard(db: AsyncSession = Depends(get_db)):
    from datetime import datetime, timedelta

    since_24h = datetime.utcnow() - timedelta(hours=24)

    total_modules = (await db.execute(select(func.count(Module.id)))).scalar() or 0
    active_modules = (await db.execute(select(func.count(Module.id)).where(Module.status == ModuleStatus.ACTIVE))).scalar() or 0
    total_identities = (await db.execute(select(func.count(Identity.id)))).scalar() or 0
    total_connectors = (await db.execute(select(func.count(Connector.id)))).scalar() or 0
    pending_connectors = (await db.execute(select(func.count(Connector.id)).where(Connector.status == ConnectorStatus.PENDING))).scalar() or 0

    high_risk = (
        await db.execute(
            select(func.count(Event.id))
            .where(Event.severity.in_([EventSeverity.HIGH, EventSeverity.CRITICAL]))
        )
    ).scalar() or 0

    blocked_24h = (
        await db.execute(
            select(func.count(Event.id))
            .where(Event.outcome == EventOutcome.BLOCKED)
            .where(Event.timestamp >= since_24h)
        )
    ).scalar() or 0

    pending_approvals = (
        await db.execute(select(func.count(PrivilegedAction.id)).where(PrivilegedAction.status == "pending"))
    ).scalar() or 0

    avg_risk = (await db.execute(select(func.avg(Event.risk_score)))).scalar() or 0.0

    # Recent 5 events
    recent_q = await db.execute(
        select(Event).order_by(desc(Event.timestamp)).limit(5)
    )
    recent_events = [
        {
            "id": str(e.id),
            "timestamp": e.timestamp.isoformat(),
            "module": e.source_module,
            "actor": e.actor_name,
            "action": e.action,
            "outcome": e.outcome.value,
            "severity": e.severity.value,
            "risk_score": e.risk_score,
        }
        for e in recent_q.scalars().all()
    ]

    return DashboardStats(
        total_modules=total_modules,
        active_modules=active_modules,
        total_identities=total_identities,
        total_connectors=total_connectors,
        pending_connectors=pending_connectors,
        high_risk_events=high_risk,
        blocked_actions_24h=blocked_24h,
        pending_approvals=pending_approvals,
        platform_risk_score=round(avg_risk, 2),
        recent_events=recent_events,
    )


@router.get("/agt-status", summary="Microsoft AGT integration status")
async def get_agt_status():
    """
    Returns AGT integration status and capability map.
    Shows which layers use AGT vs. Enkstein's built-in enforcement.
    """
    return agt_status()


@router.get("/supply-chain-scan", summary="Run AGT supply chain scan on backend dependencies")
async def run_supply_chain_scan():
    """
    Runs AGT SupplyChainGuard against the backend requirements.txt.
    Checks for typosquatting, outdated packages, and lockfile drift.
    """
    result = scan_requirements("/app/requirements.txt")
    return {
        "is_safe": result.is_safe,
        "risk_score": result.risk_score,
        "issues": result.issues,
        "typosquatting_hits": result.typosquatting_hits,
        "outdated_packages": result.outdated_packages,
        "agt_used": result.agt_used,
    }


@router.get("/control-center-summary", response_model=ControlCenterSummary, summary="Control Center unified summary")
async def get_control_center_summary(db: AsyncSession = Depends(get_db)):
    from datetime import datetime, timedelta

    # Several operational tables still use timezone-naive UTC columns. Keep the
    # summary cutoff naive as well so Postgres does not reject mixed comparisons.
    since_24h = datetime.utcnow() - timedelta(hours=24)

    pending_commands = (
        await db.execute(
            select(func.count(Event.id))
            .where(Event.source_module == "commandclaw")
            .where(Event.outcome == EventOutcome.REQUIRES_APPROVAL)
            .where(Event.timestamp >= since_24h)
        )
    ).scalar() or 0

    running_swarms = (
        await db.execute(
            select(func.count(SwarmJob.id)).where(
                SwarmJob.status.in_([SwarmJobStatus.PENDING, SwarmJobStatus.RUNNING])
            )
        )
    ).scalar() or 0
    blocked_swarms = (
        await db.execute(
            select(func.count(SwarmJob.id)).where(
                SwarmJob.status.in_([SwarmJobStatus.BLOCKED, SwarmJobStatus.FAILED, SwarmJobStatus.CANCELLED])
            )
        )
    ).scalar() or 0

    remote_agents_total = (
        await db.execute(select(func.count(Agent.id)).where(Agent.claw == "remoteagent"))
    ).scalar() or 0
    remote_agents_online = (
        await db.execute(
            select(func.count(Agent.id))
            .where(Agent.claw == "remoteagent")
            .where(Agent.status == AgentStatus.ACTIVE)
        )
    ).scalar() or 0

    schedules_total = (await db.execute(select(func.count(Schedule.id)))).scalar() or 0
    schedules_active = (
        await db.execute(select(func.count(Schedule.id)).where(Schedule.status == ScheduleStatus.ACTIVE))
    ).scalar() or 0

    channel_messages_24h = (
        await db.execute(
            select(func.count(ChannelMessage.id)).where(ChannelMessage.created_at >= since_24h)
        )
    ).scalar() or 0
    channel_blocked_24h = (
        await db.execute(
            select(func.count(ChannelMessage.id))
            .where(ChannelMessage.created_at >= since_24h)
            .where(ChannelMessage.policy_decision == "blocked")
        )
    ).scalar() or 0
    channel_replies_sent_24h = (
        await db.execute(
            select(func.count(ChannelMessage.id))
            .where(ChannelMessage.created_at >= since_24h)
            .where(ChannelMessage.response_sent == True)
        )
    ).scalar() or 0
    channel_replies_pending_24h = (
        await db.execute(
            select(func.count(ChannelMessage.id))
            .where(ChannelMessage.created_at >= since_24h)
            .where(ChannelMessage.channel_type.in_(["slack", "teams"]))
            .where(ChannelMessage.response_sent == False)
        )
    ).scalar() or 0

    execution_pending_approval = (
        await db.execute(select(func.count(ExecRequest.id)).where(ExecRequest.status == "pending"))
    ).scalar() or 0
    execution_blocked_24h = (
        await db.execute(
            select(func.count(ExecRequest.id))
            .where(ExecRequest.created_at >= since_24h)
            .where(ExecRequest.status == "blocked")
        )
    ).scalar() or 0

    blocked_actions_24h = (
        await db.execute(
            select(func.count(Event.id))
            .where(Event.outcome == EventOutcome.BLOCKED)
            .where(Event.timestamp >= since_24h)
        )
    ).scalar() or 0

    return ControlCenterSummary(
        pending_commands=pending_commands,
        running_swarms=running_swarms,
        blocked_swarms=blocked_swarms,
        remote_agents_total=remote_agents_total,
        remote_agents_online=remote_agents_online,
        schedules_active=schedules_active,
        schedules_total=schedules_total,
        channel_messages_24h=channel_messages_24h,
        channel_blocked_24h=channel_blocked_24h,
        channel_replies_sent_24h=channel_replies_sent_24h,
        channel_replies_pending_24h=channel_replies_pending_24h,
        execution_pending_approval=execution_pending_approval,
        execution_blocked_24h=execution_blocked_24h,
        blocked_actions_24h=blocked_actions_24h,
    )
