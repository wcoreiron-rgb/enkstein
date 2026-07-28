"""
Enkstein — Agent Runner Service (Async)
Every agent execution flows through Trust Fabric.

Execution modes:
  MONITOR    → observe, log findings, zero writes
  ASSIST     → propose actions, pause for human approval
  AUTONOMOUS → auto-execute pre-approved low-risk actions
"""
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.agent import Agent, AgentRun, RunStatus, ExecutionMode, RiskLevel, PlatformSettings
from app.models.event import Event, EventSeverity, EventOutcome
from app.schemas.agent import ApprovalAction

# Autonomy mode rank — higher number = more autonomous
_MODE_RANK: dict[str, int] = {
    ExecutionMode.MONITOR:    0,
    ExecutionMode.ASSIST:     1,
    ExecutionMode.APPROVAL:   2,
    ExecutionMode.AUTONOMOUS: 3,
    ExecutionMode.EMERGENCY:  -1,  # special — always allowed, but limits actions
}

# Pre-approved emergency containment action types
_EMERGENCY_ALLOWED_ACTIONS = {
    "isolate_host", "quarantine_host", "block_ip", "disable_account",
    "revoke_token", "block_llm_session", "freeze_user", "contain_endpoint",
}

logger = logging.getLogger("agent_runner")


# ─── Platform Settings Resolver ──────────────────────────────────────────────

async def _get_platform_settings(db: AsyncSession) -> Optional[PlatformSettings]:
    """Load the single-row platform settings record."""
    result = await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    settings = result.scalar_one_or_none()
    if not settings:
        # Create defaults on first access
        settings = PlatformSettings(id=1)
        db.add(settings)
        try:
            await db.commit()
            await db.refresh(settings)
        except Exception:
            pass
    return settings


def _apply_autonomy_ceiling(requested_mode: str, settings: Optional[PlatformSettings]) -> str:
    """
    Apply the platform autonomy ceiling to a requested mode.
    Emergency mode overrides everything.
    """
    if not settings:
        return requested_mode

    # Emergency mode forces EMERGENCY on all agents
    if settings.emergency_mode_active:
        return ExecutionMode.EMERGENCY

    # Cap mode at platform ceiling
    ceiling = settings.autonomy_ceiling or ExecutionMode.AUTONOMOUS
    req_rank = _MODE_RANK.get(requested_mode, 1)
    ceil_rank = _MODE_RANK.get(ceiling, 3)

    if req_rank > ceil_rank:
        return ceiling

    return requested_mode


# ─── Trust Fabric Check ───────────────────────────────────────────────────────

def _trust_fabric_check(agent: Agent, run: AgentRun) -> Tuple[str, str, float]:
    risk_map = {
        RiskLevel.LOW:      0.15,
        RiskLevel.MEDIUM:   0.45,
        RiskLevel.HIGH:     0.75,
        RiskLevel.CRITICAL: 0.95,
    }
    score = risk_map.get(agent.risk_level, 0.5)

    if (run.execution_mode == ExecutionMode.AUTONOMOUS
            and agent.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)):
        return "require_approval", "AUTO-HIGH-RISK-GATE", score

    if agent.risk_level == RiskLevel.CRITICAL:
        return "require_approval", "CRITICAL-AGENT-GATE", score

    if agent.status != "active":
        return "deny", "AGENT-STATUS-GATE", score

    return "allow", "DEFAULT-PERMIT", score


# ─── Simulated Agent Logic ────────────────────────────────────────────────────

async def _run_agent_scan(agent: Agent, db: AsyncSession) -> Dict[str, Any]:
    """
    Execute the agent's Capability Node scan and report what it actually found.

    This used to return a hardcoded scenario per node, so an agent reported the
    same two findings forever whether or not a connector existed. It now runs
    the node's real ``/scan`` — the same governed path the console uses — and
    reads back the findings that scan persisted.

    A node with nothing configured returns no findings and says so, rather than
    inventing them. Proposed actions are derived from real findings, so an
    approval queue can never contain an action for something that was not found.
    """
    from app.services.claw_scan_dispatch import run_node_scan

    try:
        scan = await run_node_scan(agent.claw, db)
    except Exception as exc:
        logger.exception("Agent %s scan failed", agent.id)
        raise RuntimeError(f"{agent.claw} scan failed: {type(exc).__name__}") from exc

    if scan is None:
        return {
            "findings": [],
            "proposed_actions": [],
            "summary": f"{agent.claw} has no scan entrypoint; nothing was executed.",
            "scan": {"status": "no_scan_entrypoint"},
        }

    findings = await _recent_findings(agent.claw, db)
    mode = scan.get("mode", "unknown")
    live = mode == "live"

    if not findings:
        summary = (
            f"{agent.name} completed a {mode} scan and found nothing to report."
        )
    else:
        criticals = sum(1 for f in findings if f["severity"] == "critical")
        highs = sum(1 for f in findings if f["severity"] == "high")
        origin = "connector-backed" if live else "unverified"
        summary = (
            f"{agent.name} completed a {mode} scan: {len(findings)} {origin} "
            f"finding(s), {criticals} critical and {highs} high."
        )

    return {
        "findings": findings,
        "proposed_actions": _actions_for(findings, live=live),
        "summary": summary,
        "scan": scan,
    }


async def _recent_findings(claw: str, db: AsyncSession, limit: int = 25) -> List[Dict[str, Any]]:
    """Read back the open findings this node's scan just refreshed."""
    from app.models.finding import Finding

    result = await db.execute(
        select(Finding)
        .where(Finding.claw == claw, Finding.status == "open")
        .order_by(Finding.risk_score.desc(), Finding.last_seen.desc())
        .limit(limit)
    )
    return [
        {
            "id": str(row.id),
            "severity": str(row.severity).lower(),
            "title": row.title,
            "provider": row.provider,
            "resource": row.resource_name or row.resource_id,
            "risk_score": row.risk_score,
            "data_origin": row.data_origin,
            "source_connector": row.source_connector,
        }
        for row in result.scalars().all()
    ]


def _actions_for(findings: List[Dict[str, Any]], *, live: bool) -> List[Dict[str, Any]]:
    """
    Propose remediation only for findings that came from a real connector.

    An action against demonstration data has no real target, so surfacing it
    for approval invites an operator to authorise a no-op.
    """
    if not live:
        return []
    actions: List[Dict[str, Any]] = []
    for finding in findings:
        if finding["severity"] not in ("critical", "high"):
            continue
        target = finding.get("resource")
        if not target:
            continue
        actions.append({
            "id": finding["id"],
            "type": "investigate_finding",
            "target": target,
            "risk": "high" if finding["severity"] == "critical" else "medium",
            "finding_id": finding["id"],
            "title": finding["title"],
        })
    return actions



# ─── Runner ───────────────────────────────────────────────────────────────────

class AgentRunner:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def execute(self, run_id: uuid.UUID) -> None:
        db = self.db

        result = await db.execute(select(AgentRun).where(AgentRun.id == run_id))
        run = result.scalar_one_or_none()
        if not run:
            logger.error(f"Run {run_id} not found")
            return

        agent_result = await db.execute(select(Agent).where(Agent.id == run.agent_id))
        agent = agent_result.scalar_one_or_none()
        if not agent:
            await self._fail(run, "Agent not found")
            return

        run.status = RunStatus.RUNNING
        run.started_at = datetime.now(timezone.utc)
        await db.commit()

        log_entries: List[Dict] = []

        try:
            # Step 0: Apply platform autonomy ceiling
            platform_settings = await _get_platform_settings(db)
            effective_mode = _apply_autonomy_ceiling(run.execution_mode, platform_settings)
            if effective_mode != run.execution_mode:
                log_entries.append({
                    "ts": _now(), "phase": "autonomy_ceiling",
                    "requested_mode": run.execution_mode,
                    "effective_mode": effective_mode,
                    "reason": (
                        "Emergency mode active" if platform_settings and platform_settings.emergency_mode_active
                        else f"Platform ceiling: {platform_settings.autonomy_ceiling if platform_settings else 'autonomous'}"
                    ),
                })
                run.execution_mode = effective_mode

            # Step 1: Trust Fabric pre-flight
            decision, policy_name, risk_score = _trust_fabric_check(agent, run)
            run.policy_decision = decision
            run.policy_name     = policy_name
            run.risk_score      = risk_score

            log_entries.append({
                "ts": _now(), "phase": "trust_fabric",
                "decision": decision, "policy": policy_name, "risk_score": risk_score,
            })

            if decision == "deny":
                run.status     = RunStatus.BLOCKED
                run.tf_blocked = True
                run.summary    = f"Blocked by Trust Fabric policy: {policy_name}"
                run.run_log    = json.dumps(log_entries)
                run.completed_at = datetime.now(timezone.utc)
                run.duration_sec = _elapsed(run.started_at)
                await self._update_agent_stats(agent, run)
                await db.commit()
                return

            # Step 2: Execute agent logic — external OpenClaw or built-in simulation
            if agent.is_external and agent.endpoint_url and agent.signing_secret:
                import json as _json
                from app.services.external_agent_dispatcher import (
                    dispatch as _ext_dispatch,
                    ExternalAgentError,
                )
                scopes = _json.loads(agent.allowed_scopes or '["*.read"]')
                try:
                    result_data = await _ext_dispatch(
                        agent_id       = str(agent.id),
                        run_id         = str(run.id),
                        endpoint_url   = agent.endpoint_url,
                        signing_secret = agent.signing_secret,
                        allowed_scopes = scopes,
                        context        = {"triggered_by": run.triggered_by},
                        dev_mode       = True,
                    )
                    # Log any scope-denied actions
                    scope_denied = result_data.pop("scope_denied_actions", [])
                    if scope_denied:
                        log_entries.append({
                            "ts": _now(), "phase": "scope_enforcement",
                            "denied_count": len(scope_denied),
                            "denied": [a["type"] for a in scope_denied],
                            "reason": "Actions outside agent declared scopes — stripped by Zero Trust dispatcher",
                        })
                except ExternalAgentError as ext_err:
                    # Update the agent's last error and fail the run
                    agent.endpoint_last_error = str(ext_err)
                    await self._fail(run, f"EXTERNAL_AGENT_ERROR: {ext_err}", log_entries)
                    return
                log_entries.append({
                    "ts": _now(), "phase": "external_dispatch",
                    "endpoint": agent.endpoint_url,
                    "findings": len(result_data.get("findings", [])),
                    "proposed_actions": len(result_data.get("proposed_actions", [])),
                    "signature": "verified",
                    "ssrf_check": "passed",
                })
            else:
                result_data = await _run_agent_scan(agent, db)

            findings       = result_data.get("findings", [])
            proposed_acts  = result_data.get("proposed_actions", [])
            summary        = result_data.get("summary", "")

            run.findings_count = len(findings)
            log_entries.append({
                "ts": _now(), "phase": "scan",
                "findings": len(findings), "proposed_actions": len(proposed_acts),
                # Carry the findings themselves, not just a tally. Without
                # this the run records that it found things but not what,
                # leaving the operator to reconstruct the result from the
                # Events feed by correlating on run id.
                "findings_detail": findings,
                # Provenance: whether these came from an authenticated
                # connector or are unverified demonstration data, and what each
                # provider actually returned.
                "scan": result_data.get("scan", {}),
            })

            # Step 3: Mode-gated action dispatch
            actions_taken:   List[Dict] = []
            actions_blocked: List[Dict] = []
            actions_pending: List[Dict] = []
            mode = run.execution_mode

            if mode == ExecutionMode.MONITOR:
                # Observe only — log everything, execute nothing
                actions_blocked = proposed_acts
                log_entries.append({"ts": _now(), "phase": "mode", "mode": "MONITOR",
                                    "note": "All actions suppressed — observe only"})

            elif mode == ExecutionMode.ASSIST:
                # Suggest and surface for human review — no auto-execution
                actions_pending = proposed_acts
                # Only park the run when there is genuinely something to decide.
                # Marking an empty run AWAITING left it in the approval queue
                # forever with no action an operator could ever act on.
                run.status = RunStatus.AWAITING if proposed_acts else RunStatus.COMPLETED
                log_entries.append({"ts": _now(), "phase": "mode", "mode": "ASSIST",
                                    "note": f"{len(proposed_acts)} actions surfaced for human review"})

            elif mode == ExecutionMode.APPROVAL:
                # Full action plan prepared — wait for explicit human approval before anything
                actions_pending = proposed_acts
                run.status = RunStatus.AWAITING if proposed_acts else RunStatus.COMPLETED
                log_entries.append({"ts": _now(), "phase": "mode", "mode": "APPROVAL",
                                    "note": f"Action plan ready — {len(proposed_acts)} actions await explicit approval"})

            elif mode == ExecutionMode.AUTONOMOUS:
                if decision == "require_approval":
                    actions_pending = proposed_acts
                    run.status = RunStatus.AWAITING
                    log_entries.append({"ts": _now(), "phase": "mode", "mode": "AUTONOMOUS",
                                        "note": "Elevated risk — require approval before executing"})
                else:
                    for act in proposed_acts:
                        if act.get("risk", "low") in ("low", "medium"):
                            actions_taken.append({**act, "executed_at": _now(), "result": "success"})
                            log_entries.append({"ts": _now(), "phase": "action", "action": act["type"], "result": "auto-executed"})
                        else:
                            actions_pending.append(act)
                            log_entries.append({"ts": _now(), "phase": "action", "action": act["type"],
                                                "note": "held — risk too high for autonomous execution"})
                    run.status = RunStatus.AWAITING if actions_pending else RunStatus.COMPLETED

            elif mode == ExecutionMode.EMERGENCY:
                # Emergency mode: only pre-approved containment actions are executed
                for act in proposed_acts:
                    action_type = act.get("type", "")
                    if action_type in _EMERGENCY_ALLOWED_ACTIONS:
                        actions_taken.append({**act, "executed_at": _now(), "result": "success",
                                              "note": "emergency_containment"})
                        log_entries.append({"ts": _now(), "phase": "action", "action": action_type,
                                            "result": "emergency-executed"})
                    else:
                        actions_blocked.append(act)
                        log_entries.append({"ts": _now(), "phase": "action", "action": action_type,
                                            "note": "blocked — not in emergency containment allowlist"})
                run.status = RunStatus.COMPLETED
                log_entries.append({"ts": _now(), "phase": "mode", "mode": "EMERGENCY",
                                    "note": f"{len(actions_taken)} containment actions executed, {len(actions_blocked)} blocked"})

            run.actions_taken   = json.dumps(actions_taken)
            run.actions_blocked = json.dumps(actions_blocked)
            run.actions_pending = json.dumps(actions_pending)
            run.summary         = summary
            run.run_log         = json.dumps(log_entries)

            if run.status not in (RunStatus.AWAITING, RunStatus.BLOCKED):
                run.status = RunStatus.COMPLETED

            run.completed_at = datetime.now(timezone.utc)
            run.duration_sec = _elapsed(run.started_at)
            await self._update_agent_stats(agent, run)

            # Broadcast run completion to live dashboard clients
            try:
                from app.services.ws_manager import broadcast_agent_run, broadcast_dashboard_refresh
                await broadcast_agent_run(
                    agent_name=agent.name,
                    run_id=str(run.id),
                    status=run.status.value,
                    findings_count=run.findings_count,
                    claw=agent.claw,
                )
                await broadcast_dashboard_refresh()
            except Exception:
                pass

            # Push findings + action outcomes to the Event telemetry bus
            await self._push_findings_to_events(
                agent, run, findings, actions_taken, actions_blocked, actions_pending
            )

            await db.commit()

        except Exception as exc:
            logger.exception(f"Agent run {run_id} failed: {exc}")
            await self._fail(run, str(exc), log_entries)

    async def process_approval(self, run_id: uuid.UUID, approval: ApprovalAction) -> None:
        db = self.db
        result = await db.execute(select(AgentRun).where(AgentRun.id == run_id))
        run = result.scalar_one_or_none()
        if not run or run.status != RunStatus.AWAITING:
            return

        pending = json.loads(run.actions_pending or "[]")
        taken   = json.loads(run.actions_taken   or "[]")
        blocked = json.loads(run.actions_blocked  or "[]")
        logs    = json.loads(run.run_log          or "[]")

        if approval.action_index >= len(pending):
            return

        action = pending.pop(approval.action_index)

        if approval.approved:
            taken.append({**action, "executed_at": _now(), "result": "approved-and-executed"})
            logs.append({"ts": _now(), "phase": "approval", "action": action["type"], "decision": "approved"})
        else:
            blocked.append({**action, "rejected_at": _now(), "result": "rejected"})
            logs.append({"ts": _now(), "phase": "approval", "action": action["type"], "decision": "rejected"})

        run.actions_pending = json.dumps(pending)
        run.actions_taken   = json.dumps(taken)
        run.actions_blocked = json.dumps(blocked)
        run.run_log         = json.dumps(logs)

        if not pending:
            run.status = RunStatus.COMPLETED
            run.completed_at = datetime.now(timezone.utc)
            agent_result = await db.execute(select(Agent).where(Agent.id == run.agent_id))
            agent = agent_result.scalar_one_or_none()
            if agent:
                await self._update_agent_stats(agent, run)

        await db.commit()

    async def _push_findings_to_events(
        self,
        agent: Agent,
        run: AgentRun,
        findings: List[Dict],
        actions_taken: List[Dict],
        actions_blocked: List[Dict],
        actions_pending: List[Dict],
    ) -> None:
        """
        Convert agent findings + action results into Event records so they
        appear on the portal Events page and Dashboard telemetry feed.
        """
        SEVERITY_MAP = {
            "informational": EventSeverity.INFO,
            "info":          EventSeverity.INFO,
            "low":           EventSeverity.LOW,
            "medium":        EventSeverity.MEDIUM,
            "high":          EventSeverity.HIGH,
            "critical":      EventSeverity.CRITICAL,
        }

        MODE_OUTCOME = {
            ExecutionMode.MONITOR:    EventOutcome.FLAGGED,
            ExecutionMode.ASSIST:     EventOutcome.REQUIRES_APPROVAL,
            ExecutionMode.AUTONOMOUS: EventOutcome.FLAGGED,
        }

        # One event per finding
        for finding in findings:
            sev_raw  = finding.get("severity", "info")
            severity = SEVERITY_MAP.get(sev_raw, EventSeverity.INFO)
            outcome  = MODE_OUTCOME.get(run.execution_mode, EventOutcome.FLAGGED)

            # Risk score from severity
            risk_map = {
                EventSeverity.INFO:     0.05,
                EventSeverity.LOW:      0.20,
                EventSeverity.MEDIUM:   0.45,
                EventSeverity.HIGH:     0.75,
                EventSeverity.CRITICAL: 0.95,
            }
            risk_score = risk_map.get(severity, 0.1)

            event = Event(
                source_module   = agent.claw,
                actor_id        = str(run.id),
                actor_name      = agent.name,
                actor_type      = "agent",
                action          = "agent_finding",
                target          = finding.get("title", "unknown"),
                target_type     = "finding",
                outcome         = outcome,
                severity        = severity,
                risk_score      = risk_score,
                policy_name     = run.policy_name,
                policy_reason   = f"Agent run {run.id} — {run.execution_mode} mode",
                description     = finding.get("title", ""),
                metadata_json   = json.dumps({
                    "finding":    finding,
                    "agent_id":   str(agent.id),
                    "run_id":     str(run.id),
                    "claw":       agent.claw,
                    "mode":       run.execution_mode,
                }),
                is_anomaly      = severity in (EventSeverity.HIGH, EventSeverity.CRITICAL),
                requires_review = severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)
                                  or run.execution_mode == ExecutionMode.ASSIST,
            )
            self.db.add(event)

        # One event per executed action (autonomous mode)
        for action in actions_taken:
            event = Event(
                source_module   = agent.claw,
                actor_id        = str(run.id),
                actor_name      = agent.name,
                actor_type      = "agent",
                action          = action.get("type", "unknown_action"),
                target          = action.get("target", "unknown"),
                target_type     = "remediation",
                outcome         = EventOutcome.ALLOWED,
                severity        = EventSeverity.INFO,
                risk_score      = 0.1,
                policy_name     = run.policy_name,
                policy_reason   = f"Auto-executed in AUTONOMOUS mode — run {run.id}",
                description     = f"Action '{action.get('type')}' executed on '{action.get('target')}'",
                metadata_json   = json.dumps({
                    "action":  action,
                    "run_id":  str(run.id),
                    "mode":    "autonomous",
                }),
                is_anomaly      = False,
                requires_review = False,
            )
            self.db.add(event)

        # One event per blocked action (monitor mode)
        for action in actions_blocked:
            event = Event(
                source_module   = agent.claw,
                actor_id        = str(run.id),
                actor_name      = agent.name,
                actor_type      = "agent",
                action          = action.get("type", "suppressed_action"),
                target          = action.get("target", "unknown"),
                target_type     = "suppressed_remediation",
                outcome         = EventOutcome.BLOCKED,
                severity        = EventSeverity.INFO,
                risk_score      = 0.05,
                policy_name     = run.policy_name,
                policy_reason   = f"Suppressed in MONITOR mode — run {run.id}",
                description     = f"Action '{action.get('type')}' suppressed (monitor mode)",
                metadata_json   = json.dumps({
                    "action": action,
                    "run_id": str(run.id),
                    "mode":   "monitor",
                }),
                is_anomaly      = False,
                requires_review = False,
            )
            self.db.add(event)

        # One event per pending action (assist mode)
        for action in actions_pending:
            event = Event(
                source_module   = agent.claw,
                actor_id        = str(run.id),
                actor_name      = agent.name,
                actor_type      = "agent",
                action          = action.get("type", "pending_action"),
                target          = action.get("target", "unknown"),
                target_type     = "pending_remediation",
                outcome         = EventOutcome.REQUIRES_APPROVAL,
                severity        = EventSeverity.MEDIUM,
                risk_score      = 0.4,
                policy_name     = run.policy_name,
                policy_reason   = f"Awaiting approval — run {run.id}",
                description     = f"Action '{action.get('type')}' pending analyst approval",
                metadata_json   = json.dumps({
                    "action": action,
                    "run_id": str(run.id),
                    "mode":   run.execution_mode,
                }),
                is_anomaly      = False,
                requires_review = True,
            )
            self.db.add(event)

    async def _fail(self, run: AgentRun, error: str, logs: Optional[List] = None) -> None:
        run.status        = RunStatus.FAILED
        run.error_message = error
        run.run_log       = json.dumps(logs or [])
        run.completed_at  = datetime.now(timezone.utc)
        if run.started_at:
            run.duration_sec = _elapsed(run.started_at)
        agent_result = await self.db.execute(select(Agent).where(Agent.id == run.agent_id))
        agent = agent_result.scalar_one_or_none()
        if agent:
            await self._update_agent_stats(agent, run)
        await self.db.commit()

    async def _update_agent_stats(self, agent: Agent, run: AgentRun) -> None:
        agent.total_runs     += 1
        agent.last_run_at     = run.completed_at or datetime.now(timezone.utc)
        agent.last_run_status = run.status.value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _elapsed(start: Optional[datetime]) -> float:
    if not start:
        return 0.0
    return (datetime.now(timezone.utc) - start).total_seconds()
