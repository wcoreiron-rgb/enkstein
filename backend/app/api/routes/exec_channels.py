"""
RegentClaw — Governed Execution Channels API

POST /exec/shell                    — Submit shell command for governed execution
POST /exec/browser                  — Submit browser task for governed execution
POST /exec/credential               — Request credential injection
POST /exec/production               — Submit production gate request

GET  /exec/requests                 — List all execution requests
GET  /exec/requests/{id}            — Request detail
POST /exec/requests/{id}/approve    — Approve a request
POST /exec/requests/{id}/reject     — Reject a request
POST /exec/requests/{id}/execute    — Execute an approved request (sandbox simulation)

GET  /exec/production-gates         — List production gate requests
POST /exec/production-gates         — Create production gate
POST /exec/production-gates/{id}/approve  — Approve production gate
POST /exec/production-gates/{id}/reject   — Reject production gate
POST /exec/production-gates/{id}/execute  — Execute approved production gate
POST /exec/production-gates/{id}/rollback — Rollback

GET  /exec/credentials              — Credential broker registry
POST /exec/credentials              — Register credential entry
PATCH /exec/credentials/{id}        — Update entry
DELETE /exec/credentials/{id}       — Remove entry

GET  /exec/stats                    — Execution statistics
"""
import secrets
import uuid
import asyncio
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.database import AsyncSessionLocal
from app.models.exec_channels import ExecRequest, CredentialBrokerEntry, ProductionGate
from app.services.exec_policy import evaluate_exec_request
from app.services.ring_policy import classify_ring, evaluate_ring
from app.services import secrets_manager
from app.core.deps import get_current_user
from app.trust_fabric import ActionRequest, enforce

router = APIRouter(prefix="/exec", tags=["exec-channels"])

PRODUCTION_APPROVALS_REQUIRED = 2
REQUEST_TTL_MINUTES = 60


# ─── helpers ─────────────────────────────────────────────────────────────────

def _req_out(r: ExecRequest) -> dict:
    return {
        "id":               r.id,
        "channel":          r.channel,
        "requested_by":     r.requested_by,
        "agent_id":         r.agent_id,
        "workflow_run_id":  r.workflow_run_id,
        "command":          r.command,
        "args":             r.args or [],
        "target_resource":  r.target_resource,
        "environment":      r.environment,
        "justification":    r.justification,
        "trust_score":      r.trust_score,
        "risk_level":       r.risk_level,
        "policy_decision":  r.policy_decision,
        "policy_flags":     r.policy_flags or [],
        "requires_approval": r.requires_approval,
        "approval_count":   r.approval_count,
        "approved_by_1":    r.approved_by_1,
        "approved_by_2":    r.approved_by_2,
        "status":           r.status,
        "exit_code":        r.exit_code,
        "stdout":           r.stdout,
        "stderr":           r.stderr,
        "output_summary":   r.output_summary,
        "duration_ms":      r.duration_ms,
        "credential_used":  r.credential_used,
        "created_at":       r.created_at.isoformat() if r.created_at else None,
        "approved_at":      r.approved_at.isoformat() if r.approved_at else None,
        "executed_at":      r.executed_at.isoformat() if r.executed_at else None,
        "completed_at":     r.completed_at.isoformat() if r.completed_at else None,
    }


def _gate_out(g: ProductionGate) -> dict:
    return {
        "id":                 g.id,
        "title":              g.title,
        "description":        g.description,
        "requested_by":       g.requested_by,
        "agent_id":           g.agent_id,
        "workflow_run_id":    g.workflow_run_id,
        "change_type":        g.change_type,
        "target_system":      g.target_system,
        "change_payload":     g.change_payload or {},
        "rollback_plan":      g.rollback_plan,
        "risk_assessment":    g.risk_assessment,
        "risk_level":         g.risk_level,
        "status":             g.status,
        "approvals_required": g.approvals_required,
        "approvals_received": g.approvals_received or [],
        "rejected_by":        g.rejected_by,
        "rejection_reason":   g.rejection_reason,
        "execution_log":      g.execution_log,
        "created_at":         g.created_at.isoformat() if g.created_at else None,
        "executed_at":        g.executed_at.isoformat() if g.executed_at else None,
        "completed_at":       g.completed_at.isoformat() if g.completed_at else None,
        "rolled_back_at":     g.rolled_back_at.isoformat() if g.rolled_back_at else None,
    }


def _cred_out(c: CredentialBrokerEntry) -> dict:
    return {
        "id":               c.id,
        "name":             c.name,
        "description":      c.description,
        "secret_path":      c.secret_path,
        "secret_type":      c.secret_type,
        "owner":            c.owner,
        "allowed_agents":   c.allowed_agents or [],
        "allowed_claws":    c.allowed_claws or [],
        "allowed_envs":     c.allowed_envs or [],
        "requires_approval": c.requires_approval,
        "max_uses_per_hour": c.max_uses_per_hour,
        "use_count":        c.use_count,
        "last_used_at":     c.last_used_at.isoformat() if c.last_used_at else None,
        "is_active":        c.is_active,
        "rotation_due":     c.rotation_due.isoformat() if c.rotation_due else None,
        "created_at":       c.created_at.isoformat() if c.created_at else None,
    }


def _create_exec_request(
    db: Session,
    channel: str,
    body: dict,
) -> dict:
    command     = body.get("command", body.get("url", body.get("secret_name", "")))
    environment = body.get("environment", "dev")
    policy      = evaluate_exec_request(
        channel      = channel,
        command      = command,
        environment  = environment,
        requested_by = body.get("requested_by", "unknown"),
        justification= body.get("justification", ""),
        agent_id     = body.get("agent_id", ""),
    )
    caller_role = body.get("caller_role", "viewer")

    # ── Ring policy (pure-sync, no DB/asyncio) ─────────────────────────────
    # Apply ring classification immediately so status is correct even if
    # the async Trust Fabric call below fails or is skipped.
    try:
        ring       = classify_ring(channel, channel)
        ring_result = evaluate_ring(ring, policy.get("trust_score", 0.0), caller_role)
        if not ring_result["allowed"] and not ring_result["requires_approval"]:
            policy["decision"]         = "blocked"
            policy["requires_approval"] = False
            policy.setdefault("policy_flags", []).append(
                f"trust_fabric:execution_ring_violation"
            )
        elif ring_result["requires_approval"]:
            policy["decision"]         = "requires_approval"
            policy["requires_approval"] = True
            policy.setdefault("policy_flags", []).append(
                f"trust_fabric:execution_ring_policy"
            )
    except Exception:
        pass  # ring_policy unavailable — fall through to legacy exec_policy result

    async def _run_enforce():
        async with AsyncSessionLocal() as adb:
            return await enforce(
                adb,
                ActionRequest(
                    module="exec_channels",
                    actor_id=body.get("agent_id", "") or body.get("requested_by", "unknown"),
                    actor_name=body.get("requested_by", "unknown"),
                    actor_type="agent" if body.get("agent_id") else "human",
                    action=channel,
                    target=body.get("target_resource", body.get("hostname", body.get("url", ""))),
                    target_type="execution_target",
                    context={
                        "channel": channel,
                        "environment": environment,
                        "enforce_ring_policy": True,
                        "caller_role": caller_role,
                        "trust_score": policy["trust_score"],
                    },
                ),
            )

    # asyncio.run() fails with RuntimeError if an event loop is already running
    # (e.g. inside pytest-asyncio). In that case, dispatch to a fresh thread
    # with its own event loop so the Trust Fabric ring check always executes.
    try:
        try:
            asyncio.get_running_loop()
            # Already inside a running loop — use a worker thread.
            import concurrent.futures

            def _in_thread():
                new_loop = asyncio.new_event_loop()
                try:
                    return new_loop.run_until_complete(_run_enforce())
                finally:
                    new_loop.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                tf_decision = pool.submit(_in_thread).result(timeout=10)
        except RuntimeError:
            # No running loop — safe to use asyncio.run().
            tf_decision = asyncio.run(_run_enforce())
    except Exception as exc:
        # Authoritative gate: fail closed if Trust Fabric cannot evaluate.
        raise HTTPException(
            status_code=503,
            detail={
                "policy_name": "trust_fabric_unavailable",
                "deny_reason": "Trust Fabric evaluation failed for execution request",
            },
        ) from exc

    policy["decision"] = (
        "blocked"
        if not tf_decision.allowed and tf_decision.outcome.value == "blocked"
        else "requires_approval"
        if tf_decision.outcome.value == "requires_approval"
        else "allowed"
    )
    policy["requires_approval"] = policy["decision"] == "requires_approval"
    policy["risk_level"] = tf_decision.severity.value
    tf_flags = list(policy.get("policy_flags", []))
    tf_flags.append(f"trust_fabric:{tf_decision.policy_name}")
    policy["policy_flags"] = tf_flags

    req = ExecRequest(
        id              = str(uuid.uuid4()),
        channel         = channel,
        requested_by    = body.get("requested_by", "unknown"),
        agent_id        = body.get("agent_id", ""),
        workflow_run_id = body.get("workflow_run_id", ""),
        command         = command,
        args            = body.get("args", []),
        target_resource = body.get("target_resource", body.get("hostname", body.get("url", ""))),
        environment     = environment,
        justification   = body.get("justification", ""),
        trust_score     = policy["trust_score"],
        risk_level      = policy["risk_level"],
        policy_decision = policy["decision"],
        policy_flags    = policy["policy_flags"],
        requires_approval = policy["requires_approval"],
        status          = "blocked" if policy["decision"] == "blocked" else
                          "pending_approval" if policy["requires_approval"] else "approved",
        credential_used = body.get("credential_name", ""),
        expires_at      = datetime.utcnow() + timedelta(minutes=REQUEST_TTL_MINUTES),
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    return _req_out(req)


# ─── shell channel ───────────────────────────────────────────────────────────

@router.post("/shell")
def submit_shell(body: dict, db: Session = Depends(get_db)):
    """
    Submit a shell command for governed execution.
    Required: command, requested_by, environment
    Optional: args, hostname, justification, agent_id, workflow_run_id
    """
    if "command" not in body:
        raise HTTPException(400, "Missing field: command")
    if "requested_by" not in body:
        raise HTTPException(400, "Missing field: requested_by")
    return _create_exec_request(db, "shell", body)


# ─── browser channel ─────────────────────────────────────────────────────────

@router.post("/browser")
def submit_browser(body: dict, db: Session = Depends(get_db)):
    """
    Submit a browser automation task for governed execution.
    Required: url (command field), requested_by, environment
    Optional: args, justification, agent_id
    """
    if "url" not in body and "command" not in body:
        raise HTTPException(400, "Missing field: url or command")
    if "requested_by" not in body:
        raise HTTPException(400, "Missing field: requested_by")
    body.setdefault("command", body.get("url", ""))
    return _create_exec_request(db, "browser", body)


# ─── credential channel ───────────────────────────────────────────────────────

@router.post("/credential")
def request_credential(body: dict, db: Session = Depends(get_db)):
    """
    Request a credential for secure injection into an agent run.
    Required: credential_name, requested_by, agent_id
    Optional: justification, environment
    """
    if "credential_name" not in body:
        raise HTTPException(400, "Missing field: credential_name")
    if "requested_by" not in body:
        raise HTTPException(400, "Missing field: requested_by")

    # Look up credential entry
    cred = db.query(CredentialBrokerEntry).filter(
        CredentialBrokerEntry.name == body["credential_name"],
        CredentialBrokerEntry.is_active == True,
    ).first()

    if not cred:
        raise HTTPException(404, f"Credential '{body['credential_name']}' not found in broker registry")

    # Check environment restriction
    allowed_envs = cred.allowed_envs or []
    env = body.get("environment", "dev")
    if allowed_envs and env not in allowed_envs:
        raise HTTPException(403, f"Credential not permitted in environment '{env}'")

    # Check agent restriction
    allowed_agents = cred.allowed_agents or []
    agent_id = body.get("agent_id", "")
    if allowed_agents and agent_id not in allowed_agents:
        raise HTTPException(403, "Agent not permitted to access this credential")

    body["command"] = f"credential:{cred.secret_path}"
    body.setdefault("requires_approval_override", cred.requires_approval)
    result = _create_exec_request(db, "credential", body)

    # Bump use count
    cred.use_count = (cred.use_count or 0) + 1
    cred.last_used_at = datetime.utcnow()
    db.commit()

    # Return redacted — never the actual secret value
    return {
        **result,
        "secret_path":   cred.secret_path,
        "secret_type":   cred.secret_type,
        "injected":      result["status"] == "approved",
        "note":          "Secret value is never returned via API — injected directly into agent runtime",
    }


# ─── production channel ───────────────────────────────────────────────────────

@router.post("/production")
def submit_production(body: dict, db: Session = Depends(get_db)):
    """
    Submit a production execution request (auto-creates a ProductionGate).
    Required: title, requested_by, change_type, target_system
    Optional: description, change_payload, rollback_plan, risk_assessment, workflow_run_id
    """
    required = ("title", "requested_by", "change_type", "target_system")
    for f in required:
        if f not in body:
            raise HTTPException(400, f"Missing field: {f}")

    gate = ProductionGate(
        id              = str(uuid.uuid4()),
        title           = body["title"],
        description     = body.get("description", ""),
        requested_by    = body["requested_by"],
        agent_id        = body.get("agent_id", ""),
        workflow_run_id = body.get("workflow_run_id", ""),
        change_type     = body["change_type"],
        target_system   = body["target_system"],
        change_payload  = body.get("change_payload", {}),
        rollback_plan   = body.get("rollback_plan", ""),
        risk_assessment = body.get("risk_assessment", ""),
        risk_level      = body.get("risk_level", "high"),
        status          = "pending_approval",
        approvals_required = PRODUCTION_APPROVALS_REQUIRED,
        approvals_received = [],
        expires_at      = datetime.utcnow() + timedelta(hours=24),
    )
    db.add(gate)
    db.commit()
    db.refresh(gate)
    return {**_gate_out(gate), "message": f"Production gate created. {PRODUCTION_APPROVALS_REQUIRED} approvals required."}


# ─── generic request management ──────────────────────────────────────────────

@router.get("/requests")
def list_requests(
    channel:    Optional[str] = Query(None),
    status:     Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(ExecRequest)
    if channel:     q = q.filter(ExecRequest.channel == channel)
    if status:      q = q.filter(ExecRequest.status == status)
    if risk_level:  q = q.filter(ExecRequest.risk_level == risk_level)
    if environment: q = q.filter(ExecRequest.environment == environment)
    total   = q.count()
    results = q.order_by(ExecRequest.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "requests": [_req_out(r) for r in results]}


@router.get("/requests/{req_id}")
def get_request(req_id: str, db: Session = Depends(get_db)):
    r = db.query(ExecRequest).filter(ExecRequest.id == req_id).first()
    if not r:
        raise HTTPException(404, "Request not found")
    return _req_out(r)


@router.post("/requests/{req_id}/approve")
def approve_request(
    req_id: str,
    body: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    r = db.query(ExecRequest).filter(ExecRequest.id == req_id).first()
    if not r:
        raise HTTPException(404, "Request not found")
    if r.status not in ("pending_approval",):
        raise HTTPException(400, f"Cannot approve request in status '{r.status}'")

    # Approver identity always comes from the JWT — never trusted from the client body
    approver = current_user.get("sub", "unknown")

    # Prevent self-approval — the person who triggered cannot also approve
    if approver == r.requested_by:
        raise HTTPException(403, "Self-approval not permitted — a different user must approve")

    # Prevent the same approver from approving twice
    if approver in (r.approved_by_1, r.approved_by_2):
        raise HTTPException(400, "You have already approved this request")

    new_count = (r.approval_count or 0) + 1
    if new_count == 1:
        r.approved_by_1 = approver
    else:
        r.approved_by_2 = approver

    r.approval_count = new_count
    r.approval_note  = body.get("note", "")
    r.approved_at    = datetime.utcnow()

    # Shell/browser channels require 2 approvals (matching PRODUCTION_APPROVALS_REQUIRED intent)
    needs_two = r.channel in ("shell", "browser", "credential")
    if needs_two and new_count < PRODUCTION_APPROVALS_REQUIRED:
        status_msg = f"Approval {new_count}/{PRODUCTION_APPROVALS_REQUIRED} recorded — waiting for second approver"
        # Stay in pending_approval until both sign off
    else:
        r.status   = "approved"
        status_msg = f"Request fully approved ({new_count} approval(s))"

    db.commit()
    return {"message": status_msg, "status": r.status, "approval_count": r.approval_count}


@router.post("/requests/{req_id}/reject")
def reject_request(req_id: str, body: dict, db: Session = Depends(get_db)):
    r = db.query(ExecRequest).filter(ExecRequest.id == req_id).first()
    if not r:
        raise HTTPException(404, "Request not found")
    r.status = "blocked"
    db.commit()
    return {"message": "Request rejected", "status": "blocked"}


@router.post("/requests/{req_id}/execute")
def execute_request(req_id: str, db: Session = Depends(get_db)):
    """
    Execute an approved request. In production this wires to a sandboxed runner.
    In this implementation we return a simulated execution result.
    """
    r = db.query(ExecRequest).filter(ExecRequest.id == req_id).first()
    if not r:
        raise HTTPException(404, "Request not found")
    if r.status != "approved":
        raise HTTPException(400, f"Request must be approved before execution (status: {r.status})")

    # Re-check Trust Fabric decision before execution (authoritative gate).
    try:
        async def _run_enforce_execute():
            async with AsyncSessionLocal() as adb:
                return await enforce(
                    adb,
                    ActionRequest(
                        module="exec_channels",
                        actor_id=r.agent_id or r.requested_by,
                        actor_name=r.requested_by,
                        actor_type="agent" if r.agent_id else "human",
                        action=r.channel,
                        target=r.target_resource,
                        target_type="execution_target",
                        context={
                            "channel": r.channel,
                            "environment": r.environment,
                            "enforce_ring_policy": True,
                            "caller_role": "admin",
                            "trust_score": float(r.trust_score or 50.0),
                        },
                    ),
                )

        tf_decision = asyncio.run(_run_enforce_execute())
        if not tf_decision.allowed:
            raise HTTPException(403, detail={
                "policy_name": tf_decision.policy_name,
                "deny_reason": tf_decision.reason,
            })
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "policy_name": "trust_fabric_unavailable",
                "deny_reason": "Trust Fabric evaluation failed during execution",
            },
        ) from exc

    import time, random
    start = time.time()

    # Simulated sandbox execution — no real shell access
    channel_outputs = {
        "shell":      ("# [SANDBOX] Command executed in isolated container\n# Output redacted per DLP policy", 0),
        "browser":    ("# [SANDBOX] Browser task completed\n# Screenshot captured and stored", 0),
        "credential": ("# Credential injected into agent runtime\n# Secret value was never returned via API", 0),
        "production": ("# Production change applied via governed pipeline\n# Change log written to audit trail", 0),
    }
    stdout_text, exit_code = channel_outputs.get(r.channel, ("# Executed", 0))
    duration = int((time.time() - start) * 1000) + random.randint(50, 350)

    r.status       = "completed"
    r.executed_at  = datetime.utcnow()
    r.completed_at = datetime.utcnow()
    r.exit_code    = exit_code
    r.stdout       = stdout_text
    r.duration_ms  = duration
    r.output_summary = f"Execution completed in {duration}ms — exit code {exit_code}"
    db.commit()
    return _req_out(r)


# ─── production gates ────────────────────────────────────────────────────────

@router.get("/production-gates")
def list_production_gates(
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(ProductionGate)
    if status:
        q = q.filter(ProductionGate.status == status)
    gates = q.order_by(ProductionGate.created_at.desc()).limit(100).all()
    return [_gate_out(g) for g in gates]


@router.get("/production-gates/{gate_id}")
def get_production_gate(gate_id: str, db: Session = Depends(get_db)):
    g = db.query(ProductionGate).filter(ProductionGate.id == gate_id).first()
    if not g:
        raise HTTPException(404, "Gate not found")
    return _gate_out(g)


@router.post("/production-gates/{gate_id}/approve")
def approve_production_gate(
    gate_id: str,
    body: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    g = db.query(ProductionGate).filter(ProductionGate.id == gate_id).first()
    if not g:
        raise HTTPException(404, "Gate not found")
    if g.status != "pending_approval":
        raise HTTPException(400, f"Gate is not pending approval (status: {g.status})")

    # Approver identity always comes from JWT.
    approver = current_user.get("sub", "unknown")
    if approver == g.requested_by:
        raise HTTPException(403, "Self-approval not permitted — a different user must approve")
    approvals = list(g.approvals_received or [])

    # Prevent same person approving twice
    if any(a.get("approver") == approver for a in approvals):
        raise HTTPException(400, "You have already approved this gate")

    approvals.append({
        "approver":  approver,
        "timestamp": datetime.utcnow().isoformat(),
        "note":      body.get("note", ""),
    })
    g.approvals_received = approvals

    if len(approvals) >= (g.approvals_required or PRODUCTION_APPROVALS_REQUIRED):
        g.status = "approved"
        message = f"Gate fully approved ({len(approvals)}/{g.approvals_required}). Ready to execute."
    else:
        message = f"Approval recorded ({len(approvals)}/{g.approvals_required}). Waiting for more approvals."

    db.commit()
    return {"message": message, "approvals_received": len(approvals), "status": g.status}


@router.post("/production-gates/{gate_id}/reject")
def reject_production_gate(
    gate_id: str,
    body: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    g = db.query(ProductionGate).filter(ProductionGate.id == gate_id).first()
    if not g:
        raise HTTPException(404, "Gate not found")
    g.status           = "rejected"
    g.rejected_by      = current_user.get("sub", "unknown")
    g.rejection_reason = body.get("reason", "")
    db.commit()
    return {"message": "Production gate rejected", "status": "rejected"}


@router.post("/production-gates/{gate_id}/execute")
def execute_production_gate(gate_id: str, db: Session = Depends(get_db)):
    g = db.query(ProductionGate).filter(ProductionGate.id == gate_id).first()
    if not g:
        raise HTTPException(404, "Gate not found")
    if g.status != "approved":
        raise HTTPException(400, f"Gate is not approved (status: {g.status})")

    # Re-check Trust Fabric before production execution (authoritative gate).
    try:
        async def _run_enforce_production():
            async with AsyncSessionLocal() as adb:
                return await enforce(
                    adb,
                    ActionRequest(
                        module="exec_channels",
                        actor_id=g.agent_id or g.requested_by,
                        actor_name=g.requested_by,
                        actor_type="agent" if g.agent_id else "human",
                        action="production",
                        target=g.target_system,
                        target_type="production_system",
                        context={
                            "channel": "production",
                            "environment": "prod",
                            "enforce_ring_policy": True,
                            "caller_role": "admin",
                            "trust_score": 50.0,
                            "change_type": g.change_type,
                        },
                    ),
                )

        tf_decision = asyncio.run(_run_enforce_production())
        if not tf_decision.allowed:
            raise HTTPException(
                403,
                detail={
                    "policy_name": tf_decision.policy_name,
                    "deny_reason": tf_decision.reason,
                },
            )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            503,
            detail={
                "policy_name": "trust_fabric_unavailable",
                "deny_reason": "Trust Fabric evaluation failed for production execution",
            },
        ) from exc

    g.status      = "completed"
    g.executed_at = datetime.utcnow()
    g.completed_at = datetime.utcnow()
    g.execution_log = (
        f"[{datetime.utcnow().isoformat()}] Production change executed via governed pipeline\n"
        f"Target: {g.target_system}\n"
        f"Change Type: {g.change_type}\n"
        f"Approvals: {', '.join(a['approver'] for a in (g.approvals_received or []))}\n"
        f"[COMPLETED] Change applied successfully"
    )
    db.commit()
    return {**_gate_out(g), "message": "Production change executed successfully"}


@router.post("/production-gates/{gate_id}/rollback")
def rollback_production_gate(gate_id: str, db: Session = Depends(get_db)):
    g = db.query(ProductionGate).filter(ProductionGate.id == gate_id).first()
    if not g:
        raise HTTPException(404, "Gate not found")
    if g.status not in ("completed", "executing"):
        raise HTTPException(400, "Can only roll back completed or executing gates")
    g.status        = "rolled_back"
    g.rolled_back_at = datetime.utcnow()
    g.execution_log += f"\n[{datetime.utcnow().isoformat()}] ROLLBACK executed — changes reverted"
    db.commit()
    return {"message": "Production gate rolled back", "status": "rolled_back"}


# ─── credential broker ───────────────────────────────────────────────────────

@router.get("/credentials")
def list_credentials(db: Session = Depends(get_db)):
    creds = db.query(CredentialBrokerEntry).all()
    return [_cred_out(c) for c in creds]


@router.post("/credentials")
def register_credential(body: dict, db: Session = Depends(get_db)):
    required = ("name", "secret_path")
    for f in required:
        if f not in body:
            raise HTTPException(400, f"Missing field: {f}")
    existing = db.query(CredentialBrokerEntry).filter(
        CredentialBrokerEntry.name == body["name"]
    ).first()
    if existing:
        raise HTTPException(409, "Credential name already registered")
    cred = CredentialBrokerEntry(
        id          = str(uuid.uuid4()),
        name        = body["name"],
        description = body.get("description", ""),
        secret_path = body["secret_path"],
        secret_type = body.get("secret_type", "api_key"),
        owner       = body.get("owner", "platform"),
        allowed_agents = body.get("allowed_agents", []),
        allowed_claws  = body.get("allowed_claws", []),
        allowed_envs   = body.get("allowed_envs", []),
        requires_approval = body.get("requires_approval", False),
        max_uses_per_hour = body.get("max_uses_per_hour", 0),
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return _cred_out(cred)


@router.patch("/credentials/{cred_id}")
def update_credential(cred_id: str, body: dict, db: Session = Depends(get_db)):
    cred = db.query(CredentialBrokerEntry).filter(CredentialBrokerEntry.id == cred_id).first()
    if not cred:
        raise HTTPException(404, "Credential not found")
    for k, v in body.items():
        if hasattr(cred, k) and k not in ("id", "use_count", "last_used_at", "created_at"):
            setattr(cred, k, v)
    db.commit()
    return _cred_out(cred)


@router.delete("/credentials/{cred_id}")
def delete_credential(cred_id: str, db: Session = Depends(get_db)):
    cred = db.query(CredentialBrokerEntry).filter(CredentialBrokerEntry.id == cred_id).first()
    if not cred:
        raise HTTPException(404, "Credential not found")
    db.delete(cred)
    db.commit()
    return {"message": "Credential removed from broker"}


@router.get("/credentials/due-for-rotation")
def credentials_due_for_rotation(db: Session = Depends(get_db)):
    """
    List all credentials whose next_rotation_at (rotation_due) is in the past.
    These should be rotated immediately.
    """
    now = datetime.utcnow()
    due = (
        db.query(CredentialBrokerEntry)
        .filter(
            CredentialBrokerEntry.is_active == True,
            CredentialBrokerEntry.rotation_due != None,
            CredentialBrokerEntry.rotation_due <= now,
        )
        .all()
    )
    return {"count": len(due), "credentials": [_cred_out(c) for c in due]}


@router.post("/credentials/{cred_id}/rotate")
def rotate_credential(cred_id: str, db: Session = Depends(get_db)):
    """
    Rotate a credential:
      1. Look up the CredentialBrokerEntry by ID.
      2. Generate a new credential value appropriate for its type.
      3. Store the encrypted value via secrets_manager.
      4. Update last_rotated_at and next_rotation_at (30 days from now).
      5. Log an audit event.
      6. Return confirmation with next_rotation_at.
    """
    cred = db.query(CredentialBrokerEntry).filter(CredentialBrokerEntry.id == cred_id).first()
    if not cred:
        raise HTTPException(404, "Credential not found")
    if not cred.is_active:
        raise HTTPException(400, "Cannot rotate an inactive credential")

    # Generate new credential value based on type
    secret_type = (cred.secret_type or "api_key").lower()
    if secret_type in ("password",):
        # 24-char password-style: letters + digits + symbols
        alphabet = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#$%^&*()-_=+"
        )
        new_value = "".join(secrets.choice(alphabet) for _ in range(24))
    else:
        # api_key, token, ssh_key, certificate → URL-safe token
        new_value = secrets.token_urlsafe(32)

    # Store encrypted credential
    secrets_manager.store_credential(cred_id, {"api_key": new_value})

    # Update rotation timestamps
    now = datetime.utcnow()
    next_rotation = now + timedelta(days=30)
    cred.rotation_due = next_rotation
    cred.last_used_at = now   # repurpose last_used_at as last_rotated_at proxy

    db.commit()

    # Log audit event (best-effort — don't fail rotation if audit write fails)
    try:
        import json as _json
        from app.models.audit import AuditLog
        entry = AuditLog(
            actor="system",
            actor_type="system",
            action="credential_rotated",
            resource_type="credential",
            resource_id=cred_id,
            resource_name=cred.name,
            outcome="allowed",
            reason="Scheduled or manual credential rotation",
            detail_json=_json.dumps({
                "cred_id":         cred_id,
                "secret_type":     secret_type,
                "next_rotation_at": next_rotation.isoformat(),
            }),
            compliance_relevant=True,
        )
        db.add(entry)
        db.commit()
    except Exception:
        pass  # Audit failure must not abort the rotation

    return {
        "rotated":         True,
        "credential_id":   cred_id,
        "credential_name": cred.name,
        "secret_type":     secret_type,
        "next_rotation_at": next_rotation.isoformat(),
        "note": "New secret value stored encrypted — never returned via API",
    }


# ─── stats ───────────────────────────────────────────────────────────────────

@router.get("/stats")
def exec_stats(db: Session = Depends(get_db)):
    total     = db.query(ExecRequest).count()
    allowed   = db.query(ExecRequest).filter(ExecRequest.policy_decision == "allowed").count()
    blocked   = db.query(ExecRequest).filter(ExecRequest.policy_decision == "blocked").count()
    pending   = db.query(ExecRequest).filter(ExecRequest.status == "pending_approval").count()
    completed = db.query(ExecRequest).filter(ExecRequest.status == "completed").count()
    prod_gates       = db.query(ProductionGate).count()
    prod_pending     = db.query(ProductionGate).filter(ProductionGate.status == "pending_approval").count()
    prod_approved    = db.query(ProductionGate).filter(ProductionGate.status == "approved").count()
    prod_completed   = db.query(ProductionGate).filter(ProductionGate.status == "completed").count()
    creds_total      = db.query(CredentialBrokerEntry).count()
    creds_active     = db.query(CredentialBrokerEntry).filter(CredentialBrokerEntry.is_active == True).count()
    channel_breakdown = {}
    for ch in ("shell", "browser", "credential", "production"):
        channel_breakdown[ch] = db.query(ExecRequest).filter(ExecRequest.channel == ch).count()
    return {
        "total_requests":       total,
        "allowed":              allowed,
        "blocked":              blocked,
        "pending_approval":     pending,
        "completed":            completed,
        "channel_breakdown":    channel_breakdown,
        "production_gates":     prod_gates,
        "gates_pending":        prod_pending,
        "gates_approved":       prod_approved,
        "gates_completed":      prod_completed,
        "credential_entries":   creds_total,
        "credentials_active":   creds_active,
    }
