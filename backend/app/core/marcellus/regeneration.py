from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.marcellus.crypto import (
    canonical_json,
    decrypt_json,
    digest_json,
    encrypt_json,
    sign_envelope,
    verify_envelope,
)
from app.core.marcellus.registry import get_capability_node
from app.core.marcellus.runtime_schemas import (
    CapabilityNodeRuntimeRead,
    CheckpointVerification,
    NodeCheckpointCreate,
    NodeCheckpointRead,
    RegenerationRunRead,
)
from app.core.marcellus.runtime_security import ensure_json_size, sensitive_paths
from app.models.marcellus import CapabilityNodeRuntime, NodeCheckpoint, RegenerationRun
from app.trust_fabric import ActionRequest, enforce


def _checkpoint_read(checkpoint: NodeCheckpoint) -> NodeCheckpointRead:
    return NodeCheckpointRead(
        id=checkpoint.id,
        tenant_id=checkpoint.tenant_id,
        node_id=checkpoint.node_id,
        version=checkpoint.version,
        state_digest=checkpoint.state_digest,
        manifest=json.loads(checkpoint.manifest_json),
        manifest_digest=checkpoint.manifest_digest,
        signature=checkpoint.signature,
        signature_algorithm=checkpoint.signature_algorithm,
        key_id=checkpoint.key_id,
        status=checkpoint.status,
        created_by=checkpoint.created_by,
        created_at=checkpoint.created_at,
        verified_at=checkpoint.verified_at,
    )


def _run_read(run: RegenerationRun) -> RegenerationRunRead:
    return RegenerationRunRead.model_validate(run)


async def create_checkpoint(
    db: AsyncSession,
    payload: NodeCheckpointCreate,
    *,
    created_by: str,
    created_by_name: str,
    ip_address: str | None = None,
) -> NodeCheckpointRead:
    if get_capability_node(payload.node_id) is None:
        raise HTTPException(status_code=422, detail="Unknown Capability Node")
    state = payload.state
    manifest = payload.manifest.model_dump()
    ensure_json_size(state, 131072, "Checkpoint state")
    ensure_json_size(manifest, 65536, "Checkpoint manifest")
    unsafe = sensitive_paths(state) + sensitive_paths(manifest)
    if unsafe:
        raise HTTPException(
            status_code=422,
            detail="Checkpoint cannot contain credentials or secret material",
        )

    decision = await enforce(
        db,
        ActionRequest(
            module="marcellus_regeneration",
            actor_id=created_by,
            actor_name=created_by_name,
            actor_type="human",
            action="checkpoint_create",
            target=payload.node_id,
            target_type="capability_node",
            context={"tenant_id": payload.tenant_id, "state_fields": sorted(state.keys())},
        ),
        ip_address=ip_address,
    )
    if not decision.allowed:
        raise HTTPException(status_code=403, detail="Checkpoint creation denied by Trust Fabric")

    version_result = await db.execute(
        select(func.max(NodeCheckpoint.version)).where(
            NodeCheckpoint.tenant_id == payload.tenant_id,
            NodeCheckpoint.node_id == payload.node_id,
        )
    )
    version = int(version_result.scalar_one_or_none() or 0) + 1
    checkpoint_id = uuid.uuid4()
    now = datetime.utcnow()
    ciphertext, state_digest = encrypt_json(state)
    manifest_json = canonical_json(manifest)
    manifest_digest = digest_json(manifest)
    envelope = {
        "checkpoint_id": str(checkpoint_id),
        "tenant_id": payload.tenant_id,
        "node_id": payload.node_id,
        "version": version,
        "state_digest": state_digest,
        "manifest_digest": manifest_digest,
        "created_at": now.isoformat(timespec="microseconds"),
    }
    envelope_json, signature, algorithm, key_id = sign_envelope(envelope)
    checkpoint = NodeCheckpoint(
        id=checkpoint_id,
        tenant_id=payload.tenant_id,
        node_id=payload.node_id,
        version=version,
        state_ciphertext=ciphertext,
        state_digest=state_digest,
        manifest_json=manifest_json,
        manifest_digest=manifest_digest,
        envelope_json=envelope_json,
        signature=signature,
        signature_algorithm=algorithm,
        key_id=key_id,
        status="active",
        created_by=created_by,
        created_at=now,
    )
    db.add(checkpoint)
    await db.commit()
    await db.refresh(checkpoint)
    return _checkpoint_read(checkpoint)


async def list_checkpoints(
    db: AsyncSession,
    tenant_id: str,
    *,
    node_id: str | None = None,
    limit: int = 100,
) -> list[NodeCheckpointRead]:
    statement = select(NodeCheckpoint).where(NodeCheckpoint.tenant_id == tenant_id)
    if node_id:
        statement = statement.where(NodeCheckpoint.node_id == node_id)
    result = await db.execute(statement.order_by(desc(NodeCheckpoint.created_at)).limit(limit))
    return [_checkpoint_read(checkpoint) for checkpoint in result.scalars().all()]


async def _load_checkpoint(db: AsyncSession, tenant_id: str, checkpoint_id: uuid.UUID) -> NodeCheckpoint:
    result = await db.execute(
        select(NodeCheckpoint).where(
            NodeCheckpoint.id == checkpoint_id,
            NodeCheckpoint.tenant_id == tenant_id,
        )
    )
    checkpoint = result.scalar_one_or_none()
    if checkpoint is None:
        raise HTTPException(status_code=404, detail="Node checkpoint not found")
    return checkpoint


async def verify_checkpoint(
    db: AsyncSession,
    tenant_id: str,
    checkpoint_id: uuid.UUID,
    *,
    persist: bool = True,
) -> CheckpointVerification:
    checkpoint = await _load_checkpoint(db, tenant_id, checkpoint_id)
    checks: dict[str, bool] = {
        "active": checkpoint.status == "active",
        "known_node": get_capability_node(checkpoint.node_id) is not None,
        "signature": verify_envelope(checkpoint.envelope_json, checkpoint.signature, checkpoint.key_id),
        "manifest_digest": False,
        "state_digest": False,
        "secret_free": False,
    }
    failures: list[str] = []
    try:
        manifest = json.loads(checkpoint.manifest_json)
        checks["manifest_digest"] = digest_json(manifest) == checkpoint.manifest_digest
    except (TypeError, json.JSONDecodeError):
        manifest = {}
    try:
        state = decrypt_json(checkpoint.state_ciphertext, checkpoint.state_digest)
        checks["state_digest"] = True
        checks["secret_free"] = not bool(sensitive_paths(state) + sensitive_paths(manifest))
    except (TypeError, ValueError):
        state = {}

    for check, passed in checks.items():
        if not passed:
            failures.append(check)
    verified = all(checks.values())
    if verified and persist:
        checkpoint.verified_at = datetime.utcnow()
        await db.commit()
    return CheckpointVerification(
        checkpoint_id=checkpoint.id,
        verified=verified,
        checks=checks,
        failures=failures,
    )


async def start_regeneration(
    db: AsyncSession,
    tenant_id: str,
    checkpoint_id: uuid.UUID,
    *,
    requested_by: str,
    requested_by_name: str,
    caller_role: str,
    ip_address: str | None = None,
) -> RegenerationRunRead:
    checkpoint = await _load_checkpoint(db, tenant_id, checkpoint_id)
    if checkpoint.status != "active":
        raise HTTPException(status_code=409, detail="Checkpoint is not active")
    active_result = await db.execute(
        select(RegenerationRun).where(
            RegenerationRun.tenant_id == tenant_id,
            RegenerationRun.node_id == checkpoint.node_id,
            RegenerationRun.status.in_(("requires_approval", "running", "quarantined")),
        )
    )
    if active_result.scalars().first() is not None:
        raise HTTPException(status_code=409, detail="A Regeneration run is already active for this Node")

    decision = await enforce(
        db,
        ActionRequest(
            module="marcellus_regeneration",
            actor_id=requested_by,
            actor_name=requested_by_name,
            actor_type="human",
            action="regeneration_start",
            target=checkpoint.node_id,
            target_type="capability_node",
            context={
                "tenant_id": tenant_id,
                "checkpoint_id": str(checkpoint.id),
                "channel": "production",
                "enforce_ring_policy": True,
                "trust_score": 70.0,
                "caller_role": caller_role,
            },
        ),
        ip_address=ip_address,
    )
    run_status = (
        "running"
        if decision.allowed
        else "requires_approval"
        if decision.outcome.value == "requires_approval"
        else "blocked"
    )
    run = RegenerationRun(
        tenant_id=tenant_id,
        node_id=checkpoint.node_id,
        checkpoint_id=checkpoint.id,
        requested_by=requested_by,
        status=run_status,
        policy_outcome=decision.outcome.value,
        policy_name=decision.policy_name,
        policy_reason=decision.reason,
        risk_score=decision.risk_score,
        stages_json="[]",
        completed_at=datetime.utcnow() if run_status == "blocked" else None,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    if run_status == "running":
        await _perform_regeneration(db, run, checkpoint)
    return _run_read(run)


async def _record_stage(
    db: AsyncSession,
    run: RegenerationRun,
    stage: str,
    stage_status: str,
    detail: str,
) -> None:
    stages = json.loads(run.stages_json or "[]")
    stages.append(
        {
            "stage": stage,
            "status": stage_status,
            "detail": detail,
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        }
    )
    run.stages_json = json.dumps(stages, separators=(",", ":"))
    await db.commit()


async def _perform_regeneration(
    db: AsyncSession,
    run: RegenerationRun,
    checkpoint: NodeCheckpoint,
) -> None:
    run.status = "running"
    run.started_at = datetime.utcnow()
    await db.commit()
    try:
        runtime_result = await db.execute(
            select(CapabilityNodeRuntime).where(
                CapabilityNodeRuntime.tenant_id == run.tenant_id,
                CapabilityNodeRuntime.node_id == run.node_id,
            )
        )
        runtime = runtime_result.scalar_one_or_none()
        if runtime is not None:
            runtime.status = "contained"
        await _record_stage(db, run, "contain", "completed", "Prior logical runtime contained")

        verification = await verify_checkpoint(db, run.tenant_id, checkpoint.id)
        run.verification_json = verification.model_dump_json()
        if not verification.verified:
            raise ValueError("Checkpoint verification failed")
        await _record_stage(db, run, "checkpoint", "completed", "Signature, digest, manifest, and secret checks passed")

        generation = (runtime.generation + 1) if runtime else 1
        if runtime is None:
            runtime = CapabilityNodeRuntime(
                tenant_id=run.tenant_id,
                node_id=run.node_id,
                instance_id=secrets.token_hex(16),
                generation=generation,
                status="quarantined",
                state_ciphertext=checkpoint.state_ciphertext,
                state_digest=checkpoint.state_digest,
                manifest_json=checkpoint.manifest_json,
                checkpoint_id=checkpoint.id,
                health_json="{}",
            )
            db.add(runtime)
        else:
            runtime.instance_id = secrets.token_hex(16)
            runtime.generation = generation
            runtime.status = "quarantined"
            runtime.state_ciphertext = checkpoint.state_ciphertext
            runtime.state_digest = checkpoint.state_digest
            runtime.manifest_json = checkpoint.manifest_json
            runtime.checkpoint_id = checkpoint.id
            runtime.regenerated_at = datetime.utcnow()
        await _record_stage(db, run, "recreate", "completed", f"Created logical runtime generation {generation}")

        restored_state = decrypt_json(runtime.state_ciphertext, runtime.state_digest)
        await _record_stage(db, run, "rehydrate", "completed", f"Restored {len(restored_state)} governed state fields")

        health = {
            "identity": get_capability_node(runtime.node_id) is not None,
            "checkpoint_signature": verification.checks.get("signature", False),
            "state_integrity": digest_json(restored_state) == runtime.state_digest,
            "credentials_restored": False,
            "tenant_bound": runtime.tenant_id == run.tenant_id,
        }
        runtime.health_json = canonical_json(health)
        runtime.last_health_at = datetime.utcnow()
        await _record_stage(db, run, "verify", "completed", "Quarantine health checks passed")
        if not all(value is True for key, value in health.items() if key != "credentials_restored"):
            raise ValueError("Regenerated runtime health verification failed")

        runtime.status = "active"
        run.status = "completed"
        run.completed_at = datetime.utcnow()
        await _record_stage(db, run, "rejoin", "completed", "Capability Node runtime rejoined in active state")
        await db.commit()
    except Exception:
        run.status = "failed"
        run.error_message = "Regeneration failed verification and remains contained"
        run.completed_at = datetime.utcnow()
        await _record_stage(db, run, "failed", "failed", run.error_message)
        await db.commit()


async def approve_regeneration(
    db: AsyncSession,
    tenant_id: str,
    run_id: uuid.UUID,
    *,
    approver: str,
    approver_name: str,
    ip_address: str | None = None,
) -> RegenerationRunRead:
    result = await db.execute(
        select(RegenerationRun).where(
            RegenerationRun.id == run_id,
            RegenerationRun.tenant_id == tenant_id,
        )
    )
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Regeneration run not found")
    if run.requested_by == approver:
        raise HTTPException(status_code=409, detail="Self-approval is not permitted")
    if run.status != "requires_approval":
        raise HTTPException(status_code=409, detail="Regeneration run is not awaiting approval")

    decision = await enforce(
        db,
        ActionRequest(
            module="marcellus_regeneration",
            actor_id=approver,
            actor_name=approver_name,
            actor_type="human",
            action="regeneration_approve",
            target=str(run.id),
            target_type="regeneration_run",
            context={"tenant_id": tenant_id, "node_id": run.node_id},
        ),
        ip_address=ip_address,
    )
    if not decision.allowed:
        raise HTTPException(status_code=403, detail="Regeneration approval denied by Trust Fabric")
    claimed = await db.execute(
        update(RegenerationRun)
        .where(
            RegenerationRun.id == run_id,
            RegenerationRun.tenant_id == tenant_id,
            RegenerationRun.status == "requires_approval",
        )
        .values(status="running", approved_by=approver)
    )
    if claimed.rowcount != 1:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Regeneration approval was already claimed")
    await db.commit()
    await db.refresh(run)
    checkpoint = await _load_checkpoint(db, tenant_id, run.checkpoint_id)
    await _perform_regeneration(db, run, checkpoint)
    await db.refresh(run)
    return _run_read(run)


async def list_regeneration_runs(
    db: AsyncSession,
    tenant_id: str,
    *,
    limit: int = 100,
) -> list[RegenerationRunRead]:
    result = await db.execute(
        select(RegenerationRun)
        .where(RegenerationRun.tenant_id == tenant_id)
        .order_by(desc(RegenerationRun.created_at))
        .limit(limit)
    )
    return [_run_read(run) for run in result.scalars().all()]


async def get_regeneration_run(
    db: AsyncSession,
    tenant_id: str,
    run_id: uuid.UUID,
) -> RegenerationRunRead:
    result = await db.execute(
        select(RegenerationRun).where(
            RegenerationRun.id == run_id,
            RegenerationRun.tenant_id == tenant_id,
        )
    )
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Regeneration run not found")
    return _run_read(run)


async def list_node_runtimes(
    db: AsyncSession,
    tenant_id: str,
) -> list[CapabilityNodeRuntimeRead]:
    result = await db.execute(
        select(CapabilityNodeRuntime)
        .where(CapabilityNodeRuntime.tenant_id == tenant_id)
        .order_by(CapabilityNodeRuntime.node_id)
    )
    return [CapabilityNodeRuntimeRead.model_validate(runtime) for runtime in result.scalars().all()]
