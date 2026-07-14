from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.marcellus.crypto import decrypt_json, digest_json, encrypt_json
from app.core.marcellus.plexus import create_plexus_message
from app.core.marcellus.registry import get_capability_node
from app.core.marcellus.runtime_schemas import (
    PlexusMessageCreate,
    ReflexDefinitionCreate,
    ReflexDefinitionRead,
    ReflexEvent,
    ReflexExecutionRead,
)
from app.core.marcellus.runtime_security import ensure_json_size, sensitive_paths
from app.core.marcellus.schemas import AuthorityCeiling
from app.models.marcellus import ReflexDefinition, ReflexExecution
from app.trust_fabric import ActionRequest, enforce


_AUTHORITY_RANK = {
    AuthorityCeiling.OBSERVE.value: 0,
    AuthorityCeiling.RECOMMEND.value: 1,
    AuthorityCeiling.APPROVAL_GATED_ACTION.value: 2,
}


def _definition_read(reflex: ReflexDefinition) -> ReflexDefinitionRead:
    return ReflexDefinitionRead.model_validate(reflex)


def _execution_read(execution: ReflexExecution) -> ReflexExecutionRead:
    return ReflexExecutionRead.model_validate(execution)


def _nested_value(payload: dict[str, Any], field: str) -> Any:
    current: Any = payload
    for segment in field.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current


def _condition_matches(actual: Any, operator: str, expected: Any) -> bool:
    try:
        if operator == "eq":
            return actual == expected
        if operator == "neq":
            return actual != expected
        if operator == "in":
            return actual in expected if isinstance(expected, list) else False
        if operator == "contains":
            return str(expected) in str(actual)
        if operator == "gte":
            return float(actual) >= float(expected)
        if operator == "lte":
            return float(actual) <= float(expected)
    except (TypeError, ValueError):
        return False
    return False


def _all_conditions_match(conditions_json: str, payload: dict[str, Any]) -> bool:
    try:
        conditions = json.loads(conditions_json)
    except (TypeError, json.JSONDecodeError):
        return False
    return all(
        _condition_matches(_nested_value(payload, condition["field"]), condition["operator"], condition.get("value"))
        for condition in conditions
    )


async def create_reflex_definition(
    db: AsyncSession,
    payload: ReflexDefinitionCreate,
    *,
    owner_id: str,
    owner_name: str,
    ip_address: str | None = None,
) -> ReflexDefinitionRead:
    node = get_capability_node(payload.node_id)
    if node is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unknown Capability Node")
    if _AUTHORITY_RANK[payload.authority.value] > _AUTHORITY_RANK[node.authority_ceiling.value]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Reflex authority exceeds Capability Node authority ceiling",
        )
    if payload.action_kind == "record_signal" and payload.authority != AuthorityCeiling.OBSERVE:
        raise HTTPException(status_code=422, detail="record_signal Reflexes must use observe authority")
    recipient_id = payload.action_config.get("recipient_node_id")
    if recipient_id and (get_capability_node(str(recipient_id)) is None or str(recipient_id) == payload.node_id):
        raise HTTPException(status_code=422, detail="Invalid Reflex recipient Capability Node")
    ensure_json_size(payload.action_config, 16384, "Reflex action configuration")
    unsafe = sensitive_paths(payload.action_config)
    if unsafe:
        raise HTTPException(status_code=422, detail="Reflex configuration cannot contain credential material")

    existing = await db.execute(
        select(ReflexDefinition).where(
            ReflexDefinition.tenant_id == payload.tenant_id,
            ReflexDefinition.name == payload.name,
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Reflex name already exists for tenant")

    decision = await enforce(
        db,
        ActionRequest(
            module="marcellus_reflex",
            actor_id=owner_id,
            actor_name=owner_name,
            actor_type="human",
            action="reflex_register",
            target=payload.node_id,
            target_type="capability_node",
            context={
                "tenant_id": payload.tenant_id,
                "event_type": payload.event_type,
                "authority": payload.authority.value,
                "action_kind": payload.action_kind,
            },
        ),
        ip_address=ip_address,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Reflex registration denied by Trust Fabric")

    reflex = ReflexDefinition(
        tenant_id=payload.tenant_id,
        name=payload.name,
        node_id=payload.node_id,
        event_type=payload.event_type,
        conditions_json=json.dumps([condition.model_dump() for condition in payload.conditions], separators=(",", ":")),
        action_kind=payload.action_kind,
        action_config_json=json.dumps(payload.action_config, separators=(",", ":"), sort_keys=True),
        authority=payload.authority.value,
        classification=payload.classification,
        owner_id=owner_id,
        max_runs_per_hour=payload.max_runs_per_hour,
        cooldown_seconds=payload.cooldown_seconds,
        expires_at=payload.expires_at,
    )
    db.add(reflex)
    await db.commit()
    await db.refresh(reflex)
    return _definition_read(reflex)


async def list_reflex_definitions(
    db: AsyncSession,
    tenant_id: str,
    *,
    active_only: bool = False,
) -> list[ReflexDefinitionRead]:
    statement = select(ReflexDefinition).where(ReflexDefinition.tenant_id == tenant_id)
    if active_only:
        statement = statement.where(ReflexDefinition.is_active.is_(True))
    result = await db.execute(statement.order_by(desc(ReflexDefinition.created_at)))
    return [_definition_read(reflex) for reflex in result.scalars().all()]


async def list_reflex_executions(
    db: AsyncSession,
    tenant_id: str,
    *,
    limit: int = 100,
) -> list[ReflexExecutionRead]:
    result = await db.execute(
        select(ReflexExecution)
        .where(ReflexExecution.tenant_id == tenant_id)
        .order_by(desc(ReflexExecution.created_at))
        .limit(limit)
    )
    return [_execution_read(execution) for execution in result.scalars().all()]


async def get_reflex_execution(
    db: AsyncSession,
    tenant_id: str,
    execution_id: uuid.UUID,
) -> ReflexExecutionRead:
    result = await db.execute(
        select(ReflexExecution).where(
            ReflexExecution.id == execution_id,
            ReflexExecution.tenant_id == tenant_id,
        )
    )
    execution = result.scalar_one_or_none()
    if execution is None:
        raise HTTPException(status_code=404, detail="Reflex execution not found")
    return _execution_read(execution)


async def _perform_effect(
    db: AsyncSession,
    reflex: ReflexDefinition,
    event: ReflexEvent,
    *,
    created_by: str,
    ip_address: str | None,
) -> dict[str, Any]:
    if reflex.action_kind == "record_signal":
        return {
            "effect": "record_signal",
            "event_id": event.event_id,
            "event_digest": digest_json(event.payload),
            "recorded": True,
        }

    config = json.loads(reflex.action_config_json)
    recipient_node_id = str(config["recipient_node_id"])
    idempotency_material = f"{reflex.id}:{event.event_id}".encode("utf-8")
    message = await create_plexus_message(
        db,
        PlexusMessageCreate(
            tenant_id=event.tenant_id,
            sender_node_id=reflex.node_id,
            recipient_node_id=recipient_node_id,
            message_type=str(config.get("message_type") or "reflex.notification")[:128],
            payload={
                "reflex_id": str(reflex.id),
                "event_id": event.event_id,
                "event_type": event.event_type,
                "event_digest": digest_json(event.payload),
                "event": event.payload,
            },
            classification=event.classification,
            ttl_seconds=int(config.get("ttl_seconds") or 900),
            idempotency_key=hashlib.sha256(idempotency_material).hexdigest(),
        ),
        created_by=created_by,
        actor_name=f"{reflex.name} Reflex",
        ip_address=ip_address,
    )
    return {
        "effect": "plexus_notify",
        "message_id": str(message.id),
        "message_status": message.status,
        "recipient_node_id": recipient_node_id,
    }


async def _rate_limit_reason(db: AsyncSession, reflex: ReflexDefinition) -> str | None:
    now = datetime.utcnow()
    if reflex.expires_at and reflex.expires_at.replace(tzinfo=None) <= now:
        return "Reflex has expired"
    if reflex.last_run_at and reflex.cooldown_seconds:
        next_allowed = reflex.last_run_at.replace(tzinfo=None) + timedelta(seconds=reflex.cooldown_seconds)
        if next_allowed > now:
            return "Reflex cooldown is active"
    count_result = await db.execute(
        select(func.count(ReflexExecution.id)).where(
            ReflexExecution.reflex_id == reflex.id,
            ReflexExecution.created_at >= now - timedelta(hours=1),
        )
    )
    if int(count_result.scalar_one() or 0) >= reflex.max_runs_per_hour:
        return "Reflex hourly execution budget exhausted"
    return None


async def evaluate_reflex_event(
    db: AsyncSession,
    event: ReflexEvent,
    *,
    requested_by: str,
    ip_address: str | None = None,
) -> list[ReflexExecutionRead]:
    ensure_json_size(event.payload, 65536, "Reflex event")
    result = await db.execute(
        select(ReflexDefinition).where(
            ReflexDefinition.tenant_id == event.tenant_id,
            ReflexDefinition.event_type == event.event_type,
            ReflexDefinition.is_active.is_(True),
        )
    )
    reflexes = list(result.scalars().all())
    executions: list[ReflexExecutionRead] = []

    for reflex in reflexes:
        if not _all_conditions_match(reflex.conditions_json, event.payload):
            continue
        prior_result = await db.execute(
            select(ReflexExecution).where(
                ReflexExecution.tenant_id == event.tenant_id,
                ReflexExecution.reflex_id == reflex.id,
                ReflexExecution.event_id == event.event_id,
            )
        )
        prior = prior_result.scalar_one_or_none()
        if prior is not None:
            executions.append(_execution_read(prior))
            continue

        event_ciphertext, event_digest = encrypt_json(event.payload)
        rate_reason = await _rate_limit_reason(db, reflex)
        if rate_reason:
            execution = ReflexExecution(
                tenant_id=event.tenant_id,
                reflex_id=reflex.id,
                event_id=event.event_id,
                event_type=event.event_type,
                event_ciphertext=event_ciphertext,
                event_digest=event_digest,
                status="rate_limited",
                requested_by=requested_by,
                policy_outcome="blocked",
                policy_name="reflex_resource_budget",
                policy_reason=rate_reason,
                risk_score=50.0,
                error_message=rate_reason,
                completed_at=datetime.utcnow(),
            )
            db.add(execution)
            await db.commit()
            await db.refresh(execution)
            executions.append(_execution_read(execution))
            continue

        channel = "production" if reflex.authority == AuthorityCeiling.APPROVAL_GATED_ACTION.value else "read"
        decision = await enforce(
            db,
            ActionRequest(
                module="marcellus_reflex",
                actor_id=reflex.node_id,
                actor_name=f"{reflex.name} Reflex",
                actor_type="capability_node",
                action="reflex_execute",
                target=reflex.action_kind,
                target_type="reflex_action",
                context={
                    "tenant_id": event.tenant_id,
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "event_digest": event_digest,
                    "authority": reflex.authority,
                    "channel": channel,
                    "enforce_ring_policy": True,
                    "trust_score": 70.0,
                    "caller_role": "agent",
                },
            ),
            ip_address=ip_address,
        )
        execution_status = (
            "running"
            if decision.allowed
            else "requires_approval"
            if decision.outcome.value == "requires_approval"
            else "blocked"
        )
        execution = ReflexExecution(
            tenant_id=event.tenant_id,
            reflex_id=reflex.id,
            event_id=event.event_id,
            event_type=event.event_type,
            event_ciphertext=event_ciphertext,
            event_digest=event_digest,
            status=execution_status,
            requested_by=requested_by,
            policy_outcome=decision.outcome.value,
            policy_name=decision.policy_name,
            policy_reason=decision.reason,
            risk_score=decision.risk_score,
            error_message=decision.reason if execution_status == "blocked" else None,
        )
        db.add(execution)
        await db.commit()
        await db.refresh(execution)

        if decision.allowed:
            try:
                effect = await _perform_effect(
                    db,
                    reflex,
                    event,
                    created_by=requested_by,
                    ip_address=ip_address,
                )
                execution.status = "completed"
                execution.result_json = json.dumps(effect, separators=(",", ":"), sort_keys=True)
                message_id = effect.get("message_id")
                execution.plexus_message_id = uuid.UUID(message_id) if message_id else None
                execution.completed_at = datetime.utcnow()
                reflex.run_count += 1
                reflex.last_run_at = datetime.utcnow()
            except Exception:
                execution.status = "failed"
                execution.error_message = "Bounded Reflex effect failed"
                execution.completed_at = datetime.utcnow()
            await db.commit()
            await db.refresh(execution)
        executions.append(_execution_read(execution))
    return executions


async def approve_reflex_execution(
    db: AsyncSession,
    tenant_id: str,
    execution_id: uuid.UUID,
    *,
    approver: str,
    approver_name: str,
    ip_address: str | None = None,
) -> ReflexExecutionRead:
    result = await db.execute(
        select(ReflexExecution).where(
            ReflexExecution.id == execution_id,
            ReflexExecution.tenant_id == tenant_id,
        )
    )
    execution = result.scalar_one_or_none()
    if execution is None:
        raise HTTPException(status_code=404, detail="Reflex execution not found")
    if execution.requested_by == approver:
        raise HTTPException(status_code=409, detail="Self-approval is not permitted")
    if execution.status != "requires_approval":
        raise HTTPException(status_code=409, detail="Reflex execution is not awaiting approval")
    reflex_result = await db.execute(select(ReflexDefinition).where(ReflexDefinition.id == execution.reflex_id))
    reflex = reflex_result.scalar_one_or_none()
    if reflex is None or not reflex.is_active:
        raise HTTPException(status_code=409, detail="Reflex definition is unavailable")

    decision = await enforce(
        db,
        ActionRequest(
            module="marcellus_reflex",
            actor_id=approver,
            actor_name=approver_name,
            actor_type="human",
            action="reflex_approve",
            target=str(execution.id),
            target_type="reflex_execution",
            context={"tenant_id": tenant_id, "reflex_id": str(reflex.id)},
        ),
        ip_address=ip_address,
    )
    if not decision.allowed:
        raise HTTPException(status_code=403, detail="Reflex approval denied by Trust Fabric")

    claimed = await db.execute(
        update(ReflexExecution)
        .where(
            ReflexExecution.id == execution_id,
            ReflexExecution.tenant_id == tenant_id,
            ReflexExecution.status == "requires_approval",
        )
        .values(status="running", approved_by=approver)
    )
    if claimed.rowcount != 1:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Reflex approval was already claimed")
    await db.commit()
    await db.refresh(execution)

    event = ReflexEvent(
        tenant_id=tenant_id,
        event_id=execution.event_id,
        event_type=execution.event_type,
        payload=decrypt_json(execution.event_ciphertext, execution.event_digest),
        classification=reflex.classification,
    )
    try:
        effect = await _perform_effect(
            db,
            reflex,
            event,
            created_by=execution.requested_by,
            ip_address=ip_address,
        )
        execution.status = "completed"
        execution.result_json = json.dumps(effect, separators=(",", ":"), sort_keys=True)
        message_id = effect.get("message_id")
        execution.plexus_message_id = uuid.UUID(message_id) if message_id else None
        execution.completed_at = datetime.utcnow()
        reflex.run_count += 1
        reflex.last_run_at = datetime.utcnow()
    except Exception:
        execution.status = "failed"
        execution.error_message = "Approved Reflex effect failed"
        execution.completed_at = datetime.utcnow()
    await db.commit()
    await db.refresh(execution)
    return _execution_read(execution)
