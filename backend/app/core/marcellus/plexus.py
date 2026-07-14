from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import and_, desc, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.marcellus.crypto import decrypt_json, encrypt_json, sign_envelope, verify_envelope
from app.core.marcellus.registry import get_capability_node
from app.core.marcellus.runtime_schemas import PlexusMessageCreate, PlexusMessageRead
from app.core.marcellus.runtime_security import ensure_json_size
from app.models.marcellus import PlexusMessage
from app.trust_fabric import ActionRequest, enforce


def _expired(value: datetime) -> bool:
    return value.replace(tzinfo=None) <= datetime.utcnow()


def _message_read(message: PlexusMessage, include_payload: bool = False) -> PlexusMessageRead:
    payload = None
    if include_payload:
        payload = decrypt_json(message.payload_ciphertext, message.payload_digest)
    return PlexusMessageRead(
        id=message.id,
        tenant_id=message.tenant_id,
        sender_node_id=message.sender_node_id,
        recipient_node_id=message.recipient_node_id,
        message_type=message.message_type,
        classification=message.classification,
        correlation_id=message.correlation_id,
        trace_id=message.trace_id,
        parent_message_id=message.parent_message_id,
        idempotency_key=message.idempotency_key,
        payload_digest=message.payload_digest,
        payload=payload,
        signature=message.signature,
        signature_algorithm=message.signature_algorithm,
        key_id=message.key_id,
        status=message.status,
        policy_outcome=message.policy_outcome,
        policy_name=message.policy_name,
        policy_reason=message.policy_reason,
        risk_score=message.risk_score,
        created_by=message.created_by,
        approved_by=message.approved_by,
        rejection_reason=message.rejection_reason,
        created_at=message.created_at,
        expires_at=message.expires_at,
        delivered_at=message.delivered_at,
        processed_at=message.processed_at,
    )


async def create_plexus_message(
    db: AsyncSession,
    payload: PlexusMessageCreate,
    *,
    created_by: str,
    actor_name: str,
    ip_address: str | None = None,
) -> PlexusMessageRead:
    sender = get_capability_node(payload.sender_node_id)
    recipient = get_capability_node(payload.recipient_node_id)
    if sender is None or recipient is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unknown Capability Node")
    if sender.id == recipient.id:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Plexus sender and recipient must differ")
    ensure_json_size(payload.payload, 65536, "Plexus payload")

    if payload.idempotency_key:
        result = await db.execute(
            select(PlexusMessage).where(
                PlexusMessage.tenant_id == payload.tenant_id,
                PlexusMessage.idempotency_key == payload.idempotency_key,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return _message_read(existing, include_payload=True)

    now = datetime.utcnow()
    message_id = uuid.uuid4()
    correlation_id = payload.correlation_id or str(message_id)
    trace_id = payload.trace_id or secrets.token_hex(16)
    nonce = secrets.token_hex(24)
    expires_at = now + timedelta(seconds=payload.ttl_seconds)
    ciphertext, payload_digest = encrypt_json(payload.payload)

    decision = await enforce(
        db,
        ActionRequest(
            module="marcellus_plexus",
            actor_id=payload.sender_node_id,
            actor_name=actor_name,
            actor_type="capability_node",
            action="plexus_send",
            target=payload.recipient_node_id,
            target_type="capability_node",
            context={
                "tenant_id": payload.tenant_id,
                "classification": payload.classification,
                "message_type": payload.message_type,
                "payload_digest": payload_digest,
                "created_by": created_by,
            },
        ),
        ip_address=ip_address,
    )

    if decision.allowed:
        message_status = "delivered"
    elif decision.outcome.value == "requires_approval":
        message_status = "requires_approval"
    else:
        message_status = "rejected"

    envelope = {
        "message_id": str(message_id),
        "tenant_id": payload.tenant_id,
        "sender_node_id": payload.sender_node_id,
        "recipient_node_id": payload.recipient_node_id,
        "message_type": payload.message_type,
        "classification": payload.classification,
        "correlation_id": correlation_id,
        "trace_id": trace_id,
        "parent_message_id": payload.parent_message_id,
        "payload_digest": payload_digest,
        "nonce": nonce,
        "created_at": now.isoformat(timespec="microseconds"),
        "expires_at": expires_at.isoformat(timespec="microseconds"),
    }
    envelope_json, signature, algorithm, key_id = sign_envelope(envelope)
    message = PlexusMessage(
        id=message_id,
        tenant_id=payload.tenant_id,
        sender_node_id=payload.sender_node_id,
        recipient_node_id=payload.recipient_node_id,
        message_type=payload.message_type,
        classification=payload.classification,
        correlation_id=correlation_id,
        trace_id=trace_id,
        parent_message_id=payload.parent_message_id,
        idempotency_key=payload.idempotency_key,
        nonce=nonce,
        payload_ciphertext=ciphertext,
        payload_digest=payload_digest,
        envelope_json=envelope_json,
        signature=signature,
        signature_algorithm=algorithm,
        key_id=key_id,
        status=message_status,
        policy_outcome=decision.outcome.value,
        policy_name=decision.policy_name,
        policy_reason=decision.reason,
        risk_score=decision.risk_score,
        created_by=created_by,
        rejection_reason=None if message_status != "rejected" else decision.reason,
        created_at=now,
        expires_at=expires_at,
        delivered_at=now if message_status == "delivered" else None,
    )
    db.add(message)
    await db.commit()
    await db.refresh(message)
    return _message_read(message, include_payload=True)


async def get_plexus_message(
    db: AsyncSession,
    tenant_id: str,
    message_id: uuid.UUID,
    *,
    include_payload: bool = True,
) -> PlexusMessageRead:
    result = await db.execute(
        select(PlexusMessage).where(
            PlexusMessage.id == message_id,
            PlexusMessage.tenant_id == tenant_id,
        )
    )
    message = result.scalar_one_or_none()
    if message is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plexus message not found")
    if message.status in {"delivered", "requires_approval"} and _expired(message.expires_at):
        message.status = "expired"
        message.rejection_reason = "Message TTL expired"
        await db.commit()
    return _message_read(message, include_payload=include_payload)


async def list_plexus_messages(
    db: AsyncSession,
    tenant_id: str,
    *,
    node_id: str | None = None,
    inbox_only: bool = False,
    limit: int = 100,
) -> list[PlexusMessageRead]:
    conditions = [PlexusMessage.tenant_id == tenant_id]
    if node_id and inbox_only:
        conditions.extend(
            [PlexusMessage.recipient_node_id == node_id, PlexusMessage.status == "delivered"]
        )
    elif node_id:
        conditions.append(
            or_(PlexusMessage.sender_node_id == node_id, PlexusMessage.recipient_node_id == node_id)
        )
    result = await db.execute(
        select(PlexusMessage).where(and_(*conditions)).order_by(desc(PlexusMessage.created_at)).limit(limit)
    )
    messages = list(result.scalars().all())
    dirty = False
    for message in messages:
        if message.status in {"delivered", "requires_approval"} and _expired(message.expires_at):
            message.status = "expired"
            message.rejection_reason = "Message TTL expired"
            dirty = True
    if dirty:
        await db.commit()
    return [_message_read(message) for message in messages]


async def approve_plexus_message(
    db: AsyncSession,
    tenant_id: str,
    message_id: uuid.UUID,
    *,
    approver: str,
    approver_name: str,
    ip_address: str | None = None,
) -> PlexusMessageRead:
    result = await db.execute(
        select(PlexusMessage).where(
            PlexusMessage.id == message_id,
            PlexusMessage.tenant_id == tenant_id,
        )
    )
    message = result.scalar_one_or_none()
    if message is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plexus message not found")
    if message.created_by == approver:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Self-approval is not permitted")
    if message.status != "requires_approval":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Message is not awaiting approval")
    if _expired(message.expires_at):
        message.status = "expired"
        message.rejection_reason = "Message TTL expired before approval"
        await db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Message has expired")

    decision = await enforce(
        db,
        ActionRequest(
            module="marcellus_plexus",
            actor_id=approver,
            actor_name=approver_name,
            actor_type="human",
            action="plexus_approve",
            target=str(message.id),
            target_type="plexus_message",
            context={"tenant_id": tenant_id, "sender_node_id": message.sender_node_id},
        ),
        ip_address=ip_address,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Plexus approval denied by Trust Fabric")
    claimed = await db.execute(
        update(PlexusMessage)
        .where(
            PlexusMessage.id == message_id,
            PlexusMessage.tenant_id == tenant_id,
            PlexusMessage.status == "requires_approval",
        )
        .values(status="delivered", approved_by=approver, delivered_at=datetime.utcnow())
    )
    if claimed.rowcount != 1:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Message approval was already claimed")
    await db.commit()
    await db.refresh(message)
    return _message_read(message)


async def acknowledge_plexus_message(
    db: AsyncSession,
    tenant_id: str,
    message_id: uuid.UUID,
    recipient_node_id: str,
) -> PlexusMessageRead:
    result = await db.execute(
        select(PlexusMessage).where(
            PlexusMessage.id == message_id,
            PlexusMessage.tenant_id == tenant_id,
        )
    )
    message = result.scalar_one_or_none()
    if message is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plexus message not found")
    if message.recipient_node_id != recipient_node_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Recipient identity mismatch")
    if message.status != "delivered":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Message is not deliverable")
    if _expired(message.expires_at):
        message.status = "expired"
        message.rejection_reason = "Message TTL expired"
        await db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Message has expired")

    verified = verify_envelope(message.envelope_json, message.signature, message.key_id)
    try:
        decrypt_json(message.payload_ciphertext, message.payload_digest)
    except ValueError:
        verified = False
    if not verified:
        message.status = "rejected"
        message.rejection_reason = "Envelope signature or payload digest verification failed"
        await db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Message verification failed")

    message.status = "processed"
    message.processed_at = datetime.utcnow()
    await db.commit()
    await db.refresh(message)
    return _message_read(message, include_payload=True)
