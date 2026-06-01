"""
RegentClaw — Messaging Channel Gateway API

POST /channel-gateway/slack/events          — Slack Events API webhook
POST /channel-gateway/teams/webhook         — Microsoft Teams outgoing webhook
POST /channel-gateway/webhook               — Generic webhook ingestion
POST /channel-gateway/email/inbound         — Email-to-command ingestion
POST /channel-gateway/cli/command           — CLI command ingestion
POST /channel-gateway/message               — Generic message ingestion (internal/test)
GET  /channel-gateway/messages              — Browse processed messages
GET  /channel-gateway/messages/{id}         — Message detail
GET  /channel-gateway/identities            — Channel identity registry
POST /channel-gateway/identities            — Register / update a channel identity
GET  /channel-gateway/configs               — Channel configs
POST /channel-gateway/configs               — Register a channel
PATCH /channel-gateway/configs/{id}         — Update a channel config
GET  /channel-gateway/stats                 — Gateway statistics
POST /channel-gateway/simulate              — Simulate a message (for testing without a real bot)
"""
import hmac
import hashlib
import time
import uuid
import logging
import re
import os
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Request, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.database import AsyncSessionLocal, get_db as get_async_db
from app.models.channel_gateway import ChannelMessage, ChannelIdentity, ChannelConfig
from app.api.routes.remote_control import (
    CommandApprovalRequest,
    CommandRejectionRequest,
    CommandRequest,
    _execute_command,
    approve_pending_command,
    reject_pending_command,
)
from app.services.channel_processor import dispatch_alert, process_message

router = APIRouter(prefix="/channel-gateway", tags=["channel-gateway"])
logger = logging.getLogger(__name__)


@asynccontextmanager
async def _channel_command_session():
    """
    Use the request-overridden async DB session in pytest, so tests and channel review
    actions share the same in-memory database. Default to AsyncSessionLocal otherwise.
    """
    if os.getenv("PYTEST_CURRENT_TEST"):
        try:
            from main import app  # local import to avoid circular import at module load

            override = app.dependency_overrides.get(get_async_db)
            if override is not None:
                agen = override()
                session = await anext(agen)
                try:
                    yield session
                finally:
                    await agen.aclose()
                return
        except Exception:
            # Fall through to default session factory if override wiring is unavailable.
            pass

    async with AsyncSessionLocal() as session:
        yield session


# ─── helpers ─────────────────────────────────────────────────────────────────

def _msg_out(m: ChannelMessage) -> dict:
    return {
        "id":               m.id,
        "channel_type":     m.channel_type,
        "channel_id":       m.channel_id,
        "channel_name":     m.channel_name,
        "sender_id":        m.sender_id,
        "sender_name":      m.sender_name,
        "sender_email":     m.sender_email,
        "message_text":     m.message_text,
        "identity_verified": m.identity_verified,
        "identity_risk":    m.identity_risk,
        "policy_decision":  m.policy_decision,
        "policy_flags":     m.policy_flags or [],
        "detected_intent":  m.detected_intent,
        "detected_claws":   m.detected_claws or [],
        "execution_status": m.execution_status,
        "workflow_run_id":  m.workflow_run_id,
        "agent_run_id":     m.agent_run_id,
        "response_text":    m.response_text,
        "response_sent":    m.response_sent,
        "created_at":       m.created_at.isoformat() if m.created_at else None,
        "processed_at":     m.processed_at.isoformat() if m.processed_at else None,
    }


def _identity_out(ci: ChannelIdentity) -> dict:
    return {
        "id":               ci.id,
        "channel_type":     ci.channel_type,
        "platform_user_id": ci.platform_user_id,
        "platform_email":   ci.platform_email,
        "platform_name":    ci.platform_name,
        "regentclaw_role":  ci.regentclaw_role,
        "is_trusted":       ci.is_trusted,
        "trust_score":      ci.trust_score,
        "allowed_claws":    ci.allowed_claws or [],
        "denied_claws":     ci.denied_claws or [],
        "max_autonomy":     ci.max_autonomy,
        "last_seen":        ci.last_seen.isoformat() if ci.last_seen else None,
    }


def _get_channel_identity(
    db: Session, channel_type: str, sender_id: str, sender_email: str
) -> dict | None:
    ci = (
        db.query(ChannelIdentity)
        .filter(
            ChannelIdentity.channel_type == channel_type,
            (ChannelIdentity.platform_user_id == sender_id)
            | (ChannelIdentity.platform_email == sender_email),
        )
        .first()
    )
    return _identity_out(ci) if ci else None


def _persist_message(db: Session, result: dict, channel_name: str = "") -> ChannelMessage:
    msg = ChannelMessage(
        id               = result["id"],
        channel_type     = result["channel_type"],
        channel_id       = result["channel_id"],
        channel_name     = channel_name,
        sender_id        = result["sender_id"],
        sender_name      = result["sender_name"],
        sender_email     = result["sender_email"],
        message_text     = result["message_text"],
        identity_verified = result["identity_verified"],
        identity_risk    = result["identity_risk"],
        policy_decision  = result["policy_decision"],
        policy_flags     = result["policy_flags"],
        detected_intent  = result["detected_intent"],
        detected_claws   = result["detected_claws"],
        execution_status = result["execution_status"],
        workflow_run_id  = result.get("workflow_run_id", ""),
        agent_run_id     = result.get("agent_run_id", ""),
        response_text    = result["response_text"],
        processed_at     = datetime.utcnow(),
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return msg


def _response_title(result: dict) -> str:
    decision = (result.get("policy_decision") or "processed").replace("_", " ").title()
    return f"RegentClaw {decision}"


async def _send_channel_response(db: Session, msg: ChannelMessage, result: dict) -> dict:
    """
    Deliver the normalized response back to configured Slack/Teams channels.
    Missing webhook config is explicit so operators can distinguish queued work
    from channel delivery gaps.
    """
    if msg.channel_type not in {"slack", "teams"}:
        return {"status": "skipped", "reason": "channel_type_not_supported"}
    if not msg.response_text:
        return {"status": "skipped", "reason": "empty_response"}

    config = (
        db.query(ChannelConfig)
        .filter(
            ChannelConfig.channel_type == msg.channel_type,
            ChannelConfig.channel_id == msg.channel_id,
            ChannelConfig.is_enabled == True,
        )
        .first()
    )
    if not config or not config.webhook_url:
        return {"status": "skipped", "reason": "missing_webhook_url"}

    delivered = await dispatch_alert(
        msg.channel_type,
        _response_title(result),
        msg.response_text,
        {"webhook_url": config.webhook_url, "color": "#0078D4"},
    )
    msg.response_sent = bool(delivered)
    db.commit()
    return {
        "status": "sent" if delivered else "failed",
        "channel_type": msg.channel_type,
        "channel_id": msg.channel_id,
        "message_id": msg.id,
    }


async def _ingest_normalized_message(
    db: Session,
    *,
    message_id: str,
    message_text: str,
    sender_id: str,
    sender_email: str,
    sender_name: str,
    channel_type: str,
    channel_id: str,
    channel_name: str,
) -> dict:
    ci = _get_channel_identity(db, channel_type, sender_id, sender_email)
    result = process_message(
        message_id=message_id,
        message_text=message_text,
        sender_id=sender_id,
        sender_email=sender_email,
        sender_name=sender_name,
        channel_type=channel_type,
        channel_id=channel_id,
        channel_identity=ci,
    )
    command_result = await _execute_channel_command(result, ci)
    _apply_command_outcome(result, command_result)
    msg = _persist_message(db, result, channel_name)
    outbound_delivery = await _send_channel_response(db, msg, result)
    return {
        **_msg_out(msg),
        "response": result["response_text"],
        "command_result": command_result,
        "outbound_delivery": outbound_delivery,
    }


def _map_intent(detected_intent: str) -> str:
    intents = [part.strip() for part in (detected_intent or "").split(",") if part.strip()]
    if not intents:
        return "channel_message"
    intent = intents[0]
    mapping = {
        "scan": "run_scan",
        "block": "contain",
        "rotate": "rotate_secret",
        "disable_account": "disable_account",
        "remediate": "remediate",
        "report": "status_report",
        "investigate": "investigate",
        "run_workflow": "run_workflow",
        "run_agent": "run_agent",
        "approve": "approve_action",
        "deny_action": "deny_action",
    }
    return mapping.get(intent, "channel_message")


def _extract_review_action(message_text: str) -> tuple[str, str] | None:
    """
    Parse simple chat-ops approvals:
      - approve <command_id>
      - reject <command_id>
      - deny <command_id>
    """
    text = (message_text or "").strip().lower()
    if not text:
        return None
    match = re.match(r"^(approve|reject|deny)\s+([a-z0-9_\-:.]+)$", text)
    if not match:
        return None
    action = match.group(1)
    command_id = match.group(2)
    if action == "deny":
        action = "reject"
    return action, command_id


def _build_command_request(
    result: dict,
    channel_identity: dict | None,
) -> CommandRequest:
    requester = result.get("sender_email") or result.get("sender_id", "channel-user")
    target = (
        (result.get("detected_claws") or [None])[0]
        or result.get("channel_id")
        or "regentclaw"
    )
    mode = "approval" if result.get("policy_decision") == "requires_approval" else "assist"
    return CommandRequest(
        command_id=f"chan_{result['id']}",
        source=result.get("channel_type", "channel"),
        requester=requester,
        tenant_id=(channel_identity or {}).get("tenant_id", "default"),
        intent=_map_intent(result.get("detected_intent", "")),
        target=str(target).lower(),
        scope=result.get("channel_id", "default"),
        mode=mode,
        classification="internal",
        payload={
            "message_id": result.get("id"),
            "message_text": result.get("message_text"),
            "policy_flags": result.get("policy_flags", []),
            "detected_claws": result.get("detected_claws", []),
        },
    )


async def _execute_channel_command(result: dict, channel_identity: dict | None) -> dict | None:
    if result.get("policy_decision") == "blocked":
        return None
    review = _extract_review_action(result.get("message_text", ""))
    if review:
        action, command_id = review
        actor_email = result.get("sender_email") or ""
        actor_id = result.get("sender_id") or "channel-user"
        current_user = {
            "sub": actor_email or actor_id,
            "role": "security_admin",
            "email": actor_email,
        }
        reason = f"{action}d from channel {result.get('channel_type')} message"
        try:
            async with _channel_command_session() as db:
                if action == "approve":
                    response = await approve_pending_command(
                        command_id,
                        CommandApprovalRequest(approver=current_user["sub"], reason=reason),
                        db=db,
                        current_user=current_user,
                    )
                else:
                    response = await reject_pending_command(
                        command_id,
                        CommandRejectionRequest(reviewer=current_user["sub"], reason=reason),
                        db=db,
                        current_user=current_user,
                    )
            return {
                "command_id": command_id,
                "source": result.get("channel_type", "channel"),
                "requester": current_user["sub"],
                "intent": f"{action}_pending_command",
                "target": command_id,
                "outcome": "allowed",
                "review_action": action,
                "review_result": response,
            }
        except HTTPException as exc:
            return {
                "command_id": command_id,
                "source": result.get("channel_type", "channel"),
                "requester": current_user["sub"],
                "intent": f"{action}_pending_command",
                "target": command_id,
                "outcome": "blocked",
                "reason": str(exc.detail),
                "review_action": action,
            }

    command = _build_command_request(result, channel_identity)
    current_user = {
        "sub": result.get("sender_id") or command.requester,
        "role": "analyst",
        "email": result.get("sender_email", ""),
    }
    try:
        async with AsyncSessionLocal() as db:
            return await _execute_command(db, current_user, command)
    except Exception as exc:
        logger.warning("Channel command execution unavailable: %s", exc)
        return {
            "command_id": command.command_id,
            "source": command.source,
            "requester": command.requester,
            "tenant_id": command.tenant_id,
            "intent": command.intent,
            "target": command.target,
            "outcome": "unavailable",
            "reason": "commandclaw_backend_unavailable",
        }


def _apply_command_outcome(result: dict, command_result: dict | None) -> None:
    if not command_result:
        return
    result["command_result"] = command_result
    outcome = command_result.get("outcome", "")
    if outcome == "blocked":
        result["policy_decision"] = "blocked"
        result["execution_status"] = "blocked"
        result["response_text"] = "🚫 Request blocked by Trust Fabric command policy."
    elif outcome == "requires_approval":
        result["policy_decision"] = "requires_approval"
        result["execution_status"] = "pending_approval"
        if command_result.get("command_id"):
            result["response_text"] = (
                f"🛑 Command queued for approval: {command_result['command_id']}. "
                f"Reply `approve {command_result['command_id']}` or `reject {command_result['command_id']}`."
            )
    elif outcome == "allowed":
        result["policy_decision"] = "allowed"
        result["execution_status"] = "dispatched"
        review_action = command_result.get("review_action")
        if review_action and command_result.get("command_id"):
            if review_action == "approve":
                result["response_text"] = f"✅ Approved command {command_result['command_id']} from channel."
            else:
                result["response_text"] = f"🛑 Rejected command {command_result['command_id']} from channel."
    elif outcome == "unavailable":
        result["execution_status"] = "pending"


# ─── Slack Events API ────────────────────────────────────────────────────────

@router.post("/slack/events")
async def slack_events(
    request: Request,
    x_slack_signature: Optional[str] = Header(None, alias="x-slack-signature"),
    x_slack_request_timestamp: Optional[str] = Header(None, alias="x-slack-request-timestamp"),
    db: Session = Depends(get_db),
):
    body_bytes = await request.body()
    payload    = await request.json()

    # URL verification challenge (Slack sends this when you register the webhook)
    if payload.get("type") == "url_verification":
        return {"challenge": payload.get("challenge")}

    # Verify Slack signature (optional in dev — requires signing_secret in config)
    channel_id = payload.get("event", {}).get("channel", "")
    config = db.query(ChannelConfig).filter(
        ChannelConfig.channel_id == channel_id,
        ChannelConfig.channel_type == "slack",
    ).first()

    if config and config.signing_secret and x_slack_signature and x_slack_request_timestamp:
        ts      = x_slack_request_timestamp
        sig_base = f"v0:{ts}:{body_bytes.decode()}"
        expected = "v0=" + hmac.new(
            config.signing_secret.encode(), sig_base.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, x_slack_signature):
            raise HTTPException(403, "Invalid Slack signature")

    event = payload.get("event", {})
    if event.get("type") not in ("message", "app_mention"):
        return {"ok": True}

    # Skip bot messages
    if event.get("bot_id") or event.get("subtype") == "bot_message":
        return {"ok": True}

    sender_id    = event.get("user", "")
    message_text = event.get("text", "").strip()
    if not message_text:
        return {"ok": True}

    channel_name = config.channel_name if config else channel_id
    out = await _ingest_normalized_message(
        db,
        message_id=str(uuid.uuid4()),
        message_text=message_text,
        sender_id=sender_id,
        sender_email="",
        sender_name=event.get("username", sender_id),
        channel_type="slack",
        channel_id=channel_id,
        channel_name=channel_name,
    )
    return {"ok": True, "response": out["response"]}


# ─── Microsoft Teams Webhook ─────────────────────────────────────────────────

@router.post("/teams/webhook")
async def teams_webhook(
    request: Request,
    db: Session = Depends(get_db),
):
    payload = await request.json()

    # Teams adaptive card / message format
    from_obj     = payload.get("from", {})
    sender_id    = from_obj.get("id", "")
    sender_email = from_obj.get("email", "")
    sender_name  = from_obj.get("name", sender_id)
    message_text = payload.get("text", "").strip()
    channel_id   = payload.get("channelData", {}).get("channel", {}).get("id", "teams-default")
    channel_name = payload.get("channelData", {}).get("channel", {}).get("displayName", channel_id)

    if not message_text:
        return {"type": "message", "text": "No message content received."}

    out = await _ingest_normalized_message(
        db,
        message_id=str(uuid.uuid4()),
        message_text=message_text,
        sender_id=sender_id,
        sender_email=sender_email,
        sender_name=sender_name,
        channel_type="teams",
        channel_id=channel_id,
        channel_name=channel_name,
    )

    # Teams expects an Activity response
    return {
        "type":    "message",
        "text":    out["response"],
        "summary": f"RegentClaw: {out['policy_decision']} ({out['execution_status']})",
    }


@router.post("/webhook")
async def webhook_ingest(body: dict, db: Session = Depends(get_db)):
    """
    Generic webhook ingestion endpoint.
    Body: { channel_id, sender_id?, sender_email?, sender_name?, message_text, channel_name? }
    """
    required = ("channel_id", "message_text")
    for field in required:
        if field not in body:
            raise HTTPException(400, f"Missing field: {field}")
    sender_id = body.get("sender_id") or body.get("sender_email") or "webhook-user"
    sender_email = body.get("sender_email", "")
    sender_name = body.get("sender_name", sender_id)
    return await _ingest_normalized_message(
        db,
        message_id=f"webhook-{uuid.uuid4()}",
        message_text=body["message_text"],
        sender_id=sender_id,
        sender_email=sender_email,
        sender_name=sender_name,
        channel_type="webhook",
        channel_id=body["channel_id"],
        channel_name=body.get("channel_name", body["channel_id"]),
    )


@router.post("/email/inbound")
async def email_inbound(body: dict, db: Session = Depends(get_db)):
    """
    Email ingress endpoint.
    Body: { inbox, from_email, from_name?, subject?, body_text }
    """
    required = ("inbox", "from_email", "body_text")
    for field in required:
        if field not in body:
            raise HTTPException(400, f"Missing field: {field}")
    subject = body.get("subject", "").strip()
    composed = body["body_text"] if not subject else f"{subject}\n\n{body['body_text']}"
    sender_email = body["from_email"]
    sender_id = sender_email
    sender_name = body.get("from_name", sender_email)
    return await _ingest_normalized_message(
        db,
        message_id=f"email-{uuid.uuid4()}",
        message_text=composed,
        sender_id=sender_id,
        sender_email=sender_email,
        sender_name=sender_name,
        channel_type="email",
        channel_id=body["inbox"],
        channel_name=body.get("inbox_name", body["inbox"]),
    )


@router.post("/cli/command")
async def cli_command(body: dict, db: Session = Depends(get_db)):
    """
    CLI ingress endpoint.
    Body: { terminal_id, user, message_text, tenant_id? }
    """
    required = ("terminal_id", "user", "message_text")
    for field in required:
        if field not in body:
            raise HTTPException(400, f"Missing field: {field}")
    user = str(body["user"])
    tenant_id = body.get("tenant_id")
    sender_id = user
    sender_email = user if "@" in user else ""
    sender_name = body.get("display_name", user)
    channel_identity = None
    if tenant_id:
        # Optional identity bootstrap metadata in CLI-mode requests.
        channel_identity = {
            "tenant_id": tenant_id,
            "is_trusted": True,
            "regentclaw_role": "engineer",
            "trust_score": 75,
        }
    # Reuse existing path while injecting optional tenant identity when provided.
    if channel_identity:
        result = process_message(
            message_id=f"cli-{uuid.uuid4()}",
            message_text=body["message_text"],
            sender_id=sender_id,
            sender_email=sender_email,
            sender_name=sender_name,
            channel_type="cli",
            channel_id=body["terminal_id"],
            channel_identity=channel_identity,
        )
        command_result = await _execute_channel_command(result, channel_identity)
        _apply_command_outcome(result, command_result)
        msg = _persist_message(db, result, body.get("terminal_name", body["terminal_id"]))
        outbound_delivery = await _send_channel_response(db, msg, result)
        return {
            **_msg_out(msg),
            "response": result["response_text"],
            "command_result": command_result,
            "outbound_delivery": outbound_delivery,
        }

    return await _ingest_normalized_message(
        db,
        message_id=f"cli-{uuid.uuid4()}",
        message_text=body["message_text"],
        sender_id=sender_id,
        sender_email=sender_email,
        sender_name=sender_name,
        channel_type="cli",
        channel_id=body["terminal_id"],
        channel_name=body.get("terminal_name", body["terminal_id"]),
    )


# ─── Generic / internal message endpoint ─────────────────────────────────────

@router.post("/message")
async def ingest_message(body: dict, db: Session = Depends(get_db)):
    """
    Internal / test endpoint. Body: { channel_type, channel_id, sender_id,
    sender_email, sender_name, message_text, channel_name? }
    """
    required = ("channel_type", "channel_id", "sender_id", "message_text")
    for f in required:
        if f not in body:
            raise HTTPException(400, f"Missing field: {f}")

    return await _ingest_normalized_message(
        db,
        message_id=str(uuid.uuid4()),
        message_text=body["message_text"],
        sender_id=body["sender_id"],
        sender_email=body.get("sender_email", ""),
        sender_name=body.get("sender_name", body["sender_id"]),
        channel_type=body["channel_type"],
        channel_id=body["channel_id"],
        channel_name=body.get("channel_name", body["channel_id"]),
    )


# ─── Simulate endpoint (test without a real bot token) ───────────────────────

@router.post("/simulate")
async def simulate_message(body: dict, db: Session = Depends(get_db)):
    """
    Simulate a channel message without writing to DB. Returns the full processing result.
    Body: { channel_type, channel_id, sender_id, sender_email?, sender_name?, message_text }
    """
    required = ("channel_type", "channel_id", "sender_id", "message_text")
    for f in required:
        if f not in body:
            raise HTTPException(400, f"Missing field: {f}")

    ci = _get_channel_identity(
        db, body["channel_type"], body["sender_id"], body.get("sender_email", "")
    )
    result = process_message(
        message_id   = "sim-" + str(uuid.uuid4()),
        message_text = body["message_text"],
        sender_id    = body["sender_id"],
        sender_email = body.get("sender_email", ""),
        sender_name  = body.get("sender_name", body["sender_id"]),
        channel_type = body["channel_type"],
        channel_id   = body["channel_id"],
        channel_identity = ci,
    )
    command_result = await _execute_channel_command(result, ci)
    _apply_command_outcome(result, command_result)
    result["command_result"] = command_result
    return result


# ─── Messages browse ─────────────────────────────────────────────────────────

@router.get("/messages")
def list_messages(
    channel_type:     Optional[str] = Query(None),
    policy_decision:  Optional[str] = Query(None),
    execution_status: Optional[str] = Query(None),
    sender_email:     Optional[str] = Query(None),
    limit:  int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(ChannelMessage)
    if channel_type:
        q = q.filter(ChannelMessage.channel_type == channel_type)
    if policy_decision:
        q = q.filter(ChannelMessage.policy_decision == policy_decision)
    if execution_status:
        q = q.filter(ChannelMessage.execution_status == execution_status)
    if sender_email:
        q = q.filter(ChannelMessage.sender_email == sender_email)
    total   = q.count()
    results = q.order_by(ChannelMessage.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "messages": [_msg_out(m) for m in results]}


@router.get("/messages/{message_id}")
def get_message(message_id: str, db: Session = Depends(get_db)):
    m = db.query(ChannelMessage).filter(ChannelMessage.id == message_id).first()
    if not m:
        raise HTTPException(404, "Message not found")
    return _msg_out(m)


# ─── Identity registry ───────────────────────────────────────────────────────

@router.get("/identities")
def list_identities(
    channel_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(ChannelIdentity)
    if channel_type:
        q = q.filter(ChannelIdentity.channel_type == channel_type)
    return [_identity_out(ci) for ci in q.all()]


@router.post("/identities")
def upsert_identity(body: dict, db: Session = Depends(get_db)):
    required = ("channel_type", "platform_user_id")
    for f in required:
        if f not in body:
            raise HTTPException(400, f"Missing field: {f}")
    existing = (
        db.query(ChannelIdentity)
        .filter(
            ChannelIdentity.channel_type == body["channel_type"],
            ChannelIdentity.platform_user_id == body["platform_user_id"],
        )
        .first()
    )
    if existing:
        for k, v in body.items():
            if hasattr(existing, k):
                setattr(existing, k, v)
        existing.last_seen = datetime.utcnow()
    else:
        existing = ChannelIdentity(**{k: v for k, v in body.items() if hasattr(ChannelIdentity, k)})
        db.add(existing)
    db.commit()
    db.refresh(existing)
    return _identity_out(existing)


# ─── Channel configs ─────────────────────────────────────────────────────────

@router.get("/configs")
def list_configs(db: Session = Depends(get_db)):
    configs = db.query(ChannelConfig).all()
    return [
        {
            "id": c.id, "channel_type": c.channel_type, "channel_id": c.channel_id,
            "channel_name": c.channel_name, "is_enabled": c.is_enabled,
            "require_approval": c.require_approval, "allowed_roles": c.allowed_roles or [],
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in configs
    ]


@router.post("/configs")
def create_config(body: dict, db: Session = Depends(get_db)):
    required = ("channel_type", "channel_id")
    for f in required:
        if f not in body:
            raise HTTPException(400, f"Missing field: {f}")
    existing = db.query(ChannelConfig).filter(
        ChannelConfig.channel_id == body["channel_id"]
    ).first()
    if existing:
        raise HTTPException(409, "Channel already configured")
    config = ChannelConfig(
        id           = str(uuid.uuid4()),
        channel_type = body["channel_type"],
        channel_id   = body["channel_id"],
        channel_name = body.get("channel_name", body["channel_id"]),
        webhook_url  = body.get("webhook_url", ""),
        bot_token    = body.get("bot_token", ""),
        signing_secret = body.get("signing_secret", ""),
        is_enabled   = body.get("is_enabled", True),
        require_approval = body.get("require_approval", True),
        allowed_roles = body.get("allowed_roles", []),
    )
    db.add(config)
    db.commit()
    db.refresh(config)
    return {"id": config.id, "channel_id": config.channel_id, "message": "Channel registered"}


@router.patch("/configs/{config_id}")
def update_config(config_id: str, body: dict, db: Session = Depends(get_db)):
    config = db.query(ChannelConfig).filter(ChannelConfig.id == config_id).first()
    if not config:
        raise HTTPException(404, "Config not found")
    for k, v in body.items():
        if hasattr(config, k) and k not in ("id", "created_at"):
            setattr(config, k, v)
    db.commit()
    return {"id": config.id, "message": "Config updated"}


# ─── Stats ───────────────────────────────────────────────────────────────────

@router.get("/stats")
def gateway_stats(db: Session = Depends(get_db)):
    total    = db.query(ChannelMessage).count()
    allowed  = db.query(ChannelMessage).filter(ChannelMessage.policy_decision == "allowed").count()
    blocked  = db.query(ChannelMessage).filter(ChannelMessage.policy_decision == "blocked").count()
    pending  = db.query(ChannelMessage).filter(ChannelMessage.policy_decision == "requires_approval").count()
    verified = db.query(ChannelMessage).filter(ChannelMessage.identity_verified == True).count()
    slack_msgs = db.query(ChannelMessage).filter(ChannelMessage.channel_type == "slack").count()
    teams_msgs = db.query(ChannelMessage).filter(ChannelMessage.channel_type == "teams").count()
    dispatched = db.query(ChannelMessage).filter(ChannelMessage.execution_status == "dispatched").count()
    identities = db.query(ChannelIdentity).count()
    trusted    = db.query(ChannelIdentity).filter(ChannelIdentity.is_trusted == True).count()
    channels   = db.query(ChannelConfig).count()
    return {
        "total_messages":   total,
        "allowed":          allowed,
        "blocked":          blocked,
        "pending_approval": pending,
        "identity_verified": verified,
        "slack_messages":   slack_msgs,
        "teams_messages":   teams_msgs,
        "dispatched_runs":  dispatched,
        "registered_identities": identities,
        "trusted_identities":    trusted,
        "connected_channels":    channels,
    }
