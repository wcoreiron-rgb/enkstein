"""
Enkstein — Messaging Channel Gateway models
Tracks inbound messages, identity checks, policy decisions, and dispatched executions.
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, Text, DateTime, JSON
from app.database import Base


class ChannelMessage(Base):
    """An inbound message from a Teams or Slack channel."""
    __tablename__ = "channel_messages"

    id               = Column(String, primary_key=True)
    channel_type     = Column(String, nullable=False)   # teams|slack
    channel_id       = Column(String, nullable=False, index=True)
    channel_name     = Column(String, default="")
    sender_id        = Column(String, nullable=False, index=True)
    sender_name      = Column(String, default="")
    sender_email     = Column(String, default="", index=True)
    message_text     = Column(Text, nullable=False)
    message_ts       = Column(String, default="")       # Slack timestamp / Teams message ID
    thread_ts        = Column(String, default="")       # Thread parent
    raw_payload      = Column(JSON, default=dict)

    # Processing
    identity_verified = Column(Boolean, default=False)
    identity_risk     = Column(String, default="unknown")   # low|medium|high|critical
    policy_decision   = Column(String, default="pending")   # allowed|blocked|requires_approval
    policy_flags      = Column(JSON, default=list)
    detected_intent   = Column(String, default="")
    detected_claws    = Column(JSON, default=list)

    # Execution
    execution_status  = Column(String, default="pending")   # pending|dispatched|completed|blocked|failed
    workflow_run_id   = Column(String, default="")
    agent_run_id      = Column(String, default="")
    response_sent     = Column(Boolean, default=False)
    response_text     = Column(Text, default="")

    created_at        = Column(DateTime, default=datetime.utcnow)
    processed_at      = Column(DateTime, nullable=True)


class ChannelIdentity(Base):
    """Maps messaging platform user IDs to Enkstein identities."""
    __tablename__ = "channel_identities"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    channel_type     = Column(String, nullable=False)
    platform_user_id = Column(String, nullable=False, index=True)
    platform_email   = Column(String, default="", index=True)
    platform_name    = Column(String, default="")
    regentclaw_role  = Column(String, default="analyst")    # analyst|engineer|admin|readonly
    is_trusted       = Column(Boolean, default=False)
    trust_score      = Column(Integer, default=50)
    allowed_claws    = Column(JSON, default=list)           # empty = all
    denied_claws     = Column(JSON, default=list)
    max_autonomy     = Column(String, default="approval")   # monitor|assist|approval|autonomous
    last_seen        = Column(DateTime, default=datetime.utcnow)
    created_at       = Column(DateTime, default=datetime.utcnow)


class ChannelConfig(Base):
    """Configuration for a connected messaging channel."""
    __tablename__ = "channel_configs"

    id               = Column(String, primary_key=True)
    channel_type     = Column(String, nullable=False)   # teams|slack
    channel_id       = Column(String, nullable=False, unique=True, index=True)
    channel_name     = Column(String, default="")
    webhook_url      = Column(String, default="")
    bot_token        = Column(String, default="")
    signing_secret   = Column(String, default="")
    is_enabled       = Column(Boolean, default=True)
    require_approval = Column(Boolean, default=True)
    allowed_roles    = Column(JSON, default=list)
    created_at       = Column(DateTime, default=datetime.utcnow)
