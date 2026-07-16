"""AI Security database models."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, Text, Boolean, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.core.database import Base


class AIEventType(str, enum.Enum):
    PROMPT_SUBMITTED = "prompt_submitted"
    RESPONSE_RECEIVED = "response_received"
    TOOL_CALLED = "tool_called"
    FILE_UPLOADED = "file_uploaded"
    DATA_EXPORTED = "data_exported"


class AIEventOutcome(str, enum.Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FLAGGED = "flagged"
    REDACTED = "redacted"


class AIEvent(Base):
    __tablename__ = "arc_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    # Source
    user_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    user_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(128), nullable=True)   # e.g., "ChatGPT", "Copilot"
    session_id: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Content
    event_type: Mapped[AIEventType] = mapped_column(SAEnum(AIEventType))
    prompt_text: Mapped[str | None] = mapped_column(Text, nullable=True)        # original (may be sensitive)
    redacted_text: Mapped[str | None] = mapped_column(Text, nullable=True)      # safe version

    # Analysis
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)     # JSON list of findings
    categories_json: Mapped[str | None] = mapped_column(Text, nullable=True)   # prompt classification
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Decision
    outcome: Mapped[AIEventOutcome] = mapped_column(SAEnum(AIEventOutcome), default=AIEventOutcome.ALLOWED)
    policy_applied: Mapped[str | None] = mapped_column(String(255), nullable=True)
    block_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
