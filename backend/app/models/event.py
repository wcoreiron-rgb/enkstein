"""
CoreOS — Event & Telemetry Bus
Normalized event model across all Claw modules.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, Text, Enum as SAEnum, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.core.database import Base


class EventSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventOutcome(str, enum.Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FLAGGED = "flagged"
    REQUIRES_APPROVAL = "requires_approval"
    PENDING = "pending"


class Event(Base):
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    # Source
    source_module: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # e.g., "arcclaw"
    actor_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    actor_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Action
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Decision
    outcome: Mapped[EventOutcome] = mapped_column(SAEnum(EventOutcome), default=EventOutcome.PENDING)
    severity: Mapped[EventSeverity] = mapped_column(SAEnum(EventSeverity), default=EventSeverity.INFO)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Policy
    policy_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    policy_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    policy_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Detail
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON blob

    # Flags
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_review: Mapped[bool] = mapped_column(Boolean, default=False)
