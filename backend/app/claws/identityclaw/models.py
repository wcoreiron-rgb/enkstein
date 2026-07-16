"""Identity Security database models."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, Text, Boolean, Enum as SAEnum, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.core.database import Base


class IdentityRiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IdentityRiskEvent(Base):
    """Tracks risk events specific to identity security."""
    __tablename__ = "identity_risk_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    identity_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    identity_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    identity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    risk_type: Mapped[str] = mapped_column(String(128), nullable=False)  # e.g., "orphaned", "excessive_privilege"
    risk_level: Mapped[IdentityRiskLevel] = mapped_column(SAEnum(IdentityRiskLevel), default=IdentityRiskLevel.MEDIUM)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class PrivilegedAction(Base):
    """Tracks privileged actions requiring approval."""
    __tablename__ = "privileged_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    requestor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    requestor_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    target_identity_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending / approved / denied
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
