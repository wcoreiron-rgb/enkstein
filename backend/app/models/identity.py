"""
CoreOS — Identity Registry
Every identity (human, agent, module, connector) is a first-class governed entity.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, Boolean, ForeignKey, Text, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.core.database import Base


class IdentityType(str, enum.Enum):
    HUMAN = "human"
    AGENT = "agent"
    MODULE = "module"
    CONNECTOR = "connector"
    SERVICE = "service"


class IdentityStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ORPHANED = "orphaned"
    REVOKED = "revoked"
    PENDING = "pending"


class Identity(Base):
    __tablename__ = "identities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[IdentityType] = mapped_column(SAEnum(IdentityType), nullable=False)
    status: Mapped[IdentityStatus] = mapped_column(SAEnum(IdentityStatus), default=IdentityStatus.ACTIVE)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id"), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    trust_score: Mapped[float] = mapped_column(Float, default=1000.0)  # 0–1000 scale
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)      # 0–100 scale
    is_privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Metadata
    external_id: Mapped[str | None] = mapped_column(String(512), nullable=True)  # e.g., Entra object ID
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)       # e.g., "entra", "manual"

    # Self-referential: owner
    owner: Mapped["Identity | None"] = relationship("Identity", remote_side=[id], foreign_keys=[owner_id])
