"""
CoreOS — Connector Registry
Every integration must be registered, scoped, and policy-approved before use.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, Text, Enum as SAEnum, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.core.database import Base


class ConnectorStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    RESTRICTED = "restricted"
    BLOCKED = "blocked"


class ConnectorRisk(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Connector(Base):
    __tablename__ = "connectors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(64), nullable=False)   # e.g., "entra", "aws", "openai"
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[ConnectorStatus] = mapped_column(SAEnum(ConnectorStatus), default=ConnectorStatus.PENDING)
    risk_level: Mapped[ConnectorRisk] = mapped_column(SAEnum(ConnectorRisk), default=ConnectorRisk.MEDIUM)

    # Scoping
    approved_scopes: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list of allowed scopes
    requested_scopes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Ownership
    # String tenant scope, matching the platform-wide tenant claim. Distinct
    # from owner_id, which is a per-user UUID and never carried tenancy.
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    module_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("modules.id"), nullable=True
    )

    # Connection details (no raw secrets stored here)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    credential_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)  # ref to secrets store

    network_access: Mapped[bool] = mapped_column(Boolean, default=False)
    shell_access: Mapped[bool] = mapped_column(Boolean, default=False)
    filesystem_access: Mapped[bool] = mapped_column(Boolean, default=False)

    # Marketplace metadata
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)   # e.g., "Identity", "SIEM", "Cloud"
    trust_score: Mapped[float] = mapped_column(Float, default=70.0)            # 0-100; derived from risk + status

    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Configuration and policy approval do not establish that credentials work.
    # Preserve the last read-only verification as a separate state.
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_verification_error: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
