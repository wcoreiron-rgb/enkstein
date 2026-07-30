"""
CoreOS — Audit Engine
Full traceability of every action, decision, and policy evaluation.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    # Tenancy. Nullable because rows written before tenant scoping existed
    # carry no owner; those legacy rows are visible only to unscoped admins.
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # Who
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # What
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    resource_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Decision
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)  # allowed / denied / flagged
    policy_applied: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Context
    module: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Compliance flags
    compliance_relevant: Mapped[bool] = mapped_column(Boolean, default=False)
    frameworks: Mapped[str | None] = mapped_column(String(512), nullable=True)  # CSV: "ISO27001,SOC2"
