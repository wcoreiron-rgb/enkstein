"""
Enkstein — PolicyPack Model
Compliance framework bundles that deploy curated policy sets.
"""
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Text, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class PolicyPack(Base):
    __tablename__ = "policy_packs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)  # zero-trust, soc2, iso27001, hipaa, pci-dss
    version: Mapped[str] = mapped_column(String(32), default="1.0")
    policy_count: Mapped[int] = mapped_column(Integer, default=0)

    # JSON array of PolicyCreate-compatible dicts
    policies_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    is_applied: Mapped[bool] = mapped_column(Boolean, default=False)
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
