"""Persisted user-defined REST API integration definitions."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.core.database import Base


class CustomClawDefinition(Base):
    __tablename__ = "customclaw_definitions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(32), default="none")
    auth_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_header: Mapped[str | None] = mapped_column(String(128), nullable=True)
    icon: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)        # JSON array string
    endpoints: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON array string
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
