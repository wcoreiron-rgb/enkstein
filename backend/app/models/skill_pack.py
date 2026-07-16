"""
Enkstein — Skill Pack Models
Versioned, policy-governed security skill bundles.

A SkillPack groups related automation skills (e.g., "CrowdStrike Endpoint
Response v1.2") into a single installable unit with:
  - A machine-readable manifest (skills, scopes, required connectors)
  - Policy mapping (which policies each skill enforces)
  - Install/uninstall lifecycle with audit trail
  - Compatibility checks (min platform version, required claws)
"""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class SkillPack(Base):
    __tablename__ = "skill_packs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Identity
    name:        Mapped[str] = mapped_column(String(255), nullable=False)
    slug:        Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    version:     Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    icon:        Mapped[str | None] = mapped_column(String(8), nullable=True)  # emoji

    # Categorisation
    category:    Mapped[str | None] = mapped_column(String(64), nullable=True)
    # e.g. Incident Response, Threat Hunting, Compliance, Hardening, Enrichment
    publisher:   Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags:        Mapped[str | None] = mapped_column(String(255), nullable=True)  # comma-sep

    # Manifest — JSON describing the pack content
    # {
    #   "skills": [{"id": str, "name": str, "description": str, "claw": str, "action": str}],
    #   "required_connectors": [str],         # connector types required
    #   "required_claws": [str],              # claw ids required
    #   "policy_mappings": [{"skill_id": str, "policy_name": str}],
    #   "scope_permissions": [str],           # e.g. ["read:findings", "write:findings"]
    #   "min_platform_version": str,
    # }
    manifest_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    # Lifecycle
    is_installed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active:    Mapped[bool] = mapped_column(Boolean, default=False)
    is_builtin:   Mapped[bool] = mapped_column(Boolean, default=False)
    # builtin = shipped with platform; non-builtin = from marketplace / uploaded

    # Install metadata
    installed_at:  Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    installed_by:  Mapped[str | None]      = mapped_column(String(255), nullable=True)
    activated_at:  Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Policy & risk
    risk_level:        Mapped[str] = mapped_column(String(32), default="low")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    # JSON list of policy IDs this pack auto-creates/attaches on install
    linked_policy_ids: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Stats
    skill_count: Mapped[int] = mapped_column(Integer, default=0)
    run_count:   Mapped[int] = mapped_column(Integer, default=0)

    # Provenance
    signature:          Mapped[str | None] = mapped_column(String(128), nullable=True)   # SHA256 of manifest (legacy short form)
    manifest_hash:      Mapped[str | None] = mapped_column(String(64), nullable=True)    # SHA-256 hex (full 64 chars)
    manifest_signature: Mapped[str | None] = mapped_column(String(512), nullable=True)   # Ed25519 base64
    publisher_key:      Mapped[str | None] = mapped_column(Text, nullable=True)           # PEM public key
    source_url:         Mapped[str | None] = mapped_column(String(512), nullable=True)
    license:            Mapped[str | None] = mapped_column(String(64), nullable=True)    # MIT | Apache-2.0 | …
    changelog:          Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
