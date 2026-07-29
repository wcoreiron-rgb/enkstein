"""
Control catalog.

A finding says something is wrong. A control says what *should* be true, and
exists whether or not anything has scanned yet. Without that distinction a
node can only ever list failures -- it cannot say "42 controls, 3 failing,
39 passing", which is the question an operator actually asks.

Controls are synced from external catalogs (NIST OSCAL, Prowler) and authored
locally for domains no public catalog covers. Every control carries its source
and the catalog version it came from, so a sync can diff rather than clobber,
and an operator can see exactly which revision their posture was measured
against.
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, String, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ControlSource(str, enum.Enum):
    """Where a control definition came from."""

    NIST_800_53 = "nist_800_53"      # OSCAL catalog, public domain
    PROWLER = "prowler"              # Apache 2.0
    AUTHORED = "authored"            # Written for Enkstein
    VENDOR = "vendor"                # Imported verdict from a vendor platform


class ControlStatus(str, enum.Enum):
    """Lifecycle of a control within this deployment."""

    ACTIVE = "active"
    # A sync introduced this control; it is not evaluated until reviewed, so a
    # catalog update cannot silently change what a tenant is measured against.
    PENDING_REVIEW = "pending_review"
    # Present in an older catalog version but absent from the current one.
    WITHDRAWN = "withdrawn"
    DISABLED = "disabled"


class Control(Base):
    __tablename__ = "control_catalog"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Stable identity. ``control_id`` is the catalog's own identifier
    # (AC-2, prowler:s3_bucket_public_access), unique per source.
    control_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default=ControlSource.AUTHORED)
    source_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Zero Trust classification. The pillar is required because it is the axis
    # maturity is scored on; the 800-207 tenets are optional references.
    zt_pillar: Mapped[str] = mapped_column(String(32), nullable=False)
    # JSON array of 800-207 tenet ids. Stored as Text to match the codebase
    # convention and stay portable across Postgres and SQLite.
    zt_tenets: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # Which Capability Node evaluates this control, and against what.
    claw: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Compliance cross-references, as {framework: [control ids]}. These are
    # factual mappings, not licensed benchmark prose.
    frameworks: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Action type from the remediation engine that fixes this, when one exists.
    remediation_action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remediation_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="recommendation_only")
    evidence_method: Mapped[str | None] = mapped_column(Text, nullable=True)
    evaluator_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    recommendation_only: Mapped[bool] = mapped_column(Boolean, default=True)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default=ControlStatus.PENDING_REVIEW)
    automated: Mapped[bool] = mapped_column(Boolean, default=False)

    reference_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    __table_args__ = (
        Index("ix_control_source_id", "source", "control_id", unique=True),
        Index("ix_control_pillar", "zt_pillar"),
        Index("ix_control_claw", "claw"),
    )


class ControlSync(Base):
    """One catalog sync run, kept so a pull can be diffed and audited."""

    __tablename__ = "control_syncs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Checksum of the fetched payload, so an unchanged catalog is a no-op.
    checksum: Mapped[str | None] = mapped_column(String(128), nullable=True)

    added: Mapped[int] = mapped_column(default=0)
    changed: Mapped[int] = mapped_column(default=0)
    withdrawn: Mapped[int] = mapped_column(default=0)
    unchanged: Mapped[int] = mapped_column(default=0)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
