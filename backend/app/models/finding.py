"""
Enkstein — Universal Security Finding Model
All 23 Claws write findings to this single table.
Query by claw + provider + severity + status for per-claw dashboards.
"""
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Text, Float, Boolean, Integer, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum
from app.core.database import Base


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class FindingStatus(str, enum.Enum):
    OPEN            = "open"
    IN_REMEDIATION  = "in_remediation"
    RESOLVED        = "resolved"
    ACCEPTED_RISK   = "accepted_risk"
    FALSE_POSITIVE  = "false_positive"


class RemediationEffort(str, enum.Enum):
    QUICK_WIN    = "quick_win"     # < 1 week
    MEDIUM_TERM  = "medium_term"   # 1-4 weeks
    STRATEGIC    = "strategic"     # 1-3 months


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Tenancy. Nullable because rows written before tenant scoping existed
    # carry no owner; those legacy rows are visible only to unscoped admins.
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # Which Claw and which data source
    claw: Mapped[str] = mapped_column(String(64), nullable=False)           # "cloudclaw", "exposureclaw", etc.
    provider: Mapped[str] = mapped_column(String(64), nullable=False)       # "aws", "azure", "gcp", "nvd", "cisa", etc.

    # Classification
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)   # "misconfiguration", "vulnerability", "exposure"
    severity: Mapped[FindingSeverity] = mapped_column(String(16), nullable=False, default=FindingSeverity.MEDIUM)

    # Affected resource
    resource_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(128), nullable=True)  # "s3_bucket", "ec2_instance"
    resource_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    account_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Scoring
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)      # 0-1 exploit probability
    risk_score: Mapped[float] = mapped_column(Float, default=50.0)             # RegentClaw 0-100
    actively_exploited: Mapped[bool] = mapped_column(Boolean, default=False)   # In CISA KEV

    # Status
    status: Mapped[FindingStatus] = mapped_column(String(32), nullable=False, default=FindingStatus.OPEN)

    # Remediation
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_effort: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # External reference
    external_id: Mapped[str | None] = mapped_column(String(256), nullable=True)   # CVE-2024-xxxx, AWS finding ID, etc.
    reference_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Raw provider data
    raw_data: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON

    # Data origin. A beta tenant typically has one or two live connectors while
    # the rest of the platform still produces realistic demo findings, so an
    # operator must be able to tell which findings describe their own estate.
    #   "live"      — returned by an authenticated provider API call
    #   "simulated" — generated locally for demonstration
    #   "unknown"   — origin was not asserted by the adapter (legacy rows)
    data_origin: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    # Which configured connector produced it, when known, so a finding can be
    # traced back to the credential that fetched it.
    source_connector: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Control identity. A finding is evidence that a control failed, so it
    # carries the control's identifier rather than restating its definition.
    # These stay nullable: findings imported from a vendor platform describe
    # that vendor's own verdict and may not map to a catalog control.
    control_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    control_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # CISA Zero Trust pillar, denormalised from the control so per-pillar
    # posture can be aggregated without joining the catalog on every query.
    zt_pillar: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
