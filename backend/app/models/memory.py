"""
Enkstein — Memory / State Layer Models
Persistent structured memory for the platform:
  - IncidentMemory    : timeline of a security incident (linked to findings/runs)
  - AssetMemory       : per-asset risk history and context
  - TenantMemory      : platform-wide threat context and global notes
  - RiskTrendSnapshot : periodic risk score snapshots for trending
"""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, Integer, Float, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class IncidentMemory(Base):
    """
    Tracks the full lifecycle of a security incident:
    from first detection through containment, remediation, and closure.
    Linked to findings, workflow runs, and agents that acted on it.
    """
    __tablename__ = "incident_memory"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # Identity
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Severity / status
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    # open | investigating | contained | remediated | closed | false_positive

    # Source context
    source_claw: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Asset / scope
    affected_assets: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON list
    affected_users: Mapped[str | None]  = mapped_column(Text, nullable=True)   # JSON list
    scope_tags: Mapped[str | None]      = mapped_column(String(255), nullable=True)

    # MITRE ATT&CK
    mitre_tactics: Mapped[str | None]    = mapped_column(String(255), nullable=True)  # comma-sep
    mitre_techniques: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Timeline (JSON array of {timestamp, actor, action, detail, type})
    timeline_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    timeline_count: Mapped[int] = mapped_column(Integer, default=0)

    # Linked workflow runs / agent runs
    linked_runs: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list of run_ids

    # Resolution
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)

    # Metrics
    mttr_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)  # mean time to remediate
    risk_score_at_open: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Ownership
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str | None]  = mapped_column(String(255), nullable=True)

    opened_at:    Mapped[datetime]      = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at:    Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at:   Mapped[datetime]      = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class AssetMemory(Base):
    """
    Per-asset risk context: cumulative findings, risk trend, last-seen status.
    asset_id is the canonical identifier (IP, hostname, account ID, etc.)
    """
    __tablename__ = "asset_memory"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # Identity
    asset_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    # endpoint | identity | cloud_resource | network | application | data_store

    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    claw: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Current risk state
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(32), default="low")
    # low | medium | high | critical

    # Cumulative counts
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    open_findings: Mapped[int]  = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    incidents_involved: Mapped[int] = mapped_column(Integer, default=0)

    # Risk history (JSON array of {timestamp, score, level, event})
    risk_history_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    # Context notes accumulated over time
    context_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tags
    tags: Mapped[str | None] = mapped_column(String(255), nullable=True)

    first_seen_at: Mapped[datetime]      = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen_at:  Mapped[datetime]      = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at:    Mapped[datetime]      = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class TenantMemory(Base):
    """
    Per-tenant rolling memory of the current security posture, active threats,
    and key context for AI agents. One row per tenant, enforced by the unique
    ``tenant_id``; the legacy ``NULL`` row is the pre-scoping remnant.
    """
    __tablename__ = "tenant_memory"

    # No default: the historical ``default=1`` allowed only one row platform-wide.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True, index=True)

    # Current posture summary
    overall_risk_level: Mapped[str] = mapped_column(String(32), default="low")
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Active context (updated by agents and ingestion pipeline)
    active_incident_count: Mapped[int] = mapped_column(Integer, default=0)
    open_finding_count: Mapped[int]    = mapped_column(Integer, default=0)
    critical_finding_count: Mapped[int] = mapped_column(Integer, default=0)

    # Top active threats (JSON list of {name, severity, ioc_type, first_seen})
    active_threats_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    # Known compromised / high-risk assets (JSON list)
    high_risk_assets_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    # Threat intel context — recent IOCs, ATT&CK patterns seen
    threat_context_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    # Free-text running notes (accumulated by agents)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Trend data (7/30 day change)
    risk_delta_7d: Mapped[float | None]  = mapped_column(Float, nullable=True)
    risk_delta_30d: Mapped[float | None] = mapped_column(Float, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    last_ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RiskTrendSnapshot(Base):
    """
    Periodic snapshots of platform-wide risk metrics.
    Used for trend charts: risk over time, finding rates, MTTR.
    """
    __tablename__ = "risk_trend_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    snapshot_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    granularity: Mapped[str] = mapped_column(String(16), nullable=False, default="hourly")
    # hourly | daily | weekly

    # Platform metrics at snapshot time
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    open_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, default=0)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0)
    low_findings: Mapped[int] = mapped_column(Integer, default=0)
    new_findings: Mapped[int] = mapped_column(Integer, default=0)     # in period
    closed_findings: Mapped[int] = mapped_column(Integer, default=0)  # in period
    active_incidents: Mapped[int] = mapped_column(Integer, default=0)
    workflow_runs: Mapped[int] = mapped_column(Integer, default=0)
    mean_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    p95_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Per-claw breakdown (JSON: {claw_id: finding_count})
    claw_breakdown_json: Mapped[str | None] = mapped_column(Text, nullable=True)


# Indexes
Index("ix_incident_memory_status_severity", IncidentMemory.status, IncidentMemory.severity)
Index("ix_risk_trend_snapshot_granularity", RiskTrendSnapshot.granularity, RiskTrendSnapshot.snapshot_at)
