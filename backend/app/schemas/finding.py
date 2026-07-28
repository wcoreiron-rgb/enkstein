"""
Enkstein — Universal Finding Schemas
Pydantic models for reading, creating, and updating Finding records.
"""
from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional

from app.models.finding import FindingSeverity, FindingStatus


class FindingCreate(BaseModel):
    claw: str
    provider: str
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: FindingSeverity = FindingSeverity.MEDIUM
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    region: Optional[str] = None
    account_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    risk_score: float = 50.0
    actively_exploited: bool = False
    status: FindingStatus = FindingStatus.OPEN
    remediation: Optional[str] = None
    remediation_effort: Optional[str] = None
    external_id: Optional[str] = None
    reference_url: Optional[str] = None
    raw_data: Optional[str] = None
    data_origin: str = "unknown"
    source_connector: Optional[str] = None
    control_id: Optional[str] = None
    control_source: Optional[str] = None
    zt_pillar: Optional[str] = None


class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    remediation_effort: Optional[str] = None
    remediation: Optional[str] = None
    risk_score: Optional[float] = None
    severity: Optional[FindingSeverity] = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    claw: str
    provider: str
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: FindingSeverity
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    region: Optional[str] = None
    account_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    risk_score: float
    actively_exploited: bool
    status: FindingStatus
    remediation: Optional[str] = None
    remediation_effort: Optional[str] = None
    external_id: Optional[str] = None
    reference_url: Optional[str] = None
    raw_data: Optional[str] = None
    data_origin: str = "unknown"
    source_connector: Optional[str] = None
    control_id: Optional[str] = None
    control_source: Optional[str] = None
    zt_pillar: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    resolved_at: Optional[datetime] = None
    created_at: datetime
