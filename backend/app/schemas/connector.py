from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional
from app.models.connector import ConnectorStatus, ConnectorRisk


class ConnectorCreate(BaseModel):
    name: str
    connector_type: str
    description: Optional[str] = None
    risk_level: ConnectorRisk = ConnectorRisk.MEDIUM
    endpoint: Optional[str] = None
    requested_scopes: Optional[str] = None
    network_access: bool = False
    shell_access: bool = False
    filesystem_access: bool = False
    owner_id: Optional[UUID] = None
    module_id: Optional[UUID] = None


class ConnectorUpdate(BaseModel):
    status: Optional[ConnectorStatus] = None
    approved_scopes: Optional[str] = None
    risk_level: Optional[ConnectorRisk] = None


class ConnectorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    connector_type: str
    description: Optional[str] = None
    status: ConnectorStatus
    risk_level: ConnectorRisk
    approved_scopes: Optional[str] = None
    requested_scopes: Optional[str] = None
    endpoint: Optional[str] = None
    network_access: bool
    shell_access: bool
    filesystem_access: bool
    category: Optional[str] = None
    trust_score: float = 70.0
    last_used: Optional[datetime] = None
    last_verified_at: Optional[datetime] = None
    verification_level: Optional[str] = None
    last_verification_error: Optional[str] = None
    created_at: datetime
    # Annotated at runtime from secrets store — not stored in DB
    is_configured: Optional[bool] = False
