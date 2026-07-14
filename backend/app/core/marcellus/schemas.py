from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ImplementationState(str, Enum):
    EXISTING = "existing"
    PARTIAL = "partial"
    CONTRACT_ONLY = "contract_only"


class SecurityArmId(str, Enum):
    THREAT_EXPOSURE = "threat_exposure"
    IDENTITY_HUMAN_RISK = "identity_human_risk"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    NETWORK_ENDPOINT = "network_endpoint"
    APPLICATION_DELIVERY = "application_delivery"
    DATA_PRIVACY_SAAS = "data_privacy_saas"
    GOVERNANCE_RESILIENCE = "governance_resilience"
    AI_AUTONOMOUS_OPERATIONS = "ai_autonomous_operations"


class AuthorityCeiling(str, Enum):
    OBSERVE = "observe"
    RECOMMEND = "recommend"
    APPROVAL_GATED_ACTION = "approval_gated_action"


class Terminology(BaseModel):
    model_config = ConfigDict(frozen=True)

    cortex: str
    three_hearts: str
    security_arms: str
    capability_nodes: str
    skills: str
    connectors: str
    reflexes: str
    plexus: str
    regeneration: str


class CortexComponent(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    purpose: str
    implementation_state: ImplementationState
    legacy_components: tuple[str, ...] = ()


class Heart(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    purpose: str
    implementation_state: ImplementationState
    components: tuple[str, ...]


class CapabilityNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    arm_id: SecurityArmId
    purpose: str
    legacy_module: str
    legacy_route: str
    task_route: str
    capabilities: tuple[str, ...]
    authority_ceiling: AuthorityCeiling
    supports_focused_task: bool = True
    plexus_ready: bool = False
    implementation_state: ImplementationState = ImplementationState.EXISTING


class SecurityArm(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: SecurityArmId
    name: str
    purpose: str
    node_ids: tuple[str, ...]
    implementation_state: ImplementationState


class ExtensionContract(BaseModel):
    model_config = ConfigDict(frozen=True)

    skills: str
    connectors: str
    invariant: str


class ReflexContract(BaseModel):
    model_config = ConfigDict(frozen=True)

    implementation_state: ImplementationState
    purpose: str
    existing_foundation: tuple[str, ...]
    invariants: tuple[str, ...]


class PlexusContract(BaseModel):
    model_config = ConfigDict(frozen=True)

    implementation_state: ImplementationState
    purpose: str
    current_transport: str
    target_transport: str
    invariants: tuple[str, ...]


class RegenerationContract(BaseModel):
    model_config = ConfigDict(frozen=True)

    implementation_state: ImplementationState
    purpose: str
    recovery_sequence: tuple[str, ...]
    invariants: tuple[str, ...]


class ArchitectureSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    working_name: bool = True
    source_lineage: str
    compatibility_mode: str
    thesis: str
    terminology: Terminology
    cortex: tuple[CortexComponent, ...]
    hearts: tuple[Heart, ...]
    arms: tuple[SecurityArm, ...]
    capability_nodes: tuple[CapabilityNode, ...]
    extensions: ExtensionContract
    reflexes: ReflexContract
    plexus: PlexusContract
    regeneration: RegenerationContract
    invariants: tuple[str, ...] = Field(min_length=1)
