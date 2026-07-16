from fastapi import APIRouter, HTTPException, Query, status

from app.core.marcellus.registry import (
    get_architecture_snapshot,
    get_capability_node,
    list_capability_nodes,
    list_security_arms,
)
from app.core.marcellus.schemas import ArchitectureSnapshot, CapabilityNode, SecurityArm, SecurityArmId


router = APIRouter(prefix="/marcellus", tags=["Enkstein Architecture"])


@router.get(
    "/architecture",
    response_model=ArchitectureSnapshot,
    summary="Get the complete Enkstein architecture contract",
)
async def architecture() -> ArchitectureSnapshot:
    return get_architecture_snapshot()


@router.get(
    "/arms",
    response_model=list[SecurityArm],
    summary="List stable cybersecurity pillar Arms",
)
async def arms() -> list[SecurityArm]:
    return list_security_arms()


@router.get(
    "/nodes",
    response_model=list[CapabilityNode],
    summary="List Capability Nodes, optionally filtered by Security Arm",
)
async def nodes(
    arm_id: SecurityArmId | None = Query(default=None),
) -> list[CapabilityNode]:
    return list_capability_nodes(arm_id)


@router.get(
    "/nodes/{node_id}",
    response_model=CapabilityNode,
    summary="Get one Capability Node",
)
async def node(node_id: str) -> CapabilityNode:
    capability = get_capability_node(node_id)
    if capability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Capability Node not found",
        )
    return capability
