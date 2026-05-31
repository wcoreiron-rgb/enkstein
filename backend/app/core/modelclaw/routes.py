from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.modelclaw.schemas import (
    ModelCallRead,
    ModelProfileCreate,
    ModelProfileRead,
    ModelProviderRead,
    ModelRouteRequest,
    ModelRouteResponse,
)
from app.core.modelclaw.service import (
    get_profile,
    list_model_calls,
    list_profiles,
    list_providers,
    record_model_call,
    upsert_profile,
)
from app.trust_fabric import ActionRequest, enforce

router = APIRouter(prefix="/modelclaw", tags=["ModelClaw"])


@router.get("/providers", response_model=list[ModelProviderRead], summary="List model providers")
async def get_model_providers():
    return list_providers()


@router.get("/profiles", response_model=list[ModelProfileRead], summary="List model profiles")
async def get_model_profiles(tenant_id: str = "global"):
    return list_profiles(tenant_id=tenant_id)


@router.post("/profiles", response_model=ModelProfileRead, summary="Create/update model profile")
async def put_model_profile(payload: ModelProfileCreate):
    return upsert_profile(payload)


@router.get("/calls", response_model=list[ModelCallRead], summary="Recent ModelClaw call audit")
async def get_model_calls(limit: int = 50, tenant_id: str = "global"):
    return list_model_calls(limit, tenant_id=tenant_id)


@router.post("/route", response_model=ModelRouteResponse, summary="Route a model call through Trust Fabric")
async def route_model_call(payload: ModelRouteRequest, db: AsyncSession = Depends(get_db)):
    profile = get_profile(payload.model_profile, tenant_id=payload.tenant_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Model profile not found")

    if profile["allowed_claws"] and payload.claw not in profile["allowed_claws"]:
        raise HTTPException(status_code=403, detail="Claw is not allowed for selected model profile")

    if payload.data_classification not in profile["allowed_data_classes"]:
        raise HTTPException(status_code=403, detail="Data classification is not allowed for selected model profile")

    tf_request = ActionRequest(
        module="modelclaw",
        actor_id=f"{payload.claw}-agent",
        actor_name=f"{payload.claw}-agent",
        actor_type="agent",
        action="model_call",
        target=f"{profile['provider']}/{profile['model']}",
        target_type="model",
        context={
            "action_type": payload.action_type,
            "claw": payload.claw,
            "data_classification": payload.data_classification,
            "swarm_job_id": payload.swarm_job_id,
            **payload.context,
        },
    )
    decision = await enforce(db, tf_request)

    if not decision.allowed:
        return ModelRouteResponse(
            allowed=False,
            outcome=decision.outcome.value,
            policy_name=decision.policy_name,
            reason=decision.reason,
            provider=profile["provider"],
            model=profile["model"],
            model_profile=profile["name"],
        )

    simulated_response = (
        f"ModelClaw response from {profile['provider']}:{profile['model']} for {payload.claw} "
        f"(classification={payload.data_classification})"
    )
    tokens = min(16000, max(64, len(payload.prompt) // 3))
    latency_ms = 180
    record_model_call(
        {
            "claw": payload.claw,
            "provider": profile["provider"],
            "model": profile["model"],
            "model_profile": profile["name"],
            "tenant_id": payload.tenant_id,
            "data_classification": payload.data_classification,
            "outcome": decision.outcome.value,
            "policy_name": decision.policy_name,
            "reason": decision.reason,
            "latency_ms": latency_ms,
            "token_count": tokens,
        }
    )
    return ModelRouteResponse(
        allowed=True,
        outcome=decision.outcome.value,
        policy_name=decision.policy_name,
        reason=decision.reason,
        provider=profile["provider"],
        model=profile["model"],
        model_profile=profile["name"],
        response=simulated_response,
        latency_ms=latency_ms,
        token_count=tokens,
    )
