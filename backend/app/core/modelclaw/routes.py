from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.marcellus.runtime_security import require_runtime_operator, resolve_tenant
from app.core.modelclaw.schemas import (
    BrainInvokeRequest,
    BrainInvokeResponse,
    BrainStatusRead,
    BrainVoteRead,
    ConsensusRequest,
    ConsensusResponse,
    CortexGatewayRequest,
    CortexGatewayResponse,
    ModelCallRead,
    ModelProfileCreate,
    ModelProfileRead,
    ModelProviderRead,
    ModelRouteRequest,
    ModelRouteResponse,
)
from app.core.modelclaw.brain_bridge import (
    bridge_status,
    collect_votes,
    create_browser_brain_pairing,
    derive_brain_session_id,
    deterministic_consensus,
    invoke_subscription_brain,
    open_browser_companion_folder,
    request_desktop_brain_access,
)
from app.core.modelclaw.gateway import execute_cortex_gateway
from app.core.modelclaw.service import (
    get_profile,
    list_model_calls,
    list_profiles,
    list_providers,
    record_model_call,
    upsert_profile,
)
from app.trust_fabric import ActionRequest, enforce

router = APIRouter(prefix="/modelclaw", tags=["Model Cortex"])
_EXTERNAL_BRAINS = {
    "codex_subscription",
    "claude_subscription",
    "chatgpt_desktop",
    "claude_desktop",
    "chatgpt_browser",
    "claude_browser",
    "gemini_browser",
}


async def _enforce_brain_call(
    db: AsyncSession,
    *,
    source: str,
    claw: str,
    classification: str,
    tenant_id: str,
    context: dict,
):
    return await enforce(
        db,
        ActionRequest(
            module="modelclaw",
            actor_id=f"{claw}-agent",
            actor_name=f"{claw}-agent",
            actor_type="agent",
            action="model_call",
            target=source,
            target_type="brain",
            context={
                **context,
                "action_type": "BRAIN_CALL",
                "claw": claw,
                "data_classification": classification,
                "tenant_id": tenant_id,
            },
        ),
    )


@router.get("/providers", response_model=list[ModelProviderRead], summary="List model providers")
async def get_model_providers(user: dict = Depends(get_current_user)):
    return list_providers()


@router.get("/profiles", response_model=list[ModelProfileRead], summary="List model profiles")
async def get_model_profiles(
    tenant_id: str = "global",
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return list_profiles(tenant_id=tenant_id)


@router.post("/profiles", response_model=ModelProfileRead, summary="Create/update model profile")
async def put_model_profile(
    payload: ModelProfileCreate,
    user: dict = Depends(get_current_user),
):
    require_runtime_operator(user)
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return upsert_profile(payload.model_copy(update={"tenant_id": tenant_id}))


@router.get("/calls", response_model=list[ModelCallRead], summary="Recent Model Cortex call audit")
async def get_model_calls(
    limit: int = 50,
    tenant_id: str = "global",
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return list_model_calls(limit, tenant_id=tenant_id)


@router.get("/brains/status", response_model=list[BrainStatusRead], summary="Native subscription Brain status")
async def get_brain_status(user: dict = Depends(get_current_user)):
    return await bridge_status()


@router.post("/brains/desktop-access", summary="Request desktop Brain accessibility permission")
async def request_desktop_access(user: dict = Depends(get_current_user)):
    return await request_desktop_brain_access()


@router.post("/brains/browser-pair", summary="Start browser companion pairing")
async def start_browser_pairing(user: dict = Depends(get_current_user)):
    return await create_browser_brain_pairing()


@router.post("/brains/browser-companion", summary="Open browser companion installation folder")
async def open_browser_companion(user: dict = Depends(get_current_user)):
    return await open_browser_companion_folder()


@router.post("/brains/invoke", response_model=BrainInvokeResponse, summary="Invoke a subscription Brain")
async def invoke_brain(
    payload: BrainInvokeRequest,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    payload = payload.model_copy(update={"tenant_id": tenant_id})
    if payload.data_classification in {"restricted", "top_secret"}:
        raise HTTPException(
            status_code=403,
            detail="Subscription Brains cannot receive restricted or top-secret data; use an approved local profile.",
        )
    decision = await _enforce_brain_call(
        db,
        source=payload.brain,
        claw=payload.claw,
        classification=payload.data_classification,
        tenant_id=payload.tenant_id,
        context=payload.context,
    )
    if not decision.allowed:
        return BrainInvokeResponse(
            source=payload.brain,
            kind="desktop_session" if payload.brain.endswith("_desktop") else "browser_session" if payload.brain.endswith("_browser") else "subscription",
            available=True,
            counted=False,
            reason=decision.reason,
            policy_outcome=decision.outcome.value,
        )

    invocation_kwargs = {"model": payload.model}
    session_id = derive_brain_session_id(payload.tenant_id, payload.context)
    if session_id:
        invocation_kwargs["session_id"] = session_id
    vote = await invoke_subscription_brain(payload.brain, payload.prompt, **invocation_kwargs)
    vote["policy_outcome"] = decision.outcome.value
    record_model_call(
        {
            "claw": payload.claw,
            "provider": vote.get("provider") or payload.brain,
            "model": vote.get("model") or "subscription-default",
            "model_profile": payload.brain,
            "tenant_id": payload.tenant_id,
            "data_classification": payload.data_classification,
            "outcome": decision.outcome.value if vote.get("available") else "unavailable",
            "policy_name": decision.policy_name,
            "reason": vote.get("reason") or decision.reason,
            "latency_ms": vote.get("latency_ms") or 0,
            "token_count": vote.get("token_count") or 0,
        }
    )
    return BrainInvokeResponse(**vote)


@router.post("/consensus", response_model=ConsensusResponse, summary="Run governed multi-Brain consensus")
async def route_consensus(
    payload: ConsensusRequest,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    payload = payload.model_copy(update={"tenant_id": tenant_id})
    unique_sources = list(dict.fromkeys(payload.sources))
    allowed_sources: list[str] = []
    allowed_decisions: dict[str, object] = {}
    denied_votes: list[dict] = []
    policy_outcomes: list[str] = []

    for source in unique_sources:
        if source in _EXTERNAL_BRAINS and payload.data_classification in {"restricted", "top_secret"}:
            policy_outcomes.append("blocked")
            denied_votes.append(
                {
                    "source": source,
                    "kind": "subscription",
                    "available": True,
                    "counted": False,
                    "reason": "External subscription Brains cannot receive this data classification.",
                    "policy_outcome": "blocked",
                }
            )
            continue
        decision = await _enforce_brain_call(
            db,
            source=source,
            claw=payload.claw,
            classification=payload.data_classification,
            tenant_id=payload.tenant_id,
            context={"consensus": True, **payload.context},
        )
        policy_outcomes.append(decision.outcome.value)
        if decision.allowed:
            allowed_sources.append(source)
            allowed_decisions[source] = decision
        else:
            denied_votes.append(
                {
                    "source": source,
                    "kind": "desktop_session" if source.endswith("_desktop") else "browser_session" if source.endswith("_browser") else "subscription" if source in _EXTERNAL_BRAINS else "profile",
                    "available": True,
                    "counted": False,
                    "reason": decision.reason,
                    "policy_outcome": decision.outcome.value,
                }
            )

    collection_kwargs = {
        "tenant_id": payload.tenant_id,
        "claw": payload.claw,
        "data_classification": payload.data_classification,
    }
    session_id = derive_brain_session_id(payload.tenant_id, payload.context)
    if session_id:
        collection_kwargs["session_id"] = session_id
    votes = await collect_votes(db, allowed_sources, payload.prompt, **collection_kwargs)
    for vote in votes:
        decision = allowed_decisions[vote["source"]]
        vote["policy_outcome"] = decision.outcome.value
        record_model_call(
            {
                "claw": payload.claw,
                "provider": vote.get("provider") or vote["source"],
                "model": vote.get("model") or "unknown",
                "model_profile": vote["source"],
                "tenant_id": payload.tenant_id,
                "data_classification": payload.data_classification,
                "outcome": decision.outcome.value if vote.get("counted") else "unavailable",
                "policy_name": decision.policy_name,
                "reason": vote.get("reason") or decision.reason,
                "latency_ms": vote.get("latency_ms") or 0,
                "token_count": vote.get("token_count") or 0,
            }
        )

    all_votes = votes + denied_votes
    counted = [vote for vote in all_votes if vote.get("counted") and vote.get("response")]
    consensus, confidence, agreement = deterministic_consensus(counted, payload.minimum_votes)
    status = "completed" if len(counted) >= payload.minimum_votes else "insufficient_votes"
    return ConsensusResponse(
        status=status,
        consensus=consensus,
        confidence=confidence,
        agreement=agreement,
        counted_votes=len(counted),
        requested_votes=len(unique_sources),
        votes=[BrainVoteRead(**vote) for vote in all_votes],
        policy_outcome="allowed" if all(outcome == "allowed" for outcome in policy_outcomes) else "partially_allowed",
        synthesis_source="deterministic_evidence_overlap",
    )


def _deterministic_consensus(votes: list[dict], minimum_votes: int) -> tuple[str | None, float, str]:
    """Compatibility wrapper retained for existing callers and tests."""
    return deterministic_consensus(votes, minimum_votes)


@router.post("/gateway", response_model=CortexGatewayResponse, summary="Governed universal Cortex gateway")
async def route_cortex_gateway(
    payload: CortexGatewayRequest,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await execute_cortex_gateway(db, payload.model_copy(update={"tenant_id": tenant_id}))


@router.post("/route", response_model=ModelRouteResponse, summary="Route a model call through Trust Fabric")
async def route_model_call(
    payload: ModelRouteRequest,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    payload = payload.model_copy(update={"tenant_id": tenant_id})
    profile = get_profile(payload.model_profile, tenant_id=payload.tenant_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Model profile not found")

    if profile["allowed_claws"] and payload.claw not in profile["allowed_claws"]:
        raise HTTPException(status_code=403, detail="Capability is not allowed for selected model profile")

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
        f"Model Cortex response from {profile['provider']}:{profile['model']} for {payload.claw} "
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
