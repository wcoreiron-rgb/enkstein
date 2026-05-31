"""
RegentClaw — Secure Model Router API Routes
"""
import logging
import threading
import time
from collections import defaultdict
from fastapi import APIRouter, HTTPException
from fastapi import Depends, Request, status
from pydantic import BaseModel, Field

from app.services.model_router import (
    route_and_call,
    classify_sensitivity,
    get_routing_table,
    update_routing_rule,
    reset_routing_table,
    get_provider_status,
    get_routing_audit,
    _DEFAULT_ROUTING_TABLE,
    _SENSITIVITY_RANK,
    _PROVIDER_BACKENDS,
    Sensitivity,
    Provider,
)

logger = logging.getLogger("regentclaw.model_router_api")
router = APIRouter(prefix="/model-router", tags=["Model Router"])

# ── In-process rate limiter for model routing (LLM04 hardening) ─────────────
# For horizontally scaled deployments, swap for Redis-backed centralized limits.
_MODEL_ROUTE_WINDOW = 60
_MODEL_ROUTE_MAX = 30
_model_route_store: dict[str, list[float]] = defaultdict(list)
_model_route_lock = threading.Lock()


def _model_route_rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    cutoff = now - _MODEL_ROUTE_WINDOW
    with _model_route_lock:
        window = [t for t in _model_route_store[ip] if t > cutoff]
        if len(window) >= _MODEL_ROUTE_MAX:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many model route requests — please retry shortly.",
                headers={"Retry-After": "60"},
            )
        window.append(now)
        _model_route_store[ip] = window

# ─── Schemas ──────────────────────────────────────────────────────────────────

class RouteRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=32_000)
    sensitivity_override: str | None = None
    provider_override: str | None = None
    model_override: str | None = None
    caller: str = Field(default="api")
    context_labels: list[str] | None = None
    override_reason: str | None = Field(default=None, max_length=512)


class ClassifyRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=32_000)


class RoutingRuleUpdate(BaseModel):
    sensitivity: str
    provider: str


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/route", summary="Route a prompt to the appropriate model backend")
async def route_prompt(
    body: RouteRequest,
    request: Request,
    _rl: None = Depends(_model_route_rate_limit),
):
    """
    Classify the prompt's data sensitivity, route to the correct provider,
    call the model, and return the response with a full routing audit entry.
    """
    try:
        result = await route_and_call(
            prompt=body.prompt,
            sensitivity_override=body.sensitivity_override,
            provider_override=body.provider_override,
            model_override=body.model_override,
            caller=body.caller,
            context_labels=body.context_labels,
            override_reason=body.override_reason,
        )
        return result
    except Exception:
        logger.exception("Model router call failed")
        raise HTTPException(status_code=502, detail="Model provider request failed")


@router.post("/classify", summary="Classify text data sensitivity (dry-run, no model call)")
def classify_text(body: ClassifyRequest):
    """Return sensitivity classification without calling any model."""
    result = classify_sensitivity(body.text)
    routed_to = get_routing_table().get(result["level"], "unknown")
    return {
        **result,
        "routed_to": routed_to,
        "routing_rationale": _routing_rationale(result["level"], routed_to),
    }


@router.get("/routing-table", summary="Get current sensitivity → provider routing rules")
def get_rules():
    table = get_routing_table()
    return {
        "routing_table": [
            {
                "sensitivity": s,
                "sensitivity_rank": _SENSITIVITY_RANK[s],
                "provider": p,
                "tier": _provider_tier(p),
                "rationale": _routing_rationale(s, p),
            }
            for s, p in sorted(table.items(), key=lambda x: _SENSITIVITY_RANK[x[0]])
        ]
    }


@router.patch("/routing-table", summary="Update a single routing rule")
def update_rule(body: RoutingRuleUpdate):
    try:
        update_routing_rule(body.sensitivity, body.provider)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid routing rule update")
    return {"updated": True, "sensitivity": body.sensitivity, "provider": body.provider}


@router.post("/routing-table/reset", summary="Reset routing table to defaults")
def reset_rules():
    reset_routing_table()
    return {"reset": True, "routing_table": get_routing_table()}


@router.get("/providers", summary="List providers and availability status")
def list_providers():
    status = get_provider_status()
    return {
        "providers": list(status.values()),
        "sensitivity_levels": list(_SENSITIVITY_RANK.keys()),
    }


@router.get("/audit", summary="Recent routing decisions")
def routing_audit(limit: int = 50):
    if limit > 500:
        limit = 500
    entries = get_routing_audit(limit)
    return {"count": len(entries), "entries": entries}


@router.get("/sensitivity-levels", summary="Reference: all sensitivity levels and their routing")
def sensitivity_reference():
    table = get_routing_table()
    return {
        "levels": [
            {
                "level": s,
                "rank": r,
                "provider": table.get(s, "unknown"),
                "tier": _provider_tier(table.get(s, "")),
                "description": _sensitivity_description(s),
                "examples": _sensitivity_examples(s),
            }
            for s, r in sorted(_SENSITIVITY_RANK.items(), key=lambda x: x[1])
        ]
    }


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _provider_tier(provider: str) -> str:
    if provider == Provider.OLLAMA:       return "local"
    if provider == Provider.AZURE_OPENAI: return "enterprise"
    if provider in (Provider.ANTHROPIC, Provider.OPENAI): return "cloud"
    return "unknown"


def _routing_rationale(sensitivity: str, provider: str) -> str:
    tier = _provider_tier(provider)
    return {
        "local":      f"{sensitivity.upper()} data stays on-premises — routed to local Ollama.",
        "enterprise": f"{sensitivity.upper()} data routed to enterprise VNet-peered Azure OpenAI.",
        "cloud":      f"{sensitivity.upper()} data safe for internet-accessible cloud providers.",
    }.get(tier, "No rationale available.")


def _sensitivity_description(level: str) -> str:
    return {
        Sensitivity.PUBLIC:       "Publicly available information — no restrictions.",
        Sensitivity.INTERNAL:     "Company-internal data — not for external sharing.",
        Sensitivity.CONFIDENTIAL: "Regulated, PII, or business-sensitive data.",
        Sensitivity.RESTRICTED:   "Credentials, secrets, and highly sensitive personal data.",
        Sensitivity.TOP_SECRET:   "Classified, cryptographic keys, board-level information.",
    }.get(level, "Unknown")


def _sensitivity_examples(level: str) -> list[str]:
    return {
        Sensitivity.PUBLIC:       ["Blog posts", "Press releases", "Marketing copy"],
        Sensitivity.INTERNAL:     ["Security findings", "CVE analysis", "IOC lookups"],
        Sensitivity.CONFIDENTIAL: ["Customer PII", "HIPAA records", "HR data"],
        Sensitivity.RESTRICTED:   ["Passwords", "OAuth tokens", "SSN / credit cards"],
        Sensitivity.TOP_SECRET:   ["API keys", "Private keys", "Classified reports"],
    }.get(level, [])
