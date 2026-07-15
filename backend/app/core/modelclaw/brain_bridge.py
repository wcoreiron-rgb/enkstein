from __future__ import annotations

import asyncio
import logging
import os
import socket
import re
from time import perf_counter
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.claws.arcclaw.llm_proxy import call_llm, fetch_ollama_models
from app.claws.arcclaw.scanner import scan_text
from app.core.config import settings
from app.core.modelclaw.service import get_profile
from app.models.connector import Connector, ConnectorStatus
from app.services import secrets_manager

logger = logging.getLogger(__name__)

_SUBSCRIPTION_BRAINS = {
    "codex_subscription",
    "claude_subscription",
    "chatgpt_desktop",
    "claude_desktop",
    "chatgpt_browser",
    "claude_browser",
    "gemini_browser",
}
_PROVIDER_ALIASES = {"nvidia_nim": "nvidia"}
_LOCAL_MODEL_PREFERENCES = (
    "regent-aegis:bc",
    "qwen2.5:7b",
    "llama3.2",
    "phi3",
)


def _brain_kind(name: str) -> str:
    if name.endswith("_desktop"):
        return "desktop_session"
    if name.endswith("_browser"):
        return "browser_session"
    return "subscription"


def _installed_ollama_model(requested: str, installed: list[str]) -> str | None:
    requested_name = requested.strip().lower()
    requested_canonical = requested_name if ":" in requested_name else f"{requested_name}:latest"
    for installed_name in installed:
        candidate = installed_name.strip().lower()
        candidate_canonical = candidate if ":" in candidate else f"{candidate}:latest"
        if candidate == requested_name or candidate_canonical == requested_canonical:
            return installed_name
    return None


def _select_ollama_model(profile_model: str, installed: list[str], requested: str | None) -> str | None:
    if requested:
        return _installed_ollama_model(requested, installed)
    configured = os.getenv("MARCELLUS_OLLAMA_MODEL", "").strip()
    candidates = [configured, profile_model, *_LOCAL_MODEL_PREFERENCES]
    for candidate in candidates:
        if not candidate:
            continue
        resolved = _installed_ollama_model(candidate, installed)
        if resolved:
            return resolved
    return installed[0] if installed else None


def bridge_configured() -> bool:
    return bool(settings.BRAIN_BRIDGE_URL and settings.BRAIN_BRIDGE_SECRET)


async def bridge_status() -> list[dict[str, Any]]:
    if not bridge_configured():
        detail = "Native Brain Bridge is not configured for this runtime."
        return [
            {
                "brain": name,
                "kind": _brain_kind(name),
                "available": False,
                "authenticated": False,
                "detail": detail,
            }
            for name in sorted(_SUBSCRIPTION_BRAINS)
        ]

    try:
        body = await _bridge_request("GET", "/v1/status")
        return list(body.get("brains", []))
    except Exception as exc:
        logger.warning("Native Brain Bridge status failed: %s", type(exc).__name__)
        return [
            {
                "brain": name,
                "kind": _brain_kind(name),
                "available": False,
                "authenticated": False,
                "detail": "Native Brain Bridge is unreachable.",
            }
            for name in sorted(_SUBSCRIPTION_BRAINS)
        ]


async def request_desktop_brain_access() -> dict[str, Any]:
    if not bridge_configured():
        return {
            "granted": False,
            "detail": "Native Brain Bridge is not configured for this runtime.",
        }
    try:
        body = await _bridge_request("POST", "/v1/accessibility/request", {})
        return {
            "granted": bool(body.get("granted")),
            "detail": str(body.get("detail") or "Accessibility permission request completed."),
        }
    except Exception as exc:
        logger.warning("Desktop Brain access request failed: %s", type(exc).__name__)
        return {
            "granted": False,
            "detail": "Marcellus could not request desktop app access.",
        }


async def create_browser_brain_pairing() -> dict[str, Any]:
    if not bridge_configured():
        return {"available": False, "detail": "Native Brain Bridge is not configured for this runtime."}
    try:
        body = await _bridge_request("POST", "/v1/browser/pair", {})
        setup_url = str(body.get("setup_url") or "")
        if not setup_url.startswith("http://127.0.0.1:"):
            raise ValueError("Invalid browser pairing URL")
        return {
            "available": True,
            "setup_url": setup_url,
            "opened": bool(body.get("opened")),
            "expires_in_seconds": int(body.get("expires_in_seconds") or 300),
        }
    except Exception as exc:
        logger.warning("Browser Brain pairing failed: %s", type(exc).__name__)
        return {"available": False, "detail": "Marcellus could not start browser pairing."}


async def open_browser_companion_folder() -> dict[str, Any]:
    if not bridge_configured():
        return {"opened": False, "detail": "Native Brain Bridge is not configured for this runtime."}
    try:
        body = await _bridge_request("POST", "/v1/browser/open-extension", {})
        return {"opened": bool(body.get("opened")), "detail": body.get("detail")}
    except Exception as exc:
        logger.warning("Browser companion folder open failed: %s", type(exc).__name__)
        return {"opened": False, "detail": "Marcellus could not open the browser companion folder."}


async def invoke_subscription_brain(
    brain: str,
    prompt: str,
    *,
    model: str | None = None,
) -> dict[str, Any]:
    if brain not in _SUBSCRIPTION_BRAINS:
        raise ValueError("Unknown subscription Brain")
    if not bridge_configured():
        return _unavailable_vote(brain, _brain_kind(brain), "Native Brain Bridge is not configured.")

    input_scan = scan_text(prompt, redact=True)
    transmitted_prompt = input_scan.redacted if input_scan.is_sensitive else prompt
    started = perf_counter()
    try:
        body = await _bridge_request(
            "POST",
            "/v1/invoke",
            {"brain": brain, "prompt": transmitted_prompt, "model": model},
        )
    except Exception as exc:
        logger.warning("Subscription Brain invocation failed: brain=%s error=%s", brain, type(exc).__name__)
        return _unavailable_vote(brain, _brain_kind(brain), "Native Brain invocation failed.")

    response = str(body.get("response") or "")
    if not body.get("success") or not response:
        return _unavailable_vote(
            brain,
            _brain_kind(brain),
            str(body.get("detail") or "Subscription Brain returned no response."),
        )

    output_scan = scan_text(response, redact=True)
    return {
        "source": brain,
        "kind": _brain_kind(brain),
        "available": True,
        "counted": True,
        "provider": str(body.get("provider") or brain),
        "model": body.get("model"),
        "response": output_scan.redacted if output_scan.is_sensitive else response,
        "reason": _redaction_reason(input_scan.is_sensitive, output_scan.is_sensitive),
        "latency_ms": int(body.get("latency_ms") or ((perf_counter() - started) * 1000)),
        "token_count": body.get("token_count"),
    }


async def invoke_native_workspace(operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Invoke a folder-scoped native workspace operation through the authenticated host bridge."""
    if operation not in {"list", "write", "trash"}:
        raise ValueError("Unsupported native workspace operation")
    if not bridge_configured():
        raise RuntimeError("Native workspace bridge is not configured")
    return await _bridge_request("POST", f"/v1/workspace/{operation}", payload)


async def invoke_profile_brain(
    db: AsyncSession,
    source: str,
    prompt: str,
    *,
    tenant_id: str,
    claw: str,
    data_classification: str,
    model: str | None = None,
) -> dict[str, Any]:
    prepared = await _prepare_profile_brain(
        db,
        source,
        tenant_id=tenant_id,
        claw=claw,
        data_classification=data_classification,
        model=model,
    )
    if "unavailable_vote" in prepared:
        return prepared["unavailable_vote"]
    return await _invoke_prepared_profile(prepared, prompt)


async def _prepare_profile_brain(
    db: AsyncSession,
    source: str,
    *,
    tenant_id: str,
    claw: str,
    data_classification: str,
    model: str | None = None,
) -> dict[str, Any]:
    """Resolve profile policy and credentials before parallel provider I/O begins."""
    profile_name = source.removeprefix("profile:")
    profile = get_profile(profile_name, tenant_id=tenant_id)
    if not profile:
        return {"unavailable_vote": _unavailable_vote(source, "profile", "Model profile was not found for this tenant.")}
    if profile["allowed_claws"] and claw not in profile["allowed_claws"]:
        return {"unavailable_vote": _unavailable_vote(source, "profile", "The requesting capability is not allowed by this profile.")}
    if data_classification not in profile["allowed_data_classes"]:
        return {"unavailable_vote": _unavailable_vote(source, "profile", "The data classification is not allowed by this profile.")}

    provider = _PROVIDER_ALIASES.get(profile["provider"], profile["provider"])
    resolved_model = model or profile["model"]
    allowed_models = profile.get("allowed_models")
    if provider == "ollama":
        installed_models, runtime_ready = await fetch_ollama_models()
        if not runtime_ready:
            return {"unavailable_vote": _unavailable_vote(source, "local", "The local model runtime is not available.")}
        selected_model = _select_ollama_model(profile["model"], installed_models, model)
        if not selected_model:
            return {"unavailable_vote": _unavailable_vote(source, "local", "The requested model is not installed locally.")}
        resolved_model = selected_model
    elif resolved_model not in (allowed_models or [profile["model"]]):
        return {"unavailable_vote": _unavailable_vote(source, "api", "The requested model is not allowed by this model profile.")}

    api_key: str | None = None
    if provider != "ollama":
        api_key = await _resolve_provider_key(db, profile["provider"])
        if not api_key:
            return {"unavailable_vote": _unavailable_vote(source, "api", "The approved provider connector is not configured.")}

    return {
        "source": source,
        "profile": profile,
        "provider": provider,
        "model": resolved_model,
        "api_key": api_key,
    }


async def _invoke_prepared_profile(prepared: dict[str, Any], prompt: str) -> dict[str, Any]:
    source = prepared["source"]
    profile = prepared["profile"]
    provider = prepared["provider"]
    resolved_model = prepared["model"]
    api_key = prepared["api_key"]

    input_scan = scan_text(prompt, redact=True)
    transmitted_prompt = (
        input_scan.redacted
        if profile.get("requires_redaction", True) and input_scan.is_sensitive
        else prompt
    )
    started = perf_counter()
    result = await call_llm(
        provider,
        transmitted_prompt,
        model=resolved_model,
        system=(
            "You are a reasoning-only Brain inside Marcellus. Return a concise, evidence-aware answer. "
            "Do not claim to have executed tools or changed systems."
        ),
        api_key=api_key,
    )
    if not result.success or not result.content:
        return _unavailable_vote(
            source,
            "local" if provider == "ollama" else "api",
            "The provider invocation failed or the configured model is unavailable.",
        )

    output_scan = scan_text(result.content, redact=True)
    input_redacted = transmitted_prompt != prompt
    return {
        "source": source,
        "kind": "local" if provider == "ollama" else "api",
        "available": True,
        "counted": True,
        "provider": provider,
        "model": result.model,
        "response": output_scan.redacted if output_scan.is_sensitive else result.content,
        "reason": _redaction_reason(input_redacted, output_scan.is_sensitive),
        "latency_ms": int((perf_counter() - started) * 1000),
        "token_count": result.tokens_used,
    }


async def collect_votes(
    db: AsyncSession,
    sources: list[str],
    prompt: str,
    *,
    tenant_id: str,
    claw: str,
    data_classification: str,
    model: str | None = None,
    subscription_invoker=None,
) -> list[dict[str, Any]]:
    prepared: dict[str, dict[str, Any]] = {}
    for source in sources:
        if source.startswith("profile:"):
            prepared[source] = await _prepare_profile_brain(
                db,
                source,
                tenant_id=tenant_id,
                claw=claw,
                data_classification=data_classification,
                model=model,
            )

    async def invoke(source: str) -> dict[str, Any]:
        if source in _SUBSCRIPTION_BRAINS:
            invoker = subscription_invoker or invoke_subscription_brain
            return await invoker(source, prompt, model=model)
        if source.startswith("profile:"):
            profile_call = prepared[source]
            if "unavailable_vote" in profile_call:
                return profile_call["unavailable_vote"]
            return await _invoke_prepared_profile(profile_call, prompt)
        return _unavailable_vote(source, "unknown", "Unsupported Brain source.")

    return list(await asyncio.gather(*(invoke(source) for source in sources)))


async def _resolve_provider_key(db: AsyncSession, provider: str) -> str | None:
    connector_type = "nvidia_nim" if provider in {"nvidia", "nvidia_nim"} else provider
    try:
        result = await db.execute(
            select(Connector).where(
                Connector.connector_type == connector_type,
                Connector.status == ConnectorStatus.APPROVED,
            )
        )
        connector = result.scalars().first()
        if not connector:
            return None
        credentials = secrets_manager.get_credential(str(connector.id)) or {}
        return credentials.get("api_key") or credentials.get("api_token")
    except Exception:
        return None


async def _bridge_request(method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    timeout = httpx.Timeout(float(settings.BRAIN_BRIDGE_TIMEOUT_SECONDS), connect=5.0)
    endpoint, host_header = _bridge_endpoint(path)
    headers = {
        "X-Marcellus-Bridge-Token": settings.BRAIN_BRIDGE_SECRET,
        "Host": host_header,
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.request(
            method,
            endpoint,
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError("Invalid Brain Bridge response")
        return body


def _bridge_endpoint(path: str) -> tuple[str, str]:
    parsed = urlparse(settings.BRAIN_BRIDGE_URL)
    if parsed.scheme != "http" or parsed.hostname not in {"host.docker.internal", "127.0.0.1", "localhost"}:
        raise ValueError("Brain Bridge URL must target the local host gateway")
    port = parsed.port or 80
    host = parsed.hostname
    if host == "host.docker.internal":
        addresses = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if not addresses:
            raise ValueError("No IPv4 host gateway is available")
        host = addresses[0][4][0]
    return f"http://{host}:{port}{path}", f"{parsed.hostname}:{port}"


def _unavailable_vote(source: str, kind: str, reason: str) -> dict[str, Any]:
    return {
        "source": source,
        "kind": kind,
        "available": False,
        "counted": False,
        "reason": reason[:240],
    }


def _redaction_reason(input_redacted: bool, output_redacted: bool) -> str | None:
    if input_redacted and output_redacted:
        return "Input and output were redacted by Marcellus."
    if input_redacted:
        return "Sensitive input was redacted before provider invocation."
    if output_redacted:
        return "Output was redacted by Marcellus."
    return None


def deterministic_consensus(votes: list[dict], minimum_votes: int) -> tuple[str | None, float, str]:
    if not votes:
        return None, 0.0, "none"
    if len(votes) < minimum_votes:
        return votes[0]["response"], 0.35, "insufficient"

    token_sets = [_meaningful_tokens(vote["response"]) for vote in votes]
    similarities: list[float] = []
    for index, left in enumerate(token_sets):
        for right in token_sets[index + 1 :]:
            union = left | right
            similarities.append(len(left & right) / len(union) if union else 0.0)
    overlap = sum(similarities) / len(similarities) if similarities else 1.0
    agreement = "high" if overlap >= 0.42 else "moderate" if overlap >= 0.22 else "low"
    vote_factor = min(1.0, len(votes) / max(minimum_votes, 3))
    confidence = round(min(0.95, 0.45 + (0.35 * overlap) + (0.15 * vote_factor)), 2)

    source_priority = {"codex_subscription": 0, "claude_subscription": 1}
    primary = min(votes, key=lambda vote: source_priority.get(vote["source"], 2))
    return primary["response"], confidence, agreement


def _meaningful_tokens(text: str) -> set[str]:
    stop = {"that", "this", "with", "from", "have", "will", "your", "into", "should", "would", "about"}
    return {token for token in re.findall(r"[a-z0-9_-]{4,}", text.lower()) if token not in stop}
