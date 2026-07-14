from __future__ import annotations

import asyncio
import logging
import socket
import re
from time import perf_counter
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.claws.arcclaw.llm_proxy import call_llm
from app.claws.arcclaw.scanner import scan_text
from app.core.config import settings
from app.core.modelclaw.service import get_profile
from app.models.connector import Connector, ConnectorStatus
from app.services import secrets_manager

logger = logging.getLogger(__name__)

_SUBSCRIPTION_BRAINS = {"codex_subscription", "claude_subscription"}
_PROVIDER_ALIASES = {"nvidia_nim": "nvidia"}


def bridge_configured() -> bool:
    return bool(settings.BRAIN_BRIDGE_URL and settings.BRAIN_BRIDGE_SECRET)


async def bridge_status() -> list[dict[str, Any]]:
    if not bridge_configured():
        detail = "Native Brain Bridge is not configured for this runtime."
        return [
            {
                "brain": name,
                "kind": "subscription",
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
                "kind": "subscription",
                "available": False,
                "authenticated": False,
                "detail": "Native Brain Bridge is unreachable.",
            }
            for name in sorted(_SUBSCRIPTION_BRAINS)
        ]


async def invoke_subscription_brain(
    brain: str,
    prompt: str,
    *,
    model: str | None = None,
) -> dict[str, Any]:
    if brain not in _SUBSCRIPTION_BRAINS:
        raise ValueError("Unknown subscription Brain")
    if not bridge_configured():
        return _unavailable_vote(brain, "subscription", "Native Brain Bridge is not configured.")

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
        return _unavailable_vote(brain, "subscription", "Native Brain invocation failed.")

    response = str(body.get("response") or "")
    if not body.get("success") or not response:
        return _unavailable_vote(
            brain,
            "subscription",
            str(body.get("detail") or "Subscription Brain returned no response."),
        )

    output_scan = scan_text(response, redact=True)
    return {
        "source": brain,
        "kind": "subscription",
        "available": True,
        "counted": True,
        "provider": str(body.get("provider") or brain),
        "model": body.get("model"),
        "response": output_scan.redacted if output_scan.is_sensitive else response,
        "reason": _redaction_reason(input_scan.is_sensitive, output_scan.is_sensitive),
        "latency_ms": int(body.get("latency_ms") or ((perf_counter() - started) * 1000)),
        "token_count": body.get("token_count"),
    }


async def invoke_profile_brain(
    db: AsyncSession,
    source: str,
    prompt: str,
    *,
    tenant_id: str,
    claw: str,
    data_classification: str,
) -> dict[str, Any]:
    profile_name = source.removeprefix("profile:")
    profile = get_profile(profile_name, tenant_id=tenant_id)
    if not profile:
        return _unavailable_vote(source, "profile", "Model profile was not found for this tenant.")
    if profile["allowed_claws"] and claw not in profile["allowed_claws"]:
        return _unavailable_vote(source, "profile", "The requesting capability is not allowed by this profile.")
    if data_classification not in profile["allowed_data_classes"]:
        return _unavailable_vote(source, "profile", "The data classification is not allowed by this profile.")

    provider = _PROVIDER_ALIASES.get(profile["provider"], profile["provider"])
    api_key: str | None = None
    if provider != "ollama":
        api_key = await _resolve_provider_key(db, profile["provider"])
        if not api_key:
            return _unavailable_vote(source, "api", "The approved provider connector is not configured.")

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
        model=profile["model"],
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
) -> list[dict[str, Any]]:
    async def invoke(source: str) -> dict[str, Any]:
        if source in _SUBSCRIPTION_BRAINS:
            return await invoke_subscription_brain(source, prompt)
        if source.startswith("profile:"):
            return await invoke_profile_brain(
                db,
                source,
                prompt,
                tenant_id=tenant_id,
                claw=claw,
                data_classification=data_classification,
            )
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
