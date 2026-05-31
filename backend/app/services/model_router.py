"""
RegentClaw — Secure Model Router
Routes AI/LLM calls to the appropriate back-end based on data sensitivity,
policy rules, and provider availability.

Routing tiers (highest → lowest trust with external services):
  LOCAL     → Ollama  (air-gapped, on-premises — for RESTRICTED / TOP-SECRET data)
  ENTERPRISE→ Azure OpenAI (VNet-peered, no data egress — for CONFIDENTIAL data)
  CLOUD     → Anthropic / OpenAI (internet — for PUBLIC / INTERNAL data only)

Each call is classified, routed, and logged to the audit trail.
"""
import re
import json
import logging
import hashlib
import asyncio
from datetime import datetime
from typing import Any

from app.claws.arcclaw.scanner import scan_text

logger = logging.getLogger("regentclaw.model_router")


# ─── Data sensitivity levels ──────────────────────────────────────────────────
class Sensitivity:
    PUBLIC       = "public"       # No restrictions
    INTERNAL     = "internal"     # Company internal
    CONFIDENTIAL = "confidential" # Regulated / PII / business-sensitive
    RESTRICTED   = "restricted"   # Secrets, credentials, board-level
    TOP_SECRET   = "top_secret"   # Nation-state / classified


_SENSITIVITY_RANK = {
    Sensitivity.PUBLIC:       0,
    Sensitivity.INTERNAL:     1,
    Sensitivity.CONFIDENTIAL: 2,
    Sensitivity.RESTRICTED:   3,
    Sensitivity.TOP_SECRET:   4,
}

# ─── Provider registry ────────────────────────────────────────────────────────
class Provider:
    OLLAMA        = "ollama"       # Local
    AZURE_OPENAI  = "azure_openai" # Enterprise
    ANTHROPIC     = "anthropic"    # Cloud
    OPENAI        = "openai"       # Cloud
    NVIDIA        = "nvidia"       # Cloud — free tier (NVIDIA NIM)
    MOCK          = "mock"         # Dev / test fallback


# Default routing table: sensitivity → provider
_DEFAULT_ROUTING_TABLE: dict[str, str] = {
    Sensitivity.PUBLIC:       Provider.ANTHROPIC,
    Sensitivity.INTERNAL:     Provider.ANTHROPIC,
    Sensitivity.CONFIDENTIAL: Provider.AZURE_OPENAI,
    Sensitivity.RESTRICTED:   Provider.OLLAMA,
    Sensitivity.TOP_SECRET:   Provider.OLLAMA,
}

# Configurable routing table (loaded from settings / DB in production)
_routing_table: dict[str, str] = dict(_DEFAULT_ROUTING_TABLE)
_provider_status: dict[str, str] = {}  # provider_id → "healthy" | "degraded" | "offline"


# ─── Sensitivity classifier ───────────────────────────────────────────────────
# Pattern → sensitivity level (first match wins, ordered highest→lowest)
_SENSITIVITY_PATTERNS: list[tuple[str, str]] = [
    # TOP SECRET
    (r"\b(api[_ ]?key|secret[_ ]?key|private[_ ]?key|ssh[_ ]?key|bearer[_ ]?token|access[_ ]?token)\b",
     Sensitivity.TOP_SECRET),
    (r"\b(classified|top[_ ]secret|ultra[_ ]secret|compartmented)\b",
     Sensitivity.TOP_SECRET),

    # RESTRICTED
    (r"\b(password|passphrase|credential|auth[_ ]?token|oauth[_ ]?token|jwt[_ ]?token)\b",
     Sensitivity.RESTRICTED),
    (r"\b(ssn|social[_ ]?security|national[_ ]?id|passport[_ ]?number)\b",
     Sensitivity.RESTRICTED),
    (r"\b(credit[_ ]?card|cvv|card[_ ]?number|bank[_ ]?account|routing[_ ]?number)\b",
     Sensitivity.RESTRICTED),
    (r"\b(confidential|restricted|do[_ ]?not[_ ]?distribute|nda)\b",
     Sensitivity.RESTRICTED),

    # CONFIDENTIAL
    (r"\b(pii|personally[_ ]?identifiable|phi|protected[_ ]?health|medical[_ ]?record)\b",
     Sensitivity.CONFIDENTIAL),
    (r"\b(hipaa|gdpr|pci.?dss|sox|glba)\b",
     Sensitivity.CONFIDENTIAL),
    (r"\b(salary|compensation|hr[_ ]?record|performance[_ ]?review|disciplinary)\b",
     Sensitivity.CONFIDENTIAL),
    (r"\b(customer[_ ]?data|client[_ ]?data|user[_ ]?data|personal[_ ]?data)\b",
     Sensitivity.CONFIDENTIAL),
    (r"\b(internal[_ ]?only|sensitive|proprietary|trade[_ ]?secret)\b",
     Sensitivity.CONFIDENTIAL),
    # IP addresses / hostnames that look internal
    (r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
     Sensitivity.CONFIDENTIAL),

    # INTERNAL
    (r"\b(internal|corp|corporate|intranet|employee|staff)\b",
     Sensitivity.INTERNAL),
    (r"\b(incident|finding|vulnerability|cve|alert|ioc)\b",
     Sensitivity.INTERNAL),
]


def classify_sensitivity(text: str) -> dict[str, Any]:
    """
    Classify the sensitivity of `text`.
    Returns {"level": str, "matched_rule": str|None, "confidence": float}
    """
    lower = text.lower()
    for pattern, level in _SENSITIVITY_PATTERNS:
        m = re.search(pattern, lower)
        if m:
            return {
                "level": level,
                "matched_rule": pattern[:60] + "…" if len(pattern) > 60 else pattern,
                "matched_text": m.group(0),
                "confidence": 0.90,
            }
    return {"level": Sensitivity.PUBLIC, "matched_rule": None, "matched_text": None, "confidence": 0.70}


# ─── Provider backends ────────────────────────────────────────────────────────

async def _call_mock(prompt: str, model: str, **_) -> dict:
    """Mock backend for development / test environments."""
    await asyncio.sleep(0.05)
    return {
        "provider": Provider.MOCK,
        "model": model or "mock-v1",
        "response": f"[MOCK RESPONSE] I processed your prompt ({len(prompt)} chars) using the mock backend.",
        "usage": {"prompt_tokens": len(prompt.split()), "completion_tokens": 42, "total_tokens": len(prompt.split()) + 42},
        "latency_ms": 50,
    }


async def _call_ollama(prompt: str, model: str = "mistral", base_url: str = "http://localhost:11434", **_) -> dict:
    """Call local Ollama instance."""
    import httpx
    from app.core.config import settings

    url = getattr(settings, "OLLAMA_BASE_URL", base_url) + "/api/generate"
    model = getattr(settings, "OLLAMA_MODEL", model)

    start = datetime.utcnow()
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(url, json={"model": model, "prompt": prompt, "stream": False})
        resp.raise_for_status()
    elapsed = int((datetime.utcnow() - start).total_seconds() * 1000)
    body = resp.json()

    return {
        "provider": Provider.OLLAMA,
        "model": model,
        "response": body.get("response", ""),
        "usage": {"prompt_tokens": body.get("prompt_eval_count", 0),
                  "completion_tokens": body.get("eval_count", 0),
                  "total_tokens": body.get("prompt_eval_count", 0) + body.get("eval_count", 0)},
        "latency_ms": elapsed,
    }


async def _call_azure_openai(prompt: str, model: str = "gpt-4o", **_) -> dict:
    """Call Azure OpenAI (requires AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_KEY env vars)."""
    import httpx
    from app.core.config import settings

    endpoint = getattr(settings, "AZURE_OPENAI_ENDPOINT", "")
    key      = getattr(settings, "AZURE_OPENAI_KEY", "")
    deploy   = getattr(settings, "AZURE_OPENAI_DEPLOYMENT", model)
    api_ver  = getattr(settings, "AZURE_OPENAI_API_VERSION", "2024-05-01-preview")

    if not endpoint or not key:
        raise ValueError("AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_KEY must be configured")

    url = f"{endpoint}/openai/deployments/{deploy}/chat/completions?api-version={api_ver}"
    start = datetime.utcnow()
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            url,
            headers={"api-key": key, "Content-Type": "application/json"},
            json={"messages": [{"role": "user", "content": prompt}], "max_tokens": 1000},
        )
        resp.raise_for_status()
    elapsed = int((datetime.utcnow() - start).total_seconds() * 1000)
    body = resp.json()

    return {
        "provider": Provider.AZURE_OPENAI,
        "model": deploy,
        "response": body["choices"][0]["message"]["content"],
        "usage": body.get("usage", {}),
        "latency_ms": elapsed,
    }


async def _call_nvidia(prompt: str, model: str = "nvidia/nemotron-4-340b-instruct", **_) -> dict:
    """
    Call NVIDIA NIM via its OpenAI-compatible endpoint.
    Free API key: https://build.nvidia.com/models
    Base URL: https://integrate.api.nvidia.com/v1
    """
    import httpx
    import os

    key = os.getenv("NVIDIA_API_KEY", "")
    if not key:
        raise ValueError(
            "NVIDIA_API_KEY not set. Get a free key at https://build.nvidia.com/models"
        )

    start = datetime.utcnow()
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
                "temperature": 0.2,
            },
        )
        resp.raise_for_status()
    elapsed = int((datetime.utcnow() - start).total_seconds() * 1000)
    body = resp.json()
    return {
        "provider": Provider.NVIDIA,
        "model": model,
        "response": body["choices"][0]["message"]["content"],
        "usage": body.get("usage", {}),
        "latency_ms": elapsed,
    }


async def _call_anthropic(prompt: str, model: str = "claude-3-5-sonnet-20241022", **_) -> dict:
    """Call Anthropic API."""
    import httpx
    from app.core.config import settings

    key = getattr(settings, "ANTHROPIC_API_KEY", "")
    if not key:
        raise ValueError("ANTHROPIC_API_KEY must be configured")

    start = datetime.utcnow()
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
    elapsed = int((datetime.utcnow() - start).total_seconds() * 1000)
    body = resp.json()

    return {
        "provider": Provider.ANTHROPIC,
        "model": model,
        "response": body["content"][0]["text"],
        "usage": body.get("usage", {}),
        "latency_ms": elapsed,
    }


_PROVIDER_BACKENDS = {
    Provider.OLLAMA:       _call_ollama,
    Provider.AZURE_OPENAI: _call_azure_openai,
    Provider.ANTHROPIC:    _call_anthropic,
    Provider.NVIDIA:       _call_nvidia,
    Provider.MOCK:         _call_mock,
}


# ─── Routing audit log ────────────────────────────────────────────────────────
_ROUTING_LOG: list[dict] = []  # In-memory ring buffer — last 500 entries


def _append_audit(entry: dict):
    _ROUTING_LOG.append(entry)
    if len(_ROUTING_LOG) > 500:
        _ROUTING_LOG.pop(0)


def get_routing_audit(limit: int = 50) -> list[dict]:
    return list(reversed(_ROUTING_LOG[-limit:]))


# ─── Public routing API ───────────────────────────────────────────────────────

def get_routing_table() -> dict[str, str]:
    return dict(_routing_table)


def update_routing_rule(sensitivity: str, provider: str):
    if sensitivity not in _SENSITIVITY_RANK:
        raise ValueError(f"Unknown sensitivity: {sensitivity}")
    if provider not in _PROVIDER_BACKENDS:
        raise ValueError(f"Unknown provider: {provider}")
    _routing_table[sensitivity] = provider


def reset_routing_table():
    _routing_table.clear()
    _routing_table.update(_DEFAULT_ROUTING_TABLE)


def get_provider_status() -> dict[str, dict]:
    providers = [Provider.OLLAMA, Provider.AZURE_OPENAI, Provider.ANTHROPIC, Provider.OPENAI, Provider.NVIDIA, Provider.MOCK]
    tier_map = {
        Provider.OLLAMA:       "local",
        Provider.AZURE_OPENAI: "enterprise",
        Provider.NVIDIA:       "cloud_free",
    }
    return {
        p: {
            "provider": p,
            "status": _provider_status.get(p, "unknown"),
            "tier": tier_map.get(p, "cloud"),
        }
        for p in providers
    }


async def route_and_call(
    prompt: str,
    *,
    sensitivity_override: str | None = None,
    provider_override: str | None = None,
    model_override: str | None = None,
    caller: str = "system",
    context_labels: list[str] | None = None,
    override_reason: str | None = None,
    allow_fallback: bool = True,
) -> dict[str, Any]:
    """
    Main entry point: classify → route → call → audit.

    Args:
        prompt: The text to send to the model.
        sensitivity_override: Skip classification, force this sensitivity level.
        provider_override: Bypass routing, call this specific provider.
        model_override: Override the default model for the chosen provider.
        caller: Identifier of the calling service/user (for audit).
        context_labels: Additional data classification labels from metadata.
        allow_fallback: If the routed provider fails, try MOCK (dev mode).
    """
    # ── Step 1: Classify ────────────────────────────────────────────────────
    if sensitivity_override:
        classification = {
            "level": sensitivity_override,
            "matched_rule": "override",
            "matched_text": None,
            "confidence": 1.0,
        }
    else:
        classification = classify_sensitivity(prompt)

    # Honour additional context labels (take highest sensitivity)
    if context_labels:
        for lbl in context_labels:
            if lbl in _SENSITIVITY_RANK:
                if _SENSITIVITY_RANK[lbl] > _SENSITIVITY_RANK[classification["level"]]:
                    classification["level"] = lbl
                    classification["matched_rule"] = "context_label"

    sensitivity = classification["level"]

    # ── Step 2: Resolve provider ────────────────────────────────────────────
    provider = provider_override or _routing_table.get(sensitivity, Provider.ANTHROPIC)
    override_used = bool(sensitivity_override or provider_override or model_override)

    # ── Step 3: Call backend ────────────────────────────────────────────────
    backend = _PROVIDER_BACKENDS.get(provider)
    if backend is None:
        raise ValueError(f"No backend registered for provider: {provider}")

    call_start = datetime.utcnow()
    error_msg: str | None = None
    result: dict = {}

    # Redact sensitive content before sending to non-local providers
    transmitted_prompt = _redact_if_needed(prompt, sensitivity, provider)

    try:
        result = await backend(transmitted_prompt, model=model_override or "")
    except Exception as exc:
        error_msg = str(exc)
        logger.warning("Model call failed: provider=%s error=%s", provider, exc)
        if allow_fallback and provider != Provider.MOCK:
            logger.info("Falling back to MOCK provider")
            result = await _call_mock(transmitted_prompt, model_override or "mock-v1")
            result["fallback"] = True
        else:
            raise

    call_end = datetime.utcnow()

    # ── Step 3b: Output re-scan (LLM02 hardening) ───────────────────────────
    raw_response = str(result.get("response", ""))
    output_scan = scan_text(raw_response, redact=True)
    response_redacted = output_scan.redacted if output_scan.is_sensitive else raw_response
    result["response"] = response_redacted
    result["output_scan"] = {
        "is_sensitive": output_scan.is_sensitive,
        "findings": output_scan.findings,
        "risk_signals": output_scan.risk_signals,
        "redacted": output_scan.is_sensitive,
    }

    # ── Step 4: Audit log ───────────────────────────────────────────────────
    audit_entry = {
        "id":           hashlib.sha256(f"{call_start.isoformat()}{caller}{prompt[:50]}".encode()).hexdigest()[:16],
        "timestamp":    call_start.isoformat() + "Z",
        "caller":       caller,
        "sensitivity":  sensitivity,
        "classification": classification,
        "provider":     provider,
        "model":        result.get("model", "unknown"),
        "fallback":     result.get("fallback", False),
        "error":        error_msg,
        "latency_ms":   result.get("latency_ms", int((call_end - call_start).total_seconds() * 1000)),
        "usage":        result.get("usage", {}),
        "prompt_hash":  hashlib.sha256(prompt.encode()).hexdigest()[:16],
        "prompt_chars": len(prompt),
        "redacted":     transmitted_prompt != prompt,
        "output_sensitive": output_scan.is_sensitive,
        "override_used": override_used,
        "override_reason": override_reason if override_used else None,
    }
    _append_audit(audit_entry)

    return {
        **result,
        "routing": {
            "sensitivity":    sensitivity,
            "provider":       provider,
            "classification": classification,
            "redacted":       audit_entry["redacted"],
            "override_used":  override_used,
            "override_reason": override_reason if override_used else None,
        },
        "audit_id": audit_entry["id"],
    }


def _redact_if_needed(prompt: str, sensitivity: str, provider: str) -> str:
    """
    If the prompt is RESTRICTED/TOP_SECRET and we're somehow calling a cloud
    provider (policy violation guard), redact potential secrets.
    Cloud providers should only receive PUBLIC/INTERNAL data — this is a
    last-resort safety net, not the primary control.
    """
    if provider in (Provider.ANTHROPIC, Provider.OPENAI, Provider.NVIDIA) and \
       _SENSITIVITY_RANK[sensitivity] >= _SENSITIVITY_RANK[Sensitivity.RESTRICTED]:
        # Redact anything that looks like a credential
        prompt = re.sub(
            r'(api[_-]?key|password|secret|token|key)\s*[:=]\s*[\w\-\.]+',
            r'\1=[REDACTED]',
            prompt,
            flags=re.IGNORECASE,
        )
    return prompt
