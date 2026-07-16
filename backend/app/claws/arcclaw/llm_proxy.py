"""
LLM Proxy Service
==============================
AI Security sits between the user and the LLM.
Every prompt is inspected BEFORE it reaches the model.

Flow:
  User prompt
      ↓
  AI Security scan (patterns + AGT injection audit)
      ↓
  Trust Fabric policy check
      ↓
  BLOCKED  → return decision, never call LLM
  ALLOWED  → forward to LLM, return response
  REDACTED → strip secrets, forward clean version

Supported providers:
  - OpenAI    (GPT-4o, GPT-4, GPT-3.5)  → needs OPENAI_API_KEY
  - Anthropic (Claude)                   → needs ANTHROPIC_API_KEY
  - Ollama    (any local model)          → free, no key, runs locally
  - NVIDIA NIM (80+ models — free tier)  → needs NVIDIA_API_KEY
    Base URL: https://integrate.api.nvidia.com/v1
    Get a free key at: https://build.nvidia.com/models
    Models: MiniMax M2.7, DeepSeek V3.2, Kimi K2.5, GLM 5.1, Nemotron, and many more
"""

from __future__ import annotations

import os
import json
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
NVIDIA_API_KEY    = os.getenv("NVIDIA_API_KEY", "")
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
OLLAMA_BASE_URL   = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")

# NVIDIA NIM — OpenAI-compatible endpoint
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"

TIMEOUT = 60.0  # seconds


# ── Response model ─────────────────────────────────────────────────────────────

@dataclass
class LLMResponse:
    provider: str
    model: str
    content: str
    tokens_used: int = 0
    error: Optional[str] = None
    success: bool = True


# ── OpenAI ────────────────────────────────────────────────────────────────────

async def call_openai(
    prompt: str,
    model: str = "gpt-4o-mini",
    system: str = "You are a helpful assistant.",
    api_key: Optional[str] = None,
) -> LLMResponse:
    resolved_key = api_key or OPENAI_API_KEY
    if not resolved_key:
        return LLMResponse(
            provider="openai", model=model, content="",
            error="OpenAI API key not configured. Add it via the Connector Marketplace or set OPENAI_API_KEY in backend/.env.",
            success=False,
        )

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {resolved_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 1024,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]["message"]["content"]
            tokens = data.get("usage", {}).get("total_tokens", 0)
            return LLMResponse(provider="openai", model=model, content=choice, tokens_used=tokens)

        except httpx.HTTPStatusError as e:
            err = f"OpenAI API error {e.response.status_code}: {e.response.text[:200]}"
            logger.error(err)
            return LLMResponse(provider="openai", model=model, content="", error=err, success=False)
        except Exception as e:
            return LLMResponse(provider="openai", model=model, content="", error=str(e), success=False)


# ── Anthropic (Claude) ────────────────────────────────────────────────────────

async def call_anthropic(
    prompt: str,
    model: str = "claude-3-haiku-20240307",
    system: str = "You are a helpful assistant.",
    api_key: Optional[str] = None,
) -> LLMResponse:
    resolved_key = api_key or ANTHROPIC_API_KEY
    if not resolved_key:
        return LLMResponse(
            provider="anthropic", model=model, content="",
            error="Anthropic API key not configured. Add it via the Connector Marketplace or set ANTHROPIC_API_KEY in backend/.env.",
            success=False,
        )

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": resolved_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 1024,
                    "system": system,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["content"][0]["text"]
            tokens = data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0)
            return LLMResponse(provider="anthropic", model=model, content=content, tokens_used=tokens)

        except httpx.HTTPStatusError as e:
            err = f"Anthropic API error {e.response.status_code}: {e.response.text[:200]}"
            logger.error(err)
            return LLMResponse(provider="anthropic", model=model, content="", error=err, success=False)
        except Exception as e:
            return LLMResponse(provider="anthropic", model=model, content="", error=str(e), success=False)


# ── Ollama (local — free, no API key) ────────────────────────────────────────

async def call_ollama(
    prompt: str,
    model: str = "llama3.2",
    system: str = "You are a helpful assistant.",
    api_key: Optional[str] = None,   # unused for Ollama — accepted for uniform signature
) -> LLMResponse:
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": model,
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data.get("message", {}).get("content", "")
            tokens = data.get("eval_count", 0)
            return LLMResponse(provider="ollama", model=model, content=content, tokens_used=tokens)

        except httpx.ConnectError:
            return LLMResponse(
                provider="ollama", model=model, content="",
                error=(
                    f"Cannot connect to Ollama at {OLLAMA_BASE_URL}. "
                    "Install Ollama from https://ollama.com and run: ollama pull llama3.2"
                ),
                success=False,
            )
        except httpx.HTTPStatusError as e:
            # Model not found → suggest pull
            if e.response.status_code == 404:
                return LLMResponse(
                    provider="ollama", model=model, content="",
                    error=f"Model '{model}' not found. Run: ollama pull {model}",
                    success=False,
                )
            return LLMResponse(provider="ollama", model=model, content="", error=str(e), success=False)
        except Exception as e:
            return LLMResponse(provider="ollama", model=model, content="", error=str(e), success=False)


# ── NVIDIA NIM (OpenAI-compatible — free tier, 80+ models) ───────────────────

async def call_nvidia(
    prompt: str,
    model: str = "nvidia/nemotron-4-340b-instruct",
    system: str = "You are a helpful assistant.",
    api_key: Optional[str] = None,
) -> LLMResponse:
    """
    Call NVIDIA NIM via its OpenAI-compatible chat completions endpoint.
    Free API access available at https://build.nvidia.com/models
    Base URL: https://integrate.api.nvidia.com/v1
    """
    resolved_key = api_key or NVIDIA_API_KEY
    if not resolved_key:
        return LLMResponse(
            provider="nvidia", model=model, content="",
            error=(
                "NVIDIA API key not configured. "
                "Get a free key at https://build.nvidia.com/models — "
                "then add it via Connector Marketplace → NVIDIA NIM."
            ),
            success=False,
        )

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                f"{NVIDIA_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {resolved_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user",   "content": prompt},
                    ],
                    "max_tokens": 1024,
                    "temperature": 0.2,
                    "top_p": 0.7,
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data   = resp.json()
            choice = data["choices"][0]["message"]["content"]
            tokens = data.get("usage", {}).get("total_tokens", 0)
            return LLMResponse(provider="nvidia", model=model, content=choice, tokens_used=tokens)

        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status == 401:
                err = "NVIDIA API key is invalid or expired. Generate a new one at https://build.nvidia.com/models"
            elif status == 422:
                err = f"NVIDIA NIM: model '{model}' not found or unavailable. Check model ID at build.nvidia.com/models"
            else:
                err = f"NVIDIA NIM API error {status}: {e.response.text[:200]}"
            logger.error(err)
            return LLMResponse(provider="nvidia", model=model, content="", error=err, success=False)
        except Exception as e:
            return LLMResponse(provider="nvidia", model=model, content="", error=str(e), success=False)


# ── Google Gemini ─────────────────────────────────────────────────────────────

async def call_gemini(
    prompt: str,
    model: str = "gemini-2.5-flash",
    system: str = "You are a helpful assistant.",
    api_key: Optional[str] = None,
) -> LLMResponse:
    """Call the supported Gemini Developer API with an approved API key."""
    resolved_key = api_key or GEMINI_API_KEY
    if not resolved_key:
        return LLMResponse(
            provider="gemini",
            model=model,
            content="",
            error="Gemini API key not configured. Add an approved Gemini connector.",
            success=False,
        )
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            response = await client.post(
                endpoint,
                headers={"x-goog-api-key": resolved_key, "Content-Type": "application/json"},
                json={
                    "systemInstruction": {"parts": [{"text": system}]},
                    "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048},
                },
            )
            response.raise_for_status()
            data = response.json()
            candidates = data.get("candidates") or []
            parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
            content = "".join(str(part.get("text") or "") for part in parts).strip()
            if not content:
                return LLMResponse(
                    provider="gemini", model=model, content="", error="Gemini returned no text output.", success=False
                )
            usage = data.get("usageMetadata") or {}
            return LLMResponse(
                provider="gemini",
                model=model,
                content=content,
                tokens_used=int(usage.get("totalTokenCount") or 0),
            )
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            detail = (
                "Gemini rejected the API key."
                if status_code in {401, 403}
                else f"Gemini API request failed with HTTP {status_code}."
            )
            return LLMResponse(provider="gemini", model=model, content="", error=detail, success=False)
        except Exception as exc:
            logger.warning("Gemini invocation failed: %s", type(exc).__name__)
            return LLMResponse(provider="gemini", model=model, content="", error="Gemini invocation failed.", success=False)


# ── Router ────────────────────────────────────────────────────────────────────

PROVIDER_MAP = {
    "openai":    call_openai,
    "anthropic": call_anthropic,
    "ollama":    call_ollama,
    "nvidia":    call_nvidia,
    "gemini":    call_gemini,
}

MODEL_DEFAULTS = {
    "openai":    "gpt-4o-mini",
    "anthropic": "claude-3-haiku-20240307",
    "ollama":    "llama3.2",
    "nvidia":    "nvidia/nemotron-4-340b-instruct",
    "gemini":    "gemini-2.5-flash",
}


async def call_llm(
    provider: str,
    prompt: str,
    model: Optional[str] = None,
    system: str = "You are a helpful assistant.",
    api_key: Optional[str] = None,
) -> LLMResponse:
    """Route a prompt to the specified LLM provider."""
    handler = PROVIDER_MAP.get(provider)
    if not handler:
        return LLMResponse(
            provider=provider, model=model or "unknown", content="",
            error=f"Unknown provider '{provider}'. Use: openai, anthropic, ollama, nvidia, gemini",
            success=False,
        )
    resolved_model = model or MODEL_DEFAULTS.get(provider, "")
    return await handler(prompt, model=resolved_model, system=system, api_key=api_key)


async def fetch_ollama_models() -> tuple[list[str], bool]:
    """
    Query Ollama's /api/tags endpoint to get all locally installed models.
    Returns (model_list, is_reachable).
    Falls back to an empty list if Ollama isn't running.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            # Each entry has a "name" field like "llama3.2:latest"
            models = [m["name"] for m in data.get("models", [])]
            return (models if models else ["llama3.2"]), True
    except Exception:
        return [], False


async def available_providers(
    openai_key: Optional[str] = None,
    anthropic_key: Optional[str] = None,
    nvidia_key: Optional[str] = None,
    gemini_key: Optional[str] = None,
) -> list[dict]:
    """
    Return which providers are configured and ready, with live Ollama model list.
    Accepts pre-resolved keys from the connector store so callers don't need to
    re-read the secrets file — env vars are always checked as a fallback.
    """
    ollama_models, ollama_reachable = await fetch_ollama_models()
    fallback_models = ["llama3.2", "llama3.1", "mistral", "phi3", "gemma2"]

    has_openai    = bool(openai_key    or OPENAI_API_KEY)
    has_anthropic = bool(anthropic_key or ANTHROPIC_API_KEY)
    has_nvidia    = bool(nvidia_key    or NVIDIA_API_KEY)
    has_gemini    = bool(gemini_key    or GEMINI_API_KEY)

    return [
        {
            "provider": "anthropic",
            "label": "Anthropic (Claude)",
            "models": ["claude-3-haiku-20240307", "claude-3-5-sonnet-20241022", "claude-3-opus-20240229"],
            "ready": has_anthropic,
            "setup": (
                "Connected via Connector Marketplace" if has_anthropic
                else "Add your Anthropic API key via Connector Marketplace → Anthropic Claude"
            ),
            "cost": "paid",
        },
        {
            "provider": "openai",
            "label": "OpenAI (GPT-4o)",
            "models": ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
            "ready": has_openai,
            "setup": (
                "Connected via Connector Marketplace" if has_openai
                else "Add your OpenAI API key via Connector Marketplace → OpenAI API"
            ),
            "cost": "paid",
        },
        {
            "provider": "nvidia",
            "label": "NVIDIA NIM (Free Tier)",
            "models": [
                "nvidia/nemotron-4-340b-instruct",
                "mistralai/mixtral-8x22b-instruct-v0.1",
                "meta/llama-3.1-405b-instruct",
                "deepseek-ai/deepseek-r1",
                "deepseek-ai/deepseek-v3",
                "minimaxai/minimax-m2",
                "moonshotai/kimi-k2-instruct",
            ],
            "ready": has_nvidia,
            "setup": (
                "Connected — 80+ models available at build.nvidia.com/models" if has_nvidia
                else (
                    "Get a FREE API key at https://build.nvidia.com/models "
                    "→ Connector Marketplace → NVIDIA NIM"
                )
            ),
            "cost": "free_tier",
            "info": "Free access to 80+ frontier models via NVIDIA NIM. No credit card required.",
        },
        {
            "provider": "gemini",
            "label": "Google Gemini",
            "models": ["gemini-2.5-flash", "gemini-2.5-pro"],
            "ready": has_gemini,
            "setup": (
                "Connected via Connector Marketplace" if has_gemini
                else "Add a verified Gemini API key via Connector Marketplace"
            ),
            "cost": "paid",
        },
        {
            "provider": "ollama",
            "label": "Ollama (Local — Free)",
            "models": ollama_models if ollama_reachable else fallback_models,
            "ready": ollama_reachable,
            "setup": (
                "Ollama is running — models listed above are installed on your machine."
                if ollama_reachable
                else "Install from https://ollama.com then run: ollama pull llama3.2"
            ),
            "cost": "free",
        },
    ]
