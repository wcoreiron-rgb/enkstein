from __future__ import annotations

import asyncio
import base64
import binascii
from datetime import datetime, timezone
from hashlib import sha256
import logging
import os
import socket
import re
from time import monotonic, perf_counter
from typing import Any, Callable
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.claws.arcclaw.llm_proxy import call_llm, fetch_ollama_models
from app.claws.arcclaw.scanner import scan_text
from app.core.config import settings
from app.core.modelclaw.schemas import BrainReadinessStatus
from app.core.modelclaw.service import get_profile
from app.models.connector import Connector, ConnectorStatus
from app.services import secrets_manager
from app.trust_fabric import ActionRequest, EnforcementDecision, enforce

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
_MAX_TENANT_BRAIN_CALLS = 4
_MAX_SOURCE_BRAIN_CALLS = 2
_BRAIN_TIMEOUT_SECONDS = 60.0
# Browser Companion sessions run at human/page speed (the native bridge's own
# browser broker call already waits up to 900s -- see invokeBrowser in
# MarcellusBrainBridge.swift) and can legitimately take far longer than a
# direct API/CLI call to produce a long response. A uniform 60s timeout cut
# these off before the native bridge's own patience window even elapsed, so
# a genuinely-in-progress long browser response was silently discarded
# rather than returned. This budget must stay at or below the native
# bridge's own browser wait so a timeout here always fires before (never
# after) the bridge itself would have given up. A large multi-file/full-app
# generation can legitimately run for several minutes, so this and the
# outer WORKSPACE_STREAM_BROWSER_DEADLINE_SECONDS both give real headroom
# for that instead of a short ceiling tuned for a simple chat answer.
_BROWSER_BRAIN_TIMEOUT_SECONDS = 890.0
# A local Ollama profile generating file content runs on the user's own CPU/GPU
# with a large project capsule in its context, which is routinely slower than a
# hosted API call to first token. The 60s budget above is tuned for an API/CLI
# round trip and was cutting local Brains off mid-generation, so a swarm would
# report most of itself as timed out and fall back to whichever Brain happened
# to be fastest. This stays under WORKSPACE_STREAM_DEADLINE_SECONDS (180s) so
# the per-Brain timeout still resolves before the outer turn deadline.
_LOCAL_BRAIN_TIMEOUT_SECONDS = 165.0
_TENANT_SEMAPHORES: dict[tuple[int, str], asyncio.Semaphore] = {}
_SOURCE_SEMAPHORES: dict[tuple[int, str, str], asyncio.Semaphore] = {}

# A bridge-unreachable result is cached briefly so a transient blip doesn't
# force every readiness poll to pay the full connection timeout, while still
# recovering to "ready" promptly once the native bridge comes back.
_STALE_STATUS_CACHE_SECONDS = 4.0
_stale_status_cache: list[dict[str, Any]] | None = None
_stale_status_cache_at: float = 0.0


def _readiness_status_fields(status: BrainReadinessStatus, detail: str | None) -> dict[str, Any]:
    return {
        "status": status,
        "detail": detail,
        "last_checked": datetime.now(timezone.utc).isoformat(),
    }


def _derive_readiness(available: bool, authenticated: bool) -> BrainReadinessStatus:
    """Map a reachable bridge's per-Brain report to a readiness status.

    Both "not installed" and "installed but not authenticated" are user
    actionable (install, or run the vendor login) so both surface as
    needs_setup; "unavailable" is reserved for when the bridge itself cannot
    be reached, which no per-Brain setup step can fix.
    """
    return "ready" if available and authenticated else "needs_setup"


def _execution_semaphores(tenant_id: str, source: str) -> tuple[asyncio.Semaphore, asyncio.Semaphore]:
    loop_id = id(asyncio.get_running_loop())
    tenant_key = (loop_id, tenant_id)
    source_key = (loop_id, tenant_id, source)
    tenant = _TENANT_SEMAPHORES.setdefault(tenant_key, asyncio.Semaphore(_MAX_TENANT_BRAIN_CALLS))
    provider = _SOURCE_SEMAPHORES.setdefault(source_key, asyncio.Semaphore(_MAX_SOURCE_BRAIN_CALLS))
    return tenant, provider


def _brain_kind(name: str) -> str:
    if name.endswith("_desktop"):
        return "desktop_session"
    if name.endswith("_browser"):
        return "browser_session"
    return "subscription"


# Subscription Brains driven by a local CLI process (Codex CLI, Claude Code)
# are not hosted API calls: they start a process on this machine, read the
# whole prompt over stdin, and stream a full answer back. On a large Cowork
# prompt they routinely need more than an API round trip's worth of time.
_CLI_SUBSCRIPTION_BRAINS = {"codex_subscription", "claude_subscription"}


def _brain_timeout_seconds(source: str) -> float:
    """Per-Brain budget matched to how that Brain actually runs.

    Browser Companion sessions run at page speed, local profiles run on the
    user's own hardware, and hosted subscription/API calls are the fastest of
    the three. A single budget tuned for the last one silently reported the
    other two as timed out.
    """
    if source.endswith("_browser"):
        return _BROWSER_BRAIN_TIMEOUT_SECONDS
    if source.startswith("profile:") or source in _CLI_SUBSCRIPTION_BRAINS:
        return _LOCAL_BRAIN_TIMEOUT_SECONDS
    return _BRAIN_TIMEOUT_SECONDS


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


def _unconfigured_status() -> list[dict[str, Any]]:
    detail = "Native Brain Bridge is not configured for this runtime."
    return [
        {
            "brain": name,
            "kind": _brain_kind(name),
            "available": False,
            "authenticated": False,
            **_readiness_status_fields("unavailable", detail),
        }
        for name in sorted(_SUBSCRIPTION_BRAINS)
    ]


def _unreachable_status() -> list[dict[str, Any]]:
    detail = "Native Brain Bridge is unreachable."
    return [
        {
            "brain": name,
            "kind": _brain_kind(name),
            "available": False,
            "authenticated": False,
            **_readiness_status_fields("unavailable", detail),
        }
        for name in sorted(_SUBSCRIPTION_BRAINS)
    ]


def _policy_blocked_status(reason: str) -> list[dict[str, Any]]:
    detail = reason or "Brain status discovery is blocked by Trust Fabric policy."
    return [
        {
            "brain": name,
            "kind": _brain_kind(name),
            "available": False,
            "authenticated": False,
            **_readiness_status_fields("policy_blocked", detail),
        }
        for name in sorted(_SUBSCRIPTION_BRAINS)
    ]


async def _enforce_status_discovery(
    db: AsyncSession,
    *,
    tenant_id: str,
    actor_id: str,
) -> EnforcementDecision:
    """Native host probing (subprocess/network calls into the Brain Bridge)
    is itself a governed action, not a free read — this runs the same
    Trust Fabric decision path as a model call, before any host is probed."""
    return await enforce(
        db,
        ActionRequest(
            module="modelclaw",
            actor_id=actor_id,
            actor_name=actor_id,
            actor_type="human",
            action="brain_status_discovery",
            target="native_brain_bridge",
            target_type="brain_bridge",
            context={"action_type": "BRAIN_STATUS_DISCOVERY", "tenant_id": tenant_id},
        ),
    )


async def bridge_status(
    db: AsyncSession,
    *,
    force: bool = False,
    tenant_id: str = "global",
    actor_id: str = "brain-status-discovery",
) -> list[dict[str, Any]]:
    global _stale_status_cache, _stale_status_cache_at

    decision = await _enforce_status_discovery(db, tenant_id=tenant_id, actor_id=actor_id)
    if not decision.allowed:
        return _policy_blocked_status(decision.reason)

    if not bridge_configured():
        return _unconfigured_status()

    now = monotonic()
    if force:
        # A forced refresh (explicit user action, tab focus, setup
        # completion) must bypass and clear any short negative cache rather
        # than replaying a stale unavailable result.
        _stale_status_cache = None
    elif _stale_status_cache is not None and (now - _stale_status_cache_at) < _STALE_STATUS_CACHE_SECONDS:
        return _stale_status_cache

    try:
        body = await _bridge_request("GET", "/v1/status")
        rows = [
            {
                **row,
                **_readiness_status_fields(
                    _derive_readiness(bool(row.get("available")), bool(row.get("authenticated"))),
                    row.get("detail"),
                ),
            }
            for row in body.get("brains", [])
        ]
        _stale_status_cache = None
        return rows
    except Exception as exc:
        logger.warning("Native Brain Bridge status failed: %s", type(exc).__name__)
        result = _unreachable_status()
        _stale_status_cache = result
        _stale_status_cache_at = now
        return result


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
            "detail": "Enkstein could not request desktop app access.",
        }


async def create_browser_brain_pairing() -> dict[str, Any]:
    if not bridge_configured():
        return {"available": False, "detail": "Native Brain Bridge is not configured for this runtime."}
    try:
        body = await _bridge_request("POST", "/v1/browser/pair", {})
        setup_url = str(body.get("setup_url") or "")
        if not _is_loopback_pairing_url(setup_url):
            raise ValueError("Invalid browser pairing URL")
        return {
            "available": True,
            "setup_url": setup_url,
            "opened": bool(body.get("opened")),
            "expires_in_seconds": int(body.get("expires_in_seconds") or 300),
        }
    except Exception as exc:
        logger.warning("Browser Brain pairing failed: %s", type(exc).__name__)
        return {"available": False, "detail": "Enkstein could not start browser pairing."}


async def launch_cli_login(brain: str) -> dict[str, Any]:
    """Open a visible Terminal window running the exact resolved CLI binary's
    login command. CLI subscription login (codex login / claude login) is an
    interactive OAuth device-flow that needs a real terminal and a browser
    tab to complete, so this cannot be a fully silent background action --
    it is the closest safe equivalent of a single authenticate button."""
    if brain not in {"codex_subscription", "claude_subscription"}:
        return {"launched": False, "detail": "Unsupported CLI brain."}
    if not bridge_configured():
        return {"launched": False, "detail": "Native Brain Bridge is not configured for this runtime."}
    try:
        body = await _bridge_request("POST", "/v1/cli/launch-login", {"brain": brain})
        return {"launched": bool(body.get("launched")), "detail": body.get("detail")}
    except Exception as exc:
        logger.warning("CLI login launch failed: brain=%s error=%s", brain, type(exc).__name__)
        return {"launched": False, "detail": "Enkstein could not open a terminal for CLI login."}


async def open_browser_companion_folder() -> dict[str, Any]:
    if not bridge_configured():
        return {"opened": False, "detail": "Native Brain Bridge is not configured for this runtime."}
    try:
        body = await _bridge_request("POST", "/v1/browser/open-extension", {})
        return {"opened": bool(body.get("opened")), "detail": body.get("detail")}
    except Exception as exc:
        logger.warning("Browser companion folder open failed: %s", type(exc).__name__)
        return {"opened": False, "detail": "Enkstein could not open the browser companion folder."}


async def invoke_subscription_brain(
    brain: str,
    prompt: str,
    *,
    model: str | None = None,
    session_id: str | None = None,
    on_progress: Callable[[str, str | None], None] | None = None,
) -> dict[str, Any]:
    if brain not in _SUBSCRIPTION_BRAINS:
        raise ValueError("Unknown subscription Brain")
    if not bridge_configured():
        return _unavailable_vote(brain, _brain_kind(brain), "Native Brain Bridge is not configured.")

    input_scan = scan_text(prompt, redact=True)
    transmitted_prompt = input_scan.redacted if input_scan.is_sensitive else prompt
    started = perf_counter()
    if brain.endswith("_browser"):
        return await _invoke_browser_polled(
            brain,
            transmitted_prompt,
            session_id=session_id,
            started=started,
            input_scan=input_scan,
            on_progress=on_progress,
        )
    try:
        body = await _bridge_request(
            "POST",
            "/v1/invoke",
            {"brain": brain, "prompt": transmitted_prompt, "model": model, "session_id": session_id},
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


# Real bridge lifecycle states -> a short, user-facing phrase. Anything unrecognized (e.g. a future
# bridge state this backend doesn't know about yet) is deliberately dropped rather than guessed at,
# so the UI only ever shows a state Enkstein can vouch for.
_BROWSER_STATE_LABELS = {
    "queued": "Waiting for an available browser tab",
    "leased": "Browser tab is preparing the request",
    "submitted": "Prompt submitted; waiting for a reply",
    "streaming": "Reply is streaming in the browser tab",
    "reconnecting": "Browser bridge reconnecting; the provider task is still active",
}


async def _invoke_browser_polled(
    brain: str,
    prompt: str,
    *,
    session_id: str | None,
    started: float,
    input_scan,
    on_progress: Callable[[str, str | None], None] | None,
) -> dict[str, Any]:
    """Starts a browser Brain invocation through the non-blocking bridge endpoints and polls it,
    reporting each real lifecycle state through on_progress as it changes. Falls back to the
    original single blocking /v1/invoke call if the bridge does not yet support the start/status
    pair (e.g. an older native bridge build), so this never regresses an existing installation.
    """
    try:
        start_body = await _bridge_request(
            "POST", "/v1/browser-invoke/start", {"brain": brain, "prompt": prompt, "session_id": session_id}
        )
    except Exception:
        # Older bridge without the polling endpoints: keep working via the blocking call.
        return await _invoke_browser_blocking(brain, prompt, session_id=session_id, started=started, input_scan=input_scan)

    task_id = start_body.get("task_id")
    if not task_id:
        return _unavailable_vote(brain, _brain_kind(brain), str(start_body.get("detail") or "Browser invocation could not be started."))

    last_state: str | None = None
    deadline = started + _BROWSER_BRAIN_TIMEOUT_SECONDS
    while perf_counter() < deadline:
        try:
            status_body = await _bridge_request("POST", "/v1/browser-invoke/status", {"task_id": task_id})
        except Exception:
            # A brief host-bridge/socket interruption must not be translated
            # into a provider timeout. The ChatGPT/Gemini page may still be
            # generating normally and the paired extension retains the task
            # metadata needed to resume observation. Keep polling until the
            # existing governed browser deadline; collect_votes supplies the
            # matching outer cancellation bound.
            if last_state != "reconnecting":
                last_state = "reconnecting"
                if on_progress:
                    on_progress("reconnecting", _BROWSER_STATE_LABELS["reconnecting"])
            await asyncio.sleep(0.75)
            continue
        state = str(status_body.get("state") or "")
        if state and state != last_state:
            last_state = state
            label = _BROWSER_STATE_LABELS.get(state)
            if label and on_progress:
                on_progress(state, label)
        if state in {"completed", "failed", "cancelled", "expired", "unknown"}:
            if state == "completed":
                response = str(status_body.get("response") or "")
                if response:
                    output_scan = scan_text(response, redact=True)
                    return {
                        "source": brain,
                        "kind": _brain_kind(brain),
                        "available": True,
                        "counted": True,
                        "provider": str(status_body.get("provider") or brain),
                        "model": "browser-selected",
                        "response": output_scan.redacted if output_scan.is_sensitive else response,
                        "reason": _redaction_reason(input_scan.is_sensitive, output_scan.is_sensitive),
                        "latency_ms": int((perf_counter() - started) * 1000),
                        "token_count": None,
                        "attachments": sanitize_provider_attachments(status_body.get("attachments")),
                    }
            return _unavailable_vote(
                brain,
                _brain_kind(brain),
                str(status_body.get("detail") or "Browser session returned no response."),
            )
        await asyncio.sleep(0.75)
    return _unavailable_vote(brain, _brain_kind(brain), "The browser session timed out before returning a response.")


async def _invoke_browser_blocking(
    brain: str,
    prompt: str,
    *,
    session_id: str | None,
    started: float,
    input_scan,
) -> dict[str, Any]:
    try:
        body = await _bridge_request(
            "POST",
            "/v1/invoke",
            {"brain": brain, "prompt": prompt, "model": None, "session_id": session_id},
            timeout_seconds=_BROWSER_BRAIN_TIMEOUT_SECONDS + 10.0,
        )
    except Exception:
        logger.warning("Subscription Brain invocation failed: brain=%s", brain)
        return _unavailable_vote(brain, _brain_kind(brain), "Native Brain invocation failed.")
    response = str(body.get("response") or "")
    if not body.get("success") or not response:
        return _unavailable_vote(brain, _brain_kind(brain), str(body.get("detail") or "Subscription Brain returned no response."))
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
    # "exec" is the narrowly scoped command operation used by the Enkstein Local
    # Executor: the broker accepts an allowlisted program plus a pre-split argv
    # and never a shell string, and runs it with the approved root as its cwd.
    if operation not in {"list", "write", "trash", "pick", "rename", "move", "exec", "exec_cancel"}:
        raise ValueError("Unsupported native workspace operation")
    if not bridge_configured():
        raise RuntimeError("Native workspace bridge is not configured")
    # A command legitimately runs far longer than a file write, so the exec
    # operation gets its own generous ceiling instead of the default timeout.
    if operation == "exec":
        budget = float(payload.get("timeout_seconds") or 300) + 30.0
        return await _bridge_request("POST", "/v1/workspace/exec", payload, timeout_seconds=budget)
    if operation == "exec_cancel":
        return await _bridge_request("POST", "/v1/workspace/exec/cancel", payload, timeout_seconds=30.0)
    return await _bridge_request("POST", f"/v1/workspace/{operation}", payload)


# Codex App Server operations proxied to the native broker. These map to the
# official Codex App Server protocol (JSON-RPC over stdio) that the broker
# supervises per approved project root; the backend only ever sees the broker's
# sanitized, structured result — never the raw stdio stream.
_CODEX_OPERATIONS = {"start", "turn", "approve", "cancel", "status"}


async def invoke_codex_bridge(operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Drive one resumable, root-bound Codex App Server thread via the host broker."""
    if operation not in _CODEX_OPERATIONS:
        raise ValueError("Unsupported Codex App Server operation")
    if not bridge_configured():
        raise RuntimeError("Codex App Server bridge is not configured")
    return await _bridge_request("POST", f"/v1/codex/{operation}", payload)


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


# A turn that carries Enkstein's file-output protocol is asking for complete
# file bodies. Telling that same turn to be "concise" is a direct conflict, and
# models resolve it by refusing to write the file and explaining that the
# content was too large for a short answer. Detected from the prompt because
# the protocol is what actually distinguishes the two cases.
_FILE_OUTPUT_PROMPT = re.compile(r"marcellus_changes", re.IGNORECASE)

_REASONING_SYSTEM_PROMPT = (
    "You are a reasoning-only Brain inside Enkstein. Return a concise, evidence-aware answer. "
    "Do not claim to have executed tools or changed systems."
)

_FILE_AUTHOR_SYSTEM_PROMPT = (
    "You are a file-authoring Brain inside Enkstein. Enkstein's deterministic writer applies whatever "
    "you return, so return complete file contents, never an abbreviation, summary, placeholder, or a "
    "note that the content is too long. Length is not a constraint: if the whole change set will not "
    "fit, emit a smaller number of COMPLETE files rather than truncating any single file. "
    "Do not claim to have executed tools or changed systems yourself."
)


def _profile_system_prompt(prompt: str) -> str:
    return _FILE_AUTHOR_SYSTEM_PROMPT if _FILE_OUTPUT_PROMPT.search(prompt) else _REASONING_SYSTEM_PROMPT


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
        system=_profile_system_prompt(prompt),
        api_key=api_key,
        max_tokens=int(profile.get("max_tokens") or 0) or None,
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
    session_id: str | None = None,
    browser_prompt: str | None = None,
    subscription_invoker=None,
    on_progress: Callable[[str, str, str | None], None] | None = None,
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

    async def invoke_unbounded(source: str) -> dict[str, Any]:
        if source in _SUBSCRIPTION_BRAINS:
            invoker = subscription_invoker or invoke_subscription_brain
            kwargs: dict[str, Any] = {"model": model}
            if session_id:
                kwargs["session_id"] = session_id
            if source.endswith("_browser") and on_progress:
                kwargs["on_progress"] = lambda state, label, _source=source: on_progress(_source, state, label)
            source_prompt = browser_prompt if source.endswith("_browser") and browser_prompt else prompt
            return await invoker(source, source_prompt, **kwargs)
        if source.startswith("profile:"):
            profile_call = prepared[source]
            if "unavailable_vote" in profile_call:
                return profile_call["unavailable_vote"]
            return await _invoke_prepared_profile(profile_call, prompt)
        return _unavailable_vote(source, "unknown", "Unsupported Brain source.")

    async def invoke(source: str) -> dict[str, Any]:
        tenant_semaphore, source_semaphore = _execution_semaphores(tenant_id, source)
        async with tenant_semaphore, source_semaphore:
            budget = _brain_timeout_seconds(source)
            try:
                return await asyncio.wait_for(invoke_unbounded(source), timeout=budget)
            except asyncio.TimeoutError:
                return _unavailable_vote(source, _brain_kind(source), "The Brain timed out before returning a response.")

    return list(await asyncio.gather(*(invoke(source) for source in sources)))


def derive_brain_session_id(tenant_id: str, context: dict[str, Any]) -> str | None:
    """Return an opaque tenant-scoped key for provider conversation affinity."""
    conversation_id = str(context.get("conversation_id") or "").strip()
    if not conversation_id or len(conversation_id) > 128:
        return None
    return sha256(f"{tenant_id}\x00{conversation_id}".encode()).hexdigest()


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


async def _bridge_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    timeout = httpx.Timeout(float(timeout_seconds or settings.BRAIN_BRIDGE_TIMEOUT_SECONDS), connect=5.0)
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


def _is_loopback_pairing_url(url: str) -> bool:
    """Reject spoofable pairing URLs: only an explicit http://127.0.0.1:<port> origin,
    with no embedded credentials, is trusted for the browser pairing handoff."""
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        return False
    if parsed.username or parsed.password:
        return False
    try:
        port = parsed.port
    except ValueError:
        return False
    return port is not None


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


# Provider-generated downloads relayed by the host bridge. The broker already
# bounds these, but the backend re-validates because the bridge is a separate
# process boundary: names must be safe single leaves and payloads real base64.
_ATTACHMENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]*\.[A-Za-z0-9]{1,12}$")
_MAX_ATTACHMENTS = 20
_MAX_ATTACHMENT_BYTES = 5_000_000


def sanitize_provider_attachments(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    sanitized: list[dict[str, Any]] = []
    seen: set[str] = set()
    total = 0
    for item in raw[:_MAX_ATTACHMENTS]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        encoded = item.get("content_base64")
        if not _ATTACHMENT_NAME.match(name) or ".." in name or name in seen:
            continue
        if not isinstance(encoded, str) or len(encoded) > 8_000_000:
            continue
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        if not payload or len(payload) > _MAX_ATTACHMENT_BYTES or total + len(payload) > 20_000_000:
            continue
        total += len(payload)
        seen.add(name)
        sanitized.append({"name": name, "size": len(payload), "content_base64": encoded})
    return sanitized


def _redaction_reason(input_redacted: bool, output_redacted: bool) -> str | None:
    if input_redacted and output_redacted:
        return "Input and output were redacted by Enkstein."
    if input_redacted:
        return "Sensitive input was redacted before provider invocation."
    if output_redacted:
        return "Output was redacted by Enkstein."
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
