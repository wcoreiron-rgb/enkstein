"""
Enkstein — Zero Trust External Agent Dispatcher
Calls a registered external / OpenClaw agent endpoint with full Zero Trust controls.

Security controls applied on every call:
  1. SSRF protection   — blocks private IPs, link-local, metadata endpoints
  2. HTTPS enforcement — plaintext HTTP rejected (except localhost in dev)
  3. Request signing   — HMAC-SHA256(signing_secret, ts.run_id.body_hash)
  4. Response verification — agent must echo X-Agent-Signature over response body
  5. Schema validation — only {findings, proposed_actions, summary} accepted
  6. Scope enforcement — proposed actions checked against agent's declared scopes
  7. Hard timeout      — 30 s max; no hanging calls

Flow:
  Enkstein                              External OpenClaw Agent
  ──────────                              ───────────────────────
  Build payload
  Sign with HMAC-SHA256
  POST → endpoint_url ──────────────────► Verify Enkstein signature
         (Authorization: Bearer <secret>)  Do work
         (X-Enkstein-Signature: <sig>)   Sign response with HMAC-SHA256
                                           Return { findings, proposed_actions }
  Receive response ◄──────────────────────
  Verify X-Agent-Signature
  Schema-validate
  Scope-check proposed actions
  Return to agent_runner → Trust Fabric → autonomy → audit (unchanged)
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("regentclaw.external_agent")

# ─── SSRF Blocklist ───────────────────────────────────────────────────────────

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 private
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local / AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),        # "This" network
    ipaddress.ip_network("100.64.0.0/10"),    # Shared address space
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]

_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",          # AWS/Azure instance metadata
    "metadata.azure.internal",
    "100.100.100.200",          # Alibaba metadata
}

_ALLOWED_SCHEMES = {"https"}
_DEV_ALLOWED_SCHEMES = {"https", "http"}   # http only allowed for 127.0.0.1 in dev


# ─── Scope definitions ────────────────────────────────────────────────────────
# Maps action_type strings → required scope label.
# An external agent may only propose actions within its declared scopes.

ACTION_SCOPE_MAP: dict[str, str] = {
    # Identity
    "disable_account":        "identity:write",
    "enable_account":         "identity:write",
    "reset_password":         "identity:write",
    "enforce_mfa":            "identity:write",
    "list_accounts":          "identity:read",
    # Credentials / secrets
    "rotate_credential":      "secrets:write",
    "revoke_token":           "secrets:write",
    "revoke_stale_tokens":    "secrets:write",
    "read_secret":            "secrets:read",
    # Network
    "block_ip":               "network:write",
    "unblock_ip":             "network:write",
    "isolate_host":           "endpoint:write",
    "quarantine_host":        "endpoint:write",
    "contain_endpoint":       "endpoint:write",
    "deploy_edr":             "endpoint:write",
    # Cloud
    "block_public_access":    "cloud:write",
    "disable_iam_role":       "cloud:write",
    "list_cloud_resources":   "cloud:read",
    # Data
    "flag_for_review":        "data:read",
    "block_llm_session":      "ai:write",
    # Compliance / reporting
    "enable_logging":         "compliance:write",
    "schedule_review":        "compliance:write",
    "generate_report":        "compliance:read",
    # Notifications
    "send_alert":             "notify:write",
    "create_incident":        "notify:write",
    "escalate":               "notify:write",
    # Generic safe
    "scan":                   "*.read",
    "assess":                 "*.read",
    "investigate":            "*.read",
    "collect_evidence":       "*.read",
}

_WILDCARD_READ_SCOPE = "*.read"


# ─── SSRF Guard ───────────────────────────────────────────────────────────────

class SSRFError(Exception):
    """Raised when a URL fails SSRF validation."""


def validate_endpoint_url(url: str, allow_http_localhost: bool = False) -> None:
    """
    Validate an external agent endpoint URL against SSRF rules.
    Raises SSRFError with a descriptive reason on failure.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise SSRFError(f"Malformed URL: {url!r}")

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    # Scheme check
    allowed = _DEV_ALLOWED_SCHEMES if allow_http_localhost else _ALLOWED_SCHEMES
    if scheme not in allowed:
        raise SSRFError(
            f"Scheme '{scheme}' not allowed. Only HTTPS is permitted for external agents."
        )

    # Hostname must be present
    if not hostname:
        raise SSRFError("URL has no resolvable hostname.")

    # Explicit blocked hostnames
    if hostname in _BLOCKED_HOSTNAMES:
        raise SSRFError(
            f"Hostname '{hostname}' is blocked (SSRF protection — metadata/localhost endpoint)."
        )

    # If it's a raw IP address, check against blocked ranges
    try:
        addr = ipaddress.ip_address(hostname)
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                raise SSRFError(
                    f"IP address {hostname} falls within blocked range {net} (SSRF protection)."
                )
    except ValueError:
        # Not a raw IP — hostname. We trust DNS for now (production should use
        # DNS pinning or an egress proxy that enforces the same blocklist).
        pass

    # Dev mode: allow http only for 127.0.0.1 / [::1]
    if scheme == "http" and hostname not in ("127.0.0.1", "::1", "localhost"):
        raise SSRFError(
            "HTTP (non-TLS) is only permitted for 127.0.0.1/localhost in development mode."
        )


# ─── HMAC Signing ─────────────────────────────────────────────────────────────

def _sign(secret: str, message: str) -> str:
    """Return HMAC-SHA256 hex digest."""
    return hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _build_request_signature(secret: str, ts: str, run_id: str, body: bytes) -> str:
    """
    Canonical signature for outbound request:
      HMAC-SHA256(secret, "{ts}.{run_id}.{sha256(body)}")
    """
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{ts}.{run_id}.{body_hash}"
    return _sign(secret, message)


def _verify_response_signature(secret: str, response_body: bytes, received_sig: str) -> bool:
    """
    Verify agent's X-Agent-Signature header.
    Agent must compute: HMAC-SHA256(secret, sha256(response_body))
    """
    body_hash = hashlib.sha256(response_body).hexdigest()
    expected = _sign(secret, body_hash)
    return hmac.compare_digest(expected, received_sig)


# ─── Schema Validation ────────────────────────────────────────────────────────

_VALID_SEVERITIES = {"informational", "info", "low", "medium", "high", "critical"}
_VALID_RISKS      = {"low", "medium", "high", "critical"}


def _validate_response_schema(data: Any) -> dict:
    """
    Strictly validate external agent response.
    Returns cleaned dict: { findings, proposed_actions, summary }
    Raises ValueError on any violation.
    """
    if not isinstance(data, dict):
        raise ValueError("Response must be a JSON object.")

    # findings: required list
    findings_raw = data.get("findings", [])
    if not isinstance(findings_raw, list):
        raise ValueError("'findings' must be a list.")
    if len(findings_raw) > 200:
        raise ValueError("Too many findings (max 200).")

    findings = []
    for i, f in enumerate(findings_raw):
        if not isinstance(f, dict):
            raise ValueError(f"findings[{i}] must be an object.")
        findings.append({
            "id":       str(f.get("id", f"F{i:03d}"))[:64],
            "severity": str(f.get("severity", "informational")).lower()
                        if str(f.get("severity", "informational")).lower() in _VALID_SEVERITIES
                        else "informational",
            "title":    str(f.get("title", "Finding"))[:512],
            "detail":   str(f.get("detail", ""))[:2048],
        })

    # proposed_actions: optional list
    actions_raw = data.get("proposed_actions", [])
    if not isinstance(actions_raw, list):
        raise ValueError("'proposed_actions' must be a list.")
    if len(actions_raw) > 50:
        raise ValueError("Too many proposed actions (max 50).")

    actions = []
    for i, a in enumerate(actions_raw):
        if not isinstance(a, dict):
            raise ValueError(f"proposed_actions[{i}] must be an object.")
        action_type = str(a.get("type", ""))[:64]
        if not action_type:
            raise ValueError(f"proposed_actions[{i}].type is required.")
        actions.append({
            "id":     str(a.get("id", f"A{i:03d}"))[:64],
            "type":   action_type,
            "target": str(a.get("target", "unknown"))[:512],
            "risk":   str(a.get("risk", "low")).lower()
                      if str(a.get("risk", "low")).lower() in _VALID_RISKS
                      else "low",
            "detail": str(a.get("detail", ""))[:1024],
        })

    summary = str(data.get("summary", "External agent scan completed."))[:2048]

    return {
        "findings":         findings,
        "proposed_actions": actions,
        "summary":          summary,
    }


# ─── Scope Enforcement ────────────────────────────────────────────────────────

def _enforce_scopes(
    proposed_actions: list[dict],
    allowed_scopes: list[str],
) -> tuple[list[dict], list[dict]]:
    """
    Filter proposed actions against the agent's declared scopes.
    Returns (permitted_actions, denied_actions).

    Scope matching:
      - "*.read"          → any read-class action
      - "identity:write"  → exact match
      - "*"               → everything (admin only — should be rare)
    """
    if "*" in allowed_scopes:
        return proposed_actions, []

    permitted, denied = [], []
    for action in proposed_actions:
        action_type = action["type"]
        required_scope = ACTION_SCOPE_MAP.get(action_type)

        if required_scope is None:
            # Unknown action type — deny by default (Zero Trust)
            denied.append({**action, "_deny_reason": "unknown_action_type"})
            continue

        # Check if required scope is in allowed scopes
        if required_scope in allowed_scopes:
            permitted.append(action)
        elif _WILDCARD_READ_SCOPE in allowed_scopes and required_scope.endswith(":read"):
            permitted.append(action)
        else:
            denied.append({**action, "_deny_reason": f"scope_not_granted:{required_scope}"})

    return permitted, denied


# ─── Key Generation ───────────────────────────────────────────────────────────

def generate_signing_secret() -> str:
    """Generate a cryptographically secure 32-byte hex signing secret."""
    return secrets.token_hex(32)   # 64-char hex string


# ─── Main Dispatcher ──────────────────────────────────────────────────────────

CALL_TIMEOUT_SEC = 30


async def dispatch(
    agent_id: str,
    run_id: str,
    endpoint_url: str,
    signing_secret: str,
    allowed_scopes: list[str],
    context: dict | None = None,
    dev_mode: bool = False,
) -> dict:
    """
    Dispatch a run to an external OpenClaw agent with full Zero Trust controls.

    Returns dict compatible with _simulate_agent_logic output:
      { findings, proposed_actions, summary }

    Raises ExternalAgentError on any security or connectivity failure.
    """
    # 1. SSRF guard
    try:
        validate_endpoint_url(endpoint_url, allow_http_localhost=dev_mode)
    except SSRFError as e:
        raise ExternalAgentError(f"SSRF_BLOCKED: {e}") from e

    # 2. Build payload
    ts = str(int(time.time()))
    payload = {
        "run_id":    run_id,
        "agent_id":  agent_id,
        "timestamp": ts,
        "context":   context or {},
    }
    body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    # 3. Sign the outbound request
    request_sig = _build_request_signature(signing_secret, ts, run_id, body_bytes)

    headers = {
        "Content-Type":          "application/json",
        "Authorization":         f"Bearer {signing_secret}",
        "X-RegentClaw-Signature": request_sig,
        "X-RegentClaw-Timestamp": ts,
        "X-RegentClaw-RunId":     run_id,
        "X-RegentClaw-AgentId":   agent_id,
        "User-Agent":             "RegentClaw/1.0 ExternalAgentDispatcher",
    }

    logger.info(
        "Dispatching to external agent agent_id=%s run_id=%s url=%s",
        agent_id, run_id, endpoint_url,
    )

    # 4. HTTP call with hard timeout
    try:
        async with httpx.AsyncClient(timeout=CALL_TIMEOUT_SEC, follow_redirects=False) as client:
            response = await client.post(endpoint_url, content=body_bytes, headers=headers)
    except httpx.TimeoutException:
        raise ExternalAgentError(
            f"TIMEOUT: External agent at {endpoint_url} did not respond within {CALL_TIMEOUT_SEC}s."
        )
    except httpx.RequestError as e:
        raise ExternalAgentError(f"CONNECTION_ERROR: {e}")

    # 5. HTTP status check
    if response.status_code not in (200, 201):
        raise ExternalAgentError(
            f"HTTP_{response.status_code}: Agent returned non-200 status. "
            f"Body preview: {response.text[:256]}"
        )

    response_body = response.content

    # 6. Verify response signature
    received_sig = response.headers.get("X-Agent-Signature", "")
    if not received_sig:
        raise ExternalAgentError(
            "MISSING_SIGNATURE: Agent response has no X-Agent-Signature header. "
            "Every external agent response must be HMAC-signed."
        )

    if not _verify_response_signature(signing_secret, response_body, received_sig):
        raise ExternalAgentError(
            "INVALID_SIGNATURE: X-Agent-Signature does not match expected HMAC. "
            "Possible tampering or wrong signing secret."
        )

    logger.info("Signature verified for agent_id=%s run_id=%s", agent_id, run_id)

    # 7. Parse JSON
    try:
        raw_data = response.json()
    except Exception:
        raise ExternalAgentError("PARSE_ERROR: Agent response is not valid JSON.")

    # 8. Schema validation
    try:
        validated = _validate_response_schema(raw_data)
    except ValueError as e:
        raise ExternalAgentError(f"SCHEMA_ERROR: {e}")

    # 9. Scope enforcement — strip out-of-scope proposed actions
    permitted, denied = _enforce_scopes(validated["proposed_actions"], allowed_scopes)

    if denied:
        scope_denials = [
            f"{a['type']} ({a.get('_deny_reason', 'scope_denied')})"
            for a in denied
        ]
        logger.warning(
            "Scope violations from external agent agent_id=%s: %s",
            agent_id, ", ".join(scope_denials),
        )

    validated["proposed_actions"] = permitted
    validated["scope_denied_actions"] = denied

    logger.info(
        "External agent run complete agent_id=%s findings=%d actions_permitted=%d actions_denied=%d",
        agent_id,
        len(validated["findings"]),
        len(permitted),
        len(denied),
    )

    return validated


class ExternalAgentError(Exception):
    """Raised when external agent dispatch fails at any security or connectivity layer."""
