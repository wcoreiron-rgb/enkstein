"""
RegentClaw — Connector Test Service
=====================================
Tests real connectivity for each connector type.
Uses stored (decrypted) credentials to make a minimal API call.
Returns success/failure + a human-readable message.

Every test is read-only — no writes, no side effects.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import smtplib
import socket
import ssl
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse
import httpx

logger = logging.getLogger(__name__)
TIMEOUT = 10.0


# ── SSRF protection ────────────────────────────────────────────────────────────

_SSRF_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # AWS/Azure/GCP metadata
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 private
]

_SSRF_BLOCKED_HOSTS = frozenset({
    "metadata.google.internal",
    "metadata.azure.com",
    "169.254.169.254",
})


def _validate_endpoint_url(url: str) -> str:
    """
    Validate a user-supplied URL against SSRF attack patterns.
    Raises ValueError with a safe message if the URL is blocked.
    Returns the URL if safe.
    """
    if not url or not url.startswith(("http://", "https://")):
        raise ValueError("Endpoint must start with http:// or https://")

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if host.lower() in _SSRF_BLOCKED_HOSTS:
        raise ValueError(f"Endpoint host '{host}' is not allowed")

    # Resolve to IP and check against blocked networks
    try:
        addr = ipaddress.ip_address(host)
        for net in _SSRF_BLOCKED_NETWORKS:
            if addr in net:
                raise ValueError(f"Endpoint resolves to a private/reserved address: {addr}")
    except ValueError as exc:
        # Re-raise our own ValueError; ip_address() raises ValueError for hostnames
        if "private/reserved" in str(exc) or "not allowed" in str(exc):
            raise
        # hostname — do a basic check; full DNS resolution would need async
        # Block known metadata hostnames explicitly (already done above)

    return url


@dataclass
class TestResult:
    success: bool
    message: str
    detail: Optional[str] = None
    verification_level: str = "none"


# ── Per-connector test implementations ────────────────────────────────────────

async def _test_openai(creds: dict) -> TestResult:
    api_key = creds.get("api_key", "")
    if not api_key:
        return TestResult(False, "API key not provided")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            if resp.status_code == 200:
                models = resp.json().get("data", [])
                return TestResult(
                    True,
                    f"Connected — {len(models)} models available",
                    verification_level="credential",
                )
            elif resp.status_code == 401:
                return TestResult(False, "Invalid API key — check your OpenAI key")
            else:
                return TestResult(False, f"HTTP {resp.status_code}: {resp.text[:100]}")
        except httpx.ConnectError:
            return TestResult(False, "Cannot reach api.openai.com — check network")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_anthropic(creds: dict) -> TestResult:
    api_key = creds.get("api_key", "")
    if not api_key:
        return TestResult(False, "API key not provided")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )
            if resp.status_code == 200:
                return TestResult(
                    True,
                    "Connected — Anthropic API responding",
                    verification_level="credential",
                )
            elif resp.status_code == 401:
                return TestResult(False, "Invalid API key — check your Anthropic key")
            else:
                return TestResult(False, f"HTTP {resp.status_code}: {resp.text[:100]}")
        except httpx.ConnectError:
            return TestResult(False, "Cannot reach api.anthropic.com — check network")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_ollama(creds: dict) -> TestResult:
    base_url = creds.get("base_url", "http://host.docker.internal:11434").rstrip("/")
    # Allow the Docker-internal Ollama host (host.docker.internal) but block all other
    # private/cloud-metadata addresses to prevent SSRF via custom base_url
    if base_url not in ("http://host.docker.internal:11434", "http://localhost:11434"):
        try:
            _validate_endpoint_url(base_url)
        except ValueError as exc:
            return TestResult(False, f"Invalid Ollama URL: {exc}")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(f"{base_url}/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                names = [m["name"] for m in models[:5]]
                return TestResult(
                    True,
                    f"Connected — {len(models)} models: {', '.join(names) or 'none pulled yet'}",
                    verification_level="service",
                )
            else:
                return TestResult(False, f"Ollama responded HTTP {resp.status_code}")
        except httpx.ConnectError:
            return TestResult(False, f"Cannot reach Ollama at {base_url} — is it running?")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_slack(creds: dict) -> TestResult:
    token = creds.get("bot_token", "")
    if not token:
        return TestResult(False, "Bot token not provided")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            data = resp.json()
            if data.get("ok"):
                return TestResult(
                    True,
                    f"Connected as @{data.get('user', 'unknown')} in {data.get('team', 'unknown')}",
                    verification_level="credential",
                )
            else:
                return TestResult(False, f"Slack error: {data.get('error', 'unknown')}")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_github(creds: dict) -> TestResult:
    token = creds.get("personal_access_token", "")
    if not token:
        return TestResult(False, "Personal access token not provided")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            )
            if resp.status_code == 200:
                user = resp.json()
                return TestResult(
                    True,
                    f"Connected as @{user.get('login')} — {user.get('public_repos', 0)} repos",
                    verification_level="credential",
                )
            elif resp.status_code == 401:
                return TestResult(False, "Invalid token — check your GitHub PAT")
            else:
                return TestResult(False, f"HTTP {resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_crowdstrike(creds: dict) -> TestResult:
    client_id     = creds.get("client_id", "")
    client_secret = creds.get("client_secret", "")
    if not client_id or not client_secret:
        return TestResult(False, "Client ID and Client Secret are required")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://api.crowdstrike.com/oauth2/token",
                data={"client_id": client_id, "client_secret": client_secret},
            )
            if resp.status_code == 201:
                return TestResult(
                    True,
                    "Connected — OAuth token obtained successfully",
                    verification_level="credential",
                )
            elif resp.status_code == 401:
                return TestResult(False, "Invalid credentials — check Client ID and Secret")
            else:
                return TestResult(False, f"HTTP {resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_pagerduty(creds: dict) -> TestResult:
    routing_key = creds.get("routing_key", "")
    if not routing_key:
        return TestResult(False, "Routing key not provided")
    # PagerDuty doesn't have a ping endpoint — validate format
    if len(routing_key) < 20:
        return TestResult(False, "Routing key appears invalid (too short)")
    return TestResult(
        True,
        "Routing key format valid — send a test event to fully verify",
        verification_level="format",
    )


async def _test_nvidia_nim(creds: dict) -> TestResult:
    """Validate a hosted NVIDIA NIM key with a minimal authenticated inference."""
    api_key = creds.get("api_key", "").strip()
    if not api_key:
        return TestResult(False, "NVIDIA API key not provided")

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://integrate.api.nvidia.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "meta/llama-3.2-1b-instruct",
                    "messages": [{"role": "user", "content": "Reply OK."}],
                    "max_tokens": 1,
                    "temperature": 0,
                },
            )
            if resp.status_code == 200:
                payload = resp.json()
                choices = payload.get("choices") if isinstance(payload, dict) else None
                if not isinstance(choices, list) or not choices:
                    return TestResult(False, "NVIDIA returned an invalid inference response")
                return TestResult(
                    True,
                    "Connected — NVIDIA accepted the key and completed a minimal inference",
                    verification_level="credential",
                )
            if resp.status_code in (401, 403):
                return TestResult(False, "NVIDIA rejected the API key")
            if resp.status_code == 429:
                return TestResult(False, "NVIDIA rate-limited the verification request — try again later")
            return TestResult(False, f"NVIDIA verification failed with HTTP {resp.status_code}")
        except httpx.ConnectError:
            return TestResult(False, "Cannot reach integrate.api.nvidia.com — check network")
        except httpx.TimeoutException:
            return TestResult(False, "NVIDIA verification timed out — try again")
        except (TypeError, ValueError):
            return TestResult(False, "NVIDIA returned an invalid verification response")
        except Exception as exc:
            logger.warning("NVIDIA connector verification failed: %s", type(exc).__name__)
            return TestResult(False, "NVIDIA verification could not be completed")


async def _test_gemini(creds: dict) -> TestResult:
    api_key = str(creds.get("api_key") or "").strip()
    if not api_key:
        return TestResult(False, "Gemini API key not provided")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            response = await client.post(
                "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
                headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
                json={
                    "contents": [{"role": "user", "parts": [{"text": "Reply OK."}]}],
                    "generationConfig": {"maxOutputTokens": 2, "temperature": 0},
                },
            )
            if response.status_code == 200:
                candidates = response.json().get("candidates") or []
                if candidates:
                    return TestResult(True, "Connected — Gemini accepted the key", verification_level="credential")
                return TestResult(False, "Gemini returned an invalid verification response")
            if response.status_code in {401, 403}:
                return TestResult(False, "Gemini rejected the API key")
            if response.status_code == 429:
                return TestResult(False, "Gemini rate-limited the verification request — try again later")
            return TestResult(False, f"Gemini verification failed with HTTP {response.status_code}")
        except (httpx.ConnectError, httpx.TimeoutException):
            return TestResult(False, "Gemini verification could not reach Google AI")
        except Exception as exc:
            logger.warning("Gemini connector verification failed: %s", type(exc).__name__)
            return TestResult(False, "Gemini verification could not be completed")


async def _test_email(creds: dict) -> TestResult:
    """Verify a TLS SMTP connection and credentials without sending mail."""
    host = str(creds.get("smtp_host", "")).strip()
    username = str(creds.get("username", "")).strip()
    password = str(creds.get("password", ""))
    from_addr = str(creds.get("from_addr", "")).strip()
    try:
        port = int(creds.get("smtp_port") or 587)
    except (TypeError, ValueError):
        return TestResult(False, "SMTP port must be a number")

    if not host or not from_addr:
        return TestResult(False, "SMTP host and From Address are required")
    if not 1 <= port <= 65535:
        return TestResult(False, "SMTP port is outside the valid range")
    if bool(username) != bool(password):
        return TestResult(False, "SMTP username and password must be provided together")

    def verify() -> TestResult:
        try:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            for address in addresses:
                ip = ipaddress.ip_address(address[4][0])
                if any(ip in network for network in _SSRF_BLOCKED_NETWORKS):
                    return TestResult(False, "SMTP host resolves to a private or reserved address")

            context = ssl.create_default_context()
            if port == 465:
                client: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=context)
            else:
                client = smtplib.SMTP(host, port, timeout=TIMEOUT)
                client.ehlo()
                if not client.has_extn("starttls"):
                    client.quit()
                    return TestResult(False, "SMTP server does not offer STARTTLS")
                client.starttls(context=context)
                client.ehlo()

            try:
                if username:
                    client.login(username, password)
                client.noop()
            finally:
                try:
                    client.quit()
                except smtplib.SMTPException:
                    client.close()
            return TestResult(
                True,
                "Connected securely — SMTP accepted the configured credentials",
                verification_level="credential" if username else "tls_connectivity",
            )
        except smtplib.SMTPAuthenticationError:
            return TestResult(False, "SMTP rejected the username or app-specific password")
        except (socket.gaierror, ConnectionError, OSError, smtplib.SMTPException):
            return TestResult(False, "Could not establish a secure SMTP connection")

    return await asyncio.to_thread(verify)


async def _test_generic(creds: dict, endpoint: str) -> TestResult:
    """Fallback: check if the endpoint is reachable. SSRF-protected."""
    try:
        safe_endpoint = _validate_endpoint_url(endpoint)
    except ValueError as exc:
        return TestResult(False, f"Endpoint blocked: {exc}")

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(safe_endpoint)
            if 200 <= resp.status_code < 400:
                return TestResult(
                    True,
                    f"Endpoint reachable — HTTP {resp.status_code}; credentials were not verified",
                    verification_level="reachability",
                )
            return TestResult(False, f"Endpoint rejected the request — HTTP {resp.status_code}")
        except httpx.ConnectError:
            return TestResult(False, f"Cannot reach {safe_endpoint}")
        except Exception as e:
            return TestResult(False, str(e))


# ── Router ─────────────────────────────────────────────────────────────────────

TEST_MAP = {
    "openai":      _test_openai,
    "anthropic":   _test_anthropic,
    "ollama":      _test_ollama,
    "slack":       _test_slack,
    "github":      _test_github,
    "crowdstrike": _test_crowdstrike,
    "pagerduty":   _test_pagerduty,
    "nvidia":      _test_nvidia_nim,
    "nvidia_nim":  _test_nvidia_nim,
    "gemini":      _test_gemini,
    "email":       _test_email,
}


async def test_connector(connector_type: str, creds: dict, endpoint: str = "") -> TestResult:
    """Run the appropriate connectivity test for this connector type."""
    handler = TEST_MAP.get(connector_type)
    if handler:
        return await handler(creds)
    return await _test_generic(creds, endpoint)
