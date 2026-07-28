"""
Enkstein — Connector Test Service
=====================================
Tests real connectivity for each connector type.
Uses stored (decrypted) credentials to make a minimal API call.
Returns success/failure + a human-readable message.

Every test is read-only — no writes, no side effects.
"""

from __future__ import annotations

import asyncio
import importlib
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
    "localhost",
    "localhost.localdomain",
    "metadata.goog",
    "metadata",
})


def _blocked_address(addr: "ipaddress._BaseAddress") -> bool:
    """True when this address is loopback, private, link-local, or reserved."""
    if any(addr in net for net in _SSRF_BLOCKED_NETWORKS):
        return True
    return bool(
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


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

    # A literal IP can be checked directly.
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        if _blocked_address(addr):
            raise ValueError(
                f"Endpoint resolves to a private/reserved address: {addr}"
            )
        return url

    # A hostname must be resolved before it can be trusted. Checking only the
    # literal text lets an attacker point a name they control at 127.0.0.1 or
    # the cloud metadata address and reach straight through this guard, which
    # is the standard DNS-based SSRF bypass.
    try:
        resolved = socket.getaddrinfo(host, parsed.port or 0, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Endpoint host '{host}' could not be resolved") from exc

    for family, _type, _proto, _canon, sockaddr in resolved:
        try:
            candidate = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if _blocked_address(candidate):
            raise ValueError(
                f"Endpoint host '{host}' resolves to a private/reserved address"
            )

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


# Connector types served by a hand-written adapter module. Their credentials
# are verified by asking the adapter for findings with real credentials, which
# exercises the provider's own auth path.
_NATIVE_TEST_MODULES: dict[str, tuple[str, str]] = {
    "aws_security_hub": ("app.claws.cloudclaw.providers.aws", "AWS Security Hub"),
    "aws_iam": ("app.claws.cloudclaw.providers.aws", "AWS IAM"),
    "azure_defender": ("app.claws.cloudclaw.providers.azure", "Azure Defender for Cloud"),
    "azure_arm": ("app.claws.cloudclaw.providers.azure", "Azure Resource Manager"),
    "gcp_scc": ("app.claws.cloudclaw.providers.gcp", "GCP Security Command Center"),
    "gcp_iam": ("app.claws.cloudclaw.providers.gcp", "GCP IAM"),
    "defender_endpoint": ("app.claws.endpointclaw.providers.defender", "Microsoft Defender for Endpoint"),
    "sentinelone": ("app.claws.endpointclaw.providers.sentinelone", "SentinelOne"),
    "okta": ("app.claws.accessclaw.providers.okta", "Okta"),
    "entra_id": ("app.claws.accessclaw.providers.entra", "Microsoft Entra ID"),
    "splunk": ("app.claws.logclaw.providers.splunk", "Splunk"),
}

# Local tooling invoked by Terraform Governance rather than remote APIs; there
# are no credentials to verify.
_LOCAL_TOOLING = {
    "terraform_mcp": "Local Terraform MCP tooling — no remote credentials required.",
    "tfsec": "Local IaC scanner — no remote credentials required.",
    "checkov": "Local IaC scanner — no remote credentials required.",
    "infracost": "Local cost analysis — no remote credentials required.",
}


# Microsoft connectors verified by calling an identity endpoint rather than by
# asking for findings.
#
# Testing "did this return findings?" conflated three different outcomes: bad
# credentials, a healthy tenant with nothing to report, and a token missing one
# optional scope. A tenant with no risky users failed its connector test even
# though Graph accepted the token and returned the organisation. These probes
# answer only the question being asked — does the provider accept this
# credential — using an endpoint covered by the base scope every sign-in grants.
_MICROSOFT_IDENTITY_PROBES: dict[str, tuple[str, str, str]] = {
    "entra_id":          ("https://graph.microsoft.com/v1.0/organization", "Microsoft Entra ID", "graph"),
    "azure_ad":          ("https://graph.microsoft.com/v1.0/organization", "Microsoft Entra ID", "graph"),
    "purview":           ("https://graph.microsoft.com/v1.0/organization", "Microsoft Purview", "graph"),
    "mcas":              ("https://graph.microsoft.com/v1.0/organization", "Microsoft Defender for Cloud Apps", "graph"),
    "defender_endpoint": ("https://graph.microsoft.com/v1.0/organization", "Microsoft Defender for Endpoint", "graph"),
    "azure":             ("https://management.azure.com/subscriptions?api-version=2020-01-01", "Microsoft Azure", "arm"),
    "azure_arm":         ("https://management.azure.com/subscriptions?api-version=2020-01-01", "Azure Resource Manager", "arm"),
    "azure_defender":    ("https://management.azure.com/subscriptions?api-version=2020-01-01", "Microsoft Defender for Cloud", "arm"),
    "sentinel":          ("https://management.azure.com/subscriptions?api-version=2020-01-01", "Microsoft Sentinel", "arm"),
}


async def _test_microsoft_identity(connector_type: str, creds: dict) -> Optional[TestResult]:
    """Verify a Microsoft credential against an endpoint its scope covers."""
    probe = _MICROSOFT_IDENTITY_PROBES.get(connector_type)
    if not probe:
        return None
    url, label, audience = probe

    from app.services import device_code_auth

    token = await device_code_auth.resolve_access_token(dict(creds))
    if not token:
        # Not an interactive sign-in: fall through to the adapter's own
        # client-credentials path rather than guessing.
        return None

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
    except httpx.HTTPError as exc:
        return TestResult(False, f"{label} could not be reached ({type(exc).__name__})")

    if resp.status_code == 200:
        return TestResult(
            True,
            f"{label} accepted the sign-in.",
            verification_level="credential",
        )
    if resp.status_code in (401, 403):
        # A token for the other audience is a real, and common, mistake:
        # Graph scopes do not work against Azure Resource Manager.
        hint = (
            " The stored token is for a different Microsoft audience — sign in "
            "again from this connector so the grant matches."
            if audience == "arm"
            else " Sign in again to refresh the grant."
        )
        return TestResult(False, f"{label} rejected the stored sign-in (HTTP {resp.status_code}).{hint}")
    return TestResult(False, f"{label} returned HTTP {resp.status_code} for the sign-in check.")


async def _test_native_adapter(connector_type: str, creds: dict) -> Optional[TestResult]:
    """Verify credentials through a hand-written provider module."""
    entry = _NATIVE_TEST_MODULES.get(connector_type)
    if not entry:
        return None
    module_path, label = entry
    try:
        module = importlib.import_module(module_path)
    except Exception as exc:
        return TestResult(False, f"{label} adapter could not be loaded ({type(exc).__name__})")

    # Imported lazily: provider modules import this module for its SSRF guard.
    from app.claws import credential_aliases

    creds = credential_aliases.resolve(connector_type, dict(creds))

    # ``get_findings`` swallows failures and returns demonstration data so a
    # screen is never blank, which makes it useless for deciding whether a
    # credential works. ``fetch_findings`` raises, so the failure reaching this
    # handler is the provider's real answer.
    authenticated = getattr(module, "fetch_findings", None)
    try:
        if callable(authenticated):
            findings = await authenticated(creds)
        else:
            findings = await module.get_findings(credentials=creds)
    except ValueError as exc:
        # The adapter rejected the credentials before making a call, which is
        # a configuration problem the operator can actually fix.
        return TestResult(False, str(exc))
    except httpx.HTTPError as exc:
        return TestResult(
            False,
            f"{label} could not be reached ({type(exc).__name__}) — check the host and network path.",
        )
    except Exception as exc:
        return TestResult(False, f"{label} test failed ({type(exc).__name__})")

    live = [f for f in findings if f.get("data_origin") == "live"]
    if live:
        return TestResult(
            True,
            f"{label} accepted the credentials — {len(live)} finding(s) returned",
            verification_level="credential",
        )
    # The call succeeded and returned nothing. That is a healthy provider with
    # nothing to report, not a rejected credential.
    return TestResult(
        True,
        f"{label} accepted the credentials — no findings to report.",
        verification_level="credential",
    )


async def test_connector(connector_type: str, creds: dict, endpoint: str = "") -> TestResult:
    """Run the appropriate connectivity test for this connector type."""
    handler = TEST_MAP.get(connector_type)
    if handler:
        return await handler(creds)

    local_note = _LOCAL_TOOLING.get(connector_type)
    if local_note:
        return TestResult(True, local_note, verification_level="local")

    # An interactive Microsoft sign-in is verified against an identity endpoint
    # before any findings query, so an empty-but-healthy tenant is not reported
    # as a credential failure.
    microsoft = await _test_microsoft_identity(connector_type, creds)
    if microsoft is not None:
        return microsoft

    native = await _test_native_adapter(connector_type, creds)
    if native is not None:
        return native

    # A connector with a declarative adapter can be verified for real: call the
    # provider with the stored credentials and see whether it accepts them.
    # Reachability alone was never trust — an unauthenticated 200 from a login
    # page told an operator nothing about whether their key works.
    spec_result = await _test_via_adapter(connector_type, creds)
    if spec_result is not None:
        return spec_result

    return await _test_generic(creds, endpoint)


async def _test_via_adapter(connector_type: str, creds: dict) -> Optional[TestResult]:
    """
    Verify credentials by exercising the connector's own adapter.

    Returns None when the connector has no declarative adapter, so the caller
    falls back to a reachability probe.
    """
    # Imported lazily: the adapter registry imports provider modules that in
    # turn import this module for its SSRF validator.
    from app.claws.adapters import registry
    from app.claws.rest_adapter import AdapterError, fetch_findings

    spec = registry.spec_for(connector_type)
    if spec is None:
        return None

    missing = [f for f in spec.required_fields if not creds.get(f)]
    if missing:
        return TestResult(False, f"Missing required fields: {', '.join(missing)}")

    try:
        findings = await fetch_findings(spec, dict(creds))
    except AdapterError as exc:
        # The adapter already distinguishes a credential rejection from an
        # unreachable host, so its message is the useful one to surface.
        return TestResult(False, str(exc))
    except Exception as exc:
        return TestResult(False, f"{spec.label} test failed ({type(exc).__name__})")

    return TestResult(
        True,
        f"{spec.label} accepted the credentials — {len(findings)} finding(s) returned",
        verification_level="credential",
    )
