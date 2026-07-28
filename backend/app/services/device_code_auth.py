"""
OAuth 2.0 device authorization grant (RFC 8628) for connector onboarding.

Most security connectors authenticate with ``client_credentials``, which needs
an app registration and a client secret.  That is the correct posture for
unattended scanning, but it is a poor first-run experience: an operator has to
leave Enkstein, register an application, mint a secret, and paste it back.

The device code grant gives those providers a genuine one-approval flow.
Enkstein asks the provider for a code, the operator approves once in a browser,
and Enkstein receives a refresh token.  This is a documented provider flow, not
browser-session scraping: no cookies, page automation, or vendor session tokens
are involved, and the operator can see and revoke the grant on the provider's
own consent screen.

Only providers that actually publish a device endpoint are supported.  Anything
else keeps client-credential configuration, because pretending a provider
supports interactive auth when it does not would leave an operator stuck on a
screen that can never succeed.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger("connectors.device_code")

TIMEOUT = httpx.Timeout(30.0)

# Microsoft's public client for device-code sign-in (Azure CLI).  Using a
# first-party public client means the operator does not need to pre-register an
# application before connecting, and no client secret is ever involved.
_AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"


@dataclass(frozen=True)
class DeviceCodeProvider:
    """A provider that supports the device authorization grant."""

    key: str
    label: str
    device_endpoint: str
    token_endpoint: str
    client_id: str
    scope: str
    connector_types: tuple[str, ...]
    # GitHub requires this header to receive JSON rather than form-encoded text.
    extra_headers: dict[str, str] = field(default_factory=dict)
    requires_tenant: bool = False


def _microsoft(key: str, label: str, scope: str, connector_types: tuple[str, ...]):
    return DeviceCodeProvider(
        key=key,
        label=label,
        # {tenant} is substituted per request; 'organizations' works for any
        # work or school account when the operator does not know the tenant ID.
        device_endpoint="https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode",
        token_endpoint="https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        client_id=_AZURE_CLI_CLIENT_ID,
        scope=scope,
        connector_types=connector_types,
        requires_tenant=True,
    )


PROVIDERS: dict[str, DeviceCodeProvider] = {
    "microsoft_graph": _microsoft(
        "microsoft_graph",
        "Microsoft Entra ID",
        # offline_access is what yields a refresh token; without it the grant
        # expires in about an hour and scheduled scans would silently stop.
        "offline_access https://graph.microsoft.com/.default",
        ("entra_id", "azure_ad", "defender_endpoint", "mcas", "purview"),
    ),
    "azure_management": _microsoft(
        "azure_management",
        "Microsoft Azure",
        "offline_access https://management.azure.com/.default",
        ("azure", "azure_arm", "sentinel", "azure_defender"),
    ),
    "github": DeviceCodeProvider(
        key="github",
        label="GitHub",
        device_endpoint="https://github.com/login/device/code",
        token_endpoint="https://github.com/login/oauth/access_token",
        # GitHub requires an OAuth app client ID; supplied by configuration
        # rather than hardcoded, since there is no first-party public client.
        client_id=getattr(settings, "GITHUB_OAUTH_CLIENT_ID", "") or "",
        scope="repo security_events read:org",
        connector_types=("github",),
        extra_headers={"Accept": "application/json"},
    ),
}


def provider_for_connector(connector_type: str) -> Optional[DeviceCodeProvider]:
    """Return the device-code provider serving a connector type, if any."""
    for provider in PROVIDERS.values():
        if connector_type in provider.connector_types:
            return provider
    return None


def supports_device_code(connector_type: str) -> bool:
    provider = provider_for_connector(connector_type)
    if provider is None:
        return False
    return bool(provider.client_id)


class DeviceCodeError(RuntimeError):
    """Raised when a provider refuses or cannot complete a device grant."""


def _resolve(url: str, tenant: Optional[str]) -> str:
    # 'organizations' accepts any work or school account, which is the right
    # default when the operator has not supplied a specific tenant.
    return url.replace("{tenant}", tenant or "organizations")


async def start_device_authorization(
    provider: DeviceCodeProvider, *, tenant: Optional[str] = None
) -> dict[str, Any]:
    """
    Begin a device grant.  Returns the verification URL and user code that the
    operator approves in a browser, plus the device code used for polling.
    """
    if not provider.client_id:
        raise DeviceCodeError(
            f"{provider.label} device sign-in needs an OAuth client ID to be configured first."
        )

    data = {"client_id": provider.client_id, "scope": provider.scope}
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.post(
            _resolve(provider.device_endpoint, tenant),
            data=data,
            headers=provider.extra_headers or None,
        )
    if resp.status_code >= 400:
        raise DeviceCodeError(
            f"{provider.label} refused the device authorization request "
            f"(HTTP {resp.status_code})."
        )

    payload = resp.json()
    device_code = payload.get("device_code")
    user_code = payload.get("user_code")
    verification_uri = payload.get("verification_uri") or payload.get(
        "verification_url"
    )
    if not device_code or not user_code or not verification_uri:
        raise DeviceCodeError(f"{provider.label} returned an incomplete device response.")

    expires_in = int(payload.get("expires_in", 900))
    return {
        "provider": provider.key,
        "label": provider.label,
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": payload.get("verification_uri_complete") or verification_uri,
        "interval": int(payload.get("interval", 5)),
        "expires_in": expires_in,
        "expires_at": time.time() + expires_in,
        "message": payload.get("message"),
    }


# Provider responses that mean "keep waiting" rather than "this failed".
_PENDING = {"authorization_pending", "slow_down"}


async def poll_device_token(
    provider: DeviceCodeProvider,
    device_code: str,
    *,
    tenant: Optional[str] = None,
) -> dict[str, Any]:
    """
    Exchange an approved device code for tokens.

    Returns ``{"status": "pending"}`` while the operator has not yet approved,
    ``{"status": "complete", "credentials": {...}}`` once approved.  A single
    poll is performed per call so the caller controls timing and can cancel.
    """
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": provider.client_id,
        "device_code": device_code,
    }
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.post(
            _resolve(provider.token_endpoint, tenant),
            data=data,
            headers=provider.extra_headers or None,
        )

    try:
        payload = resp.json()
    except ValueError:
        raise DeviceCodeError(f"{provider.label} returned an unreadable token response.")

    error = payload.get("error")
    if error in _PENDING:
        return {"status": "pending", "error": error, "slow_down": error == "slow_down"}
    if error == "expired_token":
        raise DeviceCodeError("The sign-in code expired before it was approved.")
    if error == "access_denied":
        raise DeviceCodeError("Sign-in was declined on the provider consent screen.")
    if error:
        # Provider error descriptions can echo request detail, so only the
        # stable error code is surfaced.
        raise DeviceCodeError(f"{provider.label} rejected the sign-in ({error}).")

    access_token = payload.get("access_token")
    if not access_token:
        raise DeviceCodeError(f"{provider.label} returned no access token.")

    credentials: dict[str, str] = {
        "auth_method": "device_code",
        "device_provider": provider.key,
        "access_token": access_token,
    }
    if payload.get("refresh_token"):
        credentials["refresh_token"] = payload["refresh_token"]
    if tenant:
        credentials["tenant_id"] = tenant
    expires_in = payload.get("expires_in")
    if expires_in:
        credentials["expires_at"] = str(int(time.time()) + int(expires_in))

    return {
        "status": "complete",
        "credentials": credentials,
        "has_refresh_token": bool(payload.get("refresh_token")),
    }


async def refresh_access_token(credentials: dict[str, str]) -> Optional[dict[str, str]]:
    """
    Renew an expired device-code access token using its refresh token.

    Returns updated credentials, or None when the grant cannot be renewed and
    the operator must sign in again.
    """
    provider = PROVIDERS.get(credentials.get("device_provider", ""))
    refresh_token = credentials.get("refresh_token")
    if not provider or not refresh_token:
        return None

    data = {
        "grant_type": "refresh_token",
        "client_id": provider.client_id,
        "refresh_token": refresh_token,
        "scope": provider.scope,
    }
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(
                _resolve(provider.token_endpoint, credentials.get("tenant_id")),
                data=data,
                headers=provider.extra_headers or None,
            )
        payload = resp.json()
    except Exception:
        logger.warning("Device-code refresh failed for %s", provider.key)
        return None

    access_token = payload.get("access_token")
    if not access_token:
        return None

    updated = dict(credentials)
    updated["access_token"] = access_token
    if payload.get("refresh_token"):
        updated["refresh_token"] = payload["refresh_token"]
    if payload.get("expires_in"):
        updated["expires_at"] = str(int(time.time()) + int(payload["expires_in"]))
    return updated


def is_expired(credentials: dict[str, str], *, skew_seconds: int = 120) -> bool:
    """True when a device-code access token has expired or is about to."""
    raw = credentials.get("expires_at")
    if not raw:
        return False
    try:
        return time.time() >= float(raw) - skew_seconds
    except (TypeError, ValueError):
        return False


def is_device_code(credentials: dict[str, str]) -> bool:
    """True when these credentials came from an interactive device grant."""
    return credentials.get("auth_method") == "device_code" and bool(
        credentials.get("access_token")
    )


async def resolve_access_token(credentials: dict[str, str]) -> Optional[str]:
    """
    Return a usable access token for device-code credentials, refreshing first
    when the current one has expired.  Returns None for credentials that are
    not device-code based, so callers fall through to their own auth flow.

    The refreshed token is returned to the caller but not persisted here; the
    adapter layer has no database session, and a stale stored token simply
    causes one extra refresh on the next scan.
    """
    # Browser sign-in (authorization code + PKCE) produces the same kind of
    # bearer token, so it resolves through this one choke point rather than
    # every adapter learning a second auth shape.
    if credentials.get("auth_method") == "browser_oauth":
        from app.services import browser_auth

        return await browser_auth.refresh_access_token(credentials)
    if not is_device_code(credentials):
        return None
    if not is_expired(credentials):
        return credentials["access_token"]
    refreshed = await refresh_access_token(credentials)
    if refreshed:
        # Mutate in place so a caller reusing this dict within one scan does
        # not trigger a second refresh for the same expiry.
        credentials.update(refreshed)
        return refreshed["access_token"]
    return None
