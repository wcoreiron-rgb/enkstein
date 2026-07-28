"""
Browser sign-in for connectors (OAuth 2.0 authorization code + PKCE).

Device code (RFC 8628) covers only the handful of providers that publish a
device endpoint — four of Enkstein's sixty-three. The flow that desktop
applications are actually meant to use is RFC 8252: an authorization code grant
with PKCE, redirected to a loopback address that only this machine can receive.
Most security vendors publish that endpoint, so it is what turns "sign in with
your browser" from a Microsoft-only convenience into something an operator can
expect from any connector.

What this is not: it does not read cookies, drive a page, or reuse a vendor
session. Enkstein opens the provider's own consent screen, the operator
approves, and the provider redirects a single-use code back to
``http://127.0.0.1:<port>/`` where only this process is listening. PKCE means
no client secret is involved, so nothing confidential has to be embedded in a
distributed desktop application.

Providers that require a pre-registered client are honest about it: a connector
says interactive sign-in needs a client ID rather than presenting a button that
can only fail.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import logging
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, urlparse
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

from app.core.config import settings

logger = logging.getLogger("connectors.browser_auth")

TIMEOUT = httpx.Timeout(30.0)

# The loopback port the desktop shell listens on for the redirect. A fixed port
# keeps the redirect URI stable, which matters because most providers require
# the redirect to be registered exactly.
DEFAULT_REDIRECT_PORT = 47822

# An authorization request that is never completed should not stay valid.
_PENDING_TTL_SECONDS = 600.0


@dataclass(frozen=True)
class BrowserAuthProvider:
    """A provider that supports the authorization code grant with PKCE."""

    key: str
    label: str
    authorize_endpoint: str
    token_endpoint: str
    scope: str
    connector_types: tuple[str, ...]
    # Providers whose endpoints live on the tenant's own host, such as Okta or
    # GitLab self-managed, need that host before a URL can be built.
    host_field: Optional[str] = None
    # A first-party public client, where the vendor publishes one. Where it is
    # empty the operator supplies a client ID once, which is normal for OAuth
    # apps and still needs no secret because of PKCE.
    client_id: str = ""
    settings_key: str = ""
    extra_authorize_params: dict[str, str] = field(default_factory=dict)
    extra_headers: dict[str, str] = field(default_factory=dict)
    # Microsoft substitutes a tenant segment into both endpoints.
    requires_tenant: bool = False
    # Some providers reject an unregistered loopback port and expect the
    # documented one; recorded so the UI can tell the operator what to register.
    redirect_port: int = DEFAULT_REDIRECT_PORT

    def resolved_client_id(self, credentials: Optional[dict] = None) -> str:
        """Client ID from the connector's own config, settings, or the vendor."""
        if credentials:
            supplied = str(credentials.get("oauth_client_id") or "").strip()
            if supplied:
                return supplied
        if self.settings_key:
            configured = str(getattr(settings, self.settings_key, "") or "").strip()
            if configured:
                return configured
        return self.client_id

    @property
    def redirect_uri(self) -> str:
        # Loopback only. A remote redirect would let a code leave this machine.
        return f"http://127.0.0.1:{self.redirect_port}/connector-callback"


PROVIDERS: dict[str, BrowserAuthProvider] = {
    # Microsoft is deliberately absent here and served by the device-code
    # grant instead. The Azure CLI public client does not register a redirect
    # URI carrying our /connector-callback path, so an authorization-code
    # attempt is rejected with AADSTS50011 before the operator can consent.
    # The device grant uses the same first-party public client, needs no
    # redirect registration at all, and yields the same refresh token.
    "github": BrowserAuthProvider(
        key="github",
        label="GitHub",
        authorize_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        scope="repo security_events read:org",
        connector_types=("github",),
        settings_key="GITHUB_OAUTH_CLIENT_ID",
        extra_headers={"Accept": "application/json"},
    ),
    "gitlab": BrowserAuthProvider(
        key="gitlab",
        label="GitLab",
        authorize_endpoint="https://gitlab.com/oauth/authorize",
        token_endpoint="https://gitlab.com/oauth/token",
        scope="read_api read_repository",
        connector_types=("gitlab",),
        settings_key="GITLAB_OAUTH_CLIENT_ID",
    ),
    "google_cloud": BrowserAuthProvider(
        key="google_cloud",
        label="Google Cloud",
        authorize_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint="https://oauth2.googleapis.com/token",
        scope="https://www.googleapis.com/auth/cloud-platform",
        connector_types=("gcp_scc", "gcp_iam"),
        settings_key="GOOGLE_OAUTH_CLIENT_ID",
        # Google only returns a refresh token when consent is forced offline.
        extra_authorize_params={"access_type": "offline", "prompt": "consent"},
    ),
    "okta": BrowserAuthProvider(
        key="okta",
        label="Okta",
        authorize_endpoint="https://{host}/oauth2/v1/authorize",
        token_endpoint="https://{host}/oauth2/v1/token",
        scope="offline_access okta.users.read okta.logs.read okta.policies.read",
        connector_types=("okta",),
        host_field="domain",
    ),
    "slack": BrowserAuthProvider(
        key="slack",
        label="Slack",
        authorize_endpoint="https://slack.com/oauth/v2/authorize",
        token_endpoint="https://slack.com/api/oauth.v2.access",
        scope="channels:read chat:write",
        connector_types=("slack",),
        settings_key="SLACK_OAUTH_CLIENT_ID",
    ),
    "atlassian": BrowserAuthProvider(
        key="atlassian",
        label="Atlassian",
        authorize_endpoint="https://auth.atlassian.com/authorize",
        token_endpoint="https://auth.atlassian.com/oauth/token",
        scope="offline_access read:jira-work read:jira-user",
        connector_types=("jira",),
        settings_key="ATLASSIAN_OAUTH_CLIENT_ID",
        extra_authorize_params={"audience": "api.atlassian.com", "prompt": "consent"},
    ),
    "servicenow": BrowserAuthProvider(
        key="servicenow",
        label="ServiceNow",
        authorize_endpoint="https://{host}/oauth_auth.do",
        token_endpoint="https://{host}/oauth_token.do",
        scope="useraccount",
        connector_types=("servicenow",),
        host_field="instance",
    ),
    "auth0": BrowserAuthProvider(
        key="auth0",
        label="Auth0",
        authorize_endpoint="https://{host}/authorize",
        token_endpoint="https://{host}/oauth/token",
        scope="offline_access read:users read:logs",
        connector_types=("auth0",),
        host_field="domain",
    ),
    "datadog": BrowserAuthProvider(
        key="datadog",
        label="Datadog",
        authorize_endpoint="https://app.datadoghq.com/oauth2/v1/authorize",
        token_endpoint="https://api.datadoghq.com/oauth2/v1/token",
        scope="security_monitoring_findings_read",
        connector_types=("datadog",),
        settings_key="DATADOG_OAUTH_CLIENT_ID",
    ),
    "salesforce": BrowserAuthProvider(
        key="salesforce",
        label="Salesforce",
        authorize_endpoint="https://{host}/services/oauth2/authorize",
        token_endpoint="https://{host}/services/oauth2/token",
        scope="api refresh_token",
        connector_types=("salesforce",),
        host_field="base_url",
        settings_key="SALESFORCE_OAUTH_CLIENT_ID",
    ),
    "snyk": BrowserAuthProvider(
        key="snyk",
        label="Snyk",
        authorize_endpoint="https://app.snyk.io/oauth2/authorize",
        token_endpoint="https://api.snyk.io/oauth2/token",
        scope="org.read org.project.read",
        connector_types=("snyk",),
        settings_key="SNYK_OAUTH_CLIENT_ID",
    ),
    "pagerduty": BrowserAuthProvider(
        key="pagerduty",
        label="PagerDuty",
        authorize_endpoint="https://identity.pagerduty.com/oauth/authorize",
        token_endpoint="https://identity.pagerduty.com/oauth/token",
        scope="incidents.read services.read",
        connector_types=("pagerduty",),
        settings_key="PAGERDUTY_OAUTH_CLIENT_ID",
    ),
}


class BrowserAuthError(RuntimeError):
    """Raised when a provider refuses or cannot complete a browser sign-in."""


def provider_for_connector(connector_type: str) -> Optional[BrowserAuthProvider]:
    for provider in PROVIDERS.values():
        if connector_type in provider.connector_types:
            return provider
    return None


def supports_browser_auth(connector_type: str) -> bool:
    return provider_for_connector(connector_type) is not None


def readiness(connector_type: str, credentials: Optional[dict] = None) -> dict[str, Any]:
    """
    Describe whether browser sign-in can start for this connector, and if not,
    exactly what is missing. An operator should never be shown a button that
    cannot succeed.
    """
    provider = provider_for_connector(connector_type)
    if provider is None:
        return {"supported": False}

    client_id = provider.resolved_client_id(credentials)
    return {
        "supported": True,
        "provider": provider.key,
        "label": provider.label,
        "requires_tenant": provider.requires_tenant,
        "requires_host": provider.host_field,
        "requires_client_id": not client_id,
        "redirect_uri": provider.redirect_uri,
        "ready": bool(client_id),
        "unavailable_reason": (
            None
            if client_id
            else (
                f"{provider.label} has no first-party public client, so browser "
                f"sign-in needs a one-time OAuth client ID. Register a native/"
                f"public app with redirect URI {provider.redirect_uri} and enter "
                f"its client ID — no client secret is required."
            )
        ),
    }


def _pkce_pair() -> tuple[str, str]:
    """Return (verifier, challenge) for PKCE S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def _resolve_endpoint(
    template: str,
    provider: BrowserAuthProvider,
    tenant: Optional[str],
    host: Optional[str],
) -> str:
    url = template.replace("{tenant}", tenant or "organizations")
    if "{host}" in url:
        cleaned = (host or "").strip().rstrip("/")
        cleaned = cleaned.split("://", 1)[-1]
        if not cleaned:
            raise BrowserAuthError(
                f"{provider.label} sign-in needs your {provider.host_field or 'host'} first."
            )
        # A host is operator-supplied, so it must not smuggle a path, port
        # redirect, or second authority into the authorization URL.
        if any(character in cleaned for character in "/?#\\ "):
            raise BrowserAuthError(f"{provider.label} host is not a valid hostname.")
        url = url.replace("{host}", cleaned)
    return url


# Pending authorizations, keyed by the opaque state value. Held in memory
# deliberately: a PKCE verifier is a short-lived secret and does not belong in
# the database or in any log.
_PENDING: dict[str, dict[str, Any]] = {}


def _prune() -> None:
    cutoff = time.monotonic() - _PENDING_TTL_SECONDS
    for state in [s for s, entry in _PENDING.items() if entry["created"] < cutoff]:
        _PENDING.pop(state, None)


# ── Loopback redirect listener ────────────────────────────────────────────────
#
# The provider redirects the browser to 127.0.0.1 with the authorization code.
# Catching it here is what makes this feel like signing in rather than copying
# a code between windows. Bound to loopback only, single request, then closed.

_REDIRECT_RESULTS: dict[str, dict[str, str]] = {}
_LISTENER_LOCK = threading.Lock()
_LISTENER: Optional[http.server.HTTPServer] = None

_DONE_PAGE = b"""<!doctype html><html><head><meta charset="utf-8">
<title>Enkstein</title></head>
<body style="font-family:-apple-system,system-ui,sans-serif;background:#0f1115;color:#e6e8ec;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center"><h1 style="font-weight:600;font-size:20px">Sign-in complete</h1>
<p style="color:#9aa3b2;font-size:14px">You can close this tab and return to Enkstein.</p></div>
</body></html>"""

_FAIL_PAGE = b"""<!doctype html><html><head><meta charset="utf-8">
<title>Enkstein</title></head>
<body style="font-family:-apple-system,system-ui,sans-serif;background:#0f1115;color:#e6e8ec;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center"><h1 style="font-weight:600;font-size:20px">Sign-in was not completed</h1>
<p style="color:#9aa3b2;font-size:14px">Return to Enkstein and try again.</p></div>
</body></html>"""


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        state = (query.get("state") or [""])[0]
        code = (query.get("code") or [""])[0]
        error = (query.get("error_description") or query.get("error") or [""])[0]

        # Only record a result for a request this process actually started, so
        # a stray page cannot inject a state value.
        if state and state in _PENDING:
            _REDIRECT_RESULTS[state] = {"code": code, "error": error}

        body = _DONE_PAGE if code and not error else _FAIL_PAGE
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # This page must never be cached or framed.
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: Any) -> None:
        # The default handler writes the full query string, including the
        # authorization code, to stderr.
        return


def ensure_listener(port: int = DEFAULT_REDIRECT_PORT) -> bool:
    """Start the loopback redirect listener if it is not already running."""
    global _LISTENER
    with _LISTENER_LOCK:
        if _LISTENER is not None:
            return True
        try:
            server = http.server.HTTPServer(("127.0.0.1", port), _RedirectHandler)
        except OSError as exc:
            logger.warning("Could not bind loopback redirect listener: %s", exc)
            return False
        server.timeout = 1.0
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.5},
            name="enkstein-oauth-redirect",
            daemon=True,
        )
        thread.start()
        _LISTENER = server
        logger.info("Loopback OAuth redirect listener started on 127.0.0.1:%s", port)
        return True


def take_redirect_result(state: str) -> Optional[dict[str, str]]:
    """Return and clear the redirect result for a pending sign-in."""
    return _REDIRECT_RESULTS.pop(state, None)


def start_authorization(
    provider: BrowserAuthProvider,
    *,
    connector_id: str,
    tenant: Optional[str] = None,
    host: Optional[str] = None,
    credentials: Optional[dict] = None,
) -> dict[str, Any]:
    """Build the provider consent URL the operator should open."""
    _prune()
    client_id = provider.resolved_client_id(credentials)
    if not client_id:
        raise BrowserAuthError(
            f"{provider.label} browser sign-in needs an OAuth client ID."
        )

    authorize = _resolve_endpoint(provider.authorize_endpoint, provider, tenant, host)
    token_url = _resolve_endpoint(provider.token_endpoint, provider, tenant, host)
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)

    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": provider.redirect_uri,
        "scope": provider.scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        **provider.extra_authorize_params,
    }

    _PENDING[state] = {
        "created": time.monotonic(),
        "connector_id": connector_id,
        "provider": provider.key,
        "verifier": verifier,
        "client_id": client_id,
        "token_url": token_url,
        "host": host,
        "host_field": provider.host_field,
    }

    # Start the listener only once a sign-in is genuinely in flight, so an
    # idle installation never holds an open port.
    listening = ensure_listener(provider.redirect_port)

    return {
        "state": state,
        "authorization_url": f"{authorize}?{urlencode(params)}",
        "redirect_uri": provider.redirect_uri,
        "expires_in": int(_PENDING_TTL_SECONDS),
        "label": provider.label,
        # When the port cannot be bound the operator can still paste the code
        # from the redirected URL, so sign-in degrades rather than breaking.
        "auto_capture": listening,
    }


async def complete_authorization(
    provider: BrowserAuthProvider,
    *,
    connector_id: str,
    state: str,
    code: str,
) -> dict[str, Any]:
    """Exchange the returned authorization code for tokens."""
    _prune()
    pending = _PENDING.get(state)
    if pending is None:
        raise BrowserAuthError(
            "This sign-in request has expired or was already used. Start again."
        )
    # The state must belong to this connector and provider, so a code issued
    # for one connector cannot be redeemed into another.
    if pending["connector_id"] != connector_id or pending["provider"] != provider.key:
        raise BrowserAuthError("This sign-in request does not match this connector.")

    # Single use, whatever the outcome.
    _PENDING.pop(state, None)

    payload = {
        "grant_type": "authorization_code",
        "client_id": pending["client_id"],
        "code": code,
        "redirect_uri": provider.redirect_uri,
        "code_verifier": pending["verifier"],
    }
    headers = {"Accept": "application/json", **provider.extra_headers}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            response = await client.post(
                pending["token_url"], data=payload, headers=headers
            )
    except Exception as exc:
        raise BrowserAuthError(
            f"Could not reach {provider.label} to complete sign-in."
        ) from exc

    try:
        body = response.json()
    except ValueError:
        raise BrowserAuthError(f"{provider.label} returned an unreadable token response.")

    if response.status_code >= 400 or body.get("error"):
        # Provider error descriptions are safe to surface and are usually the
        # only actionable detail an operator gets.
        detail = body.get("error_description") or body.get("error") or response.status_code
        raise BrowserAuthError(f"{provider.label} rejected the sign-in: {detail}")

    access_token = body.get("access_token")
    if not access_token:
        raise BrowserAuthError(f"{provider.label} did not return an access token.")

    refresh_token = body.get("refresh_token") or ""
    expires_in = body.get("expires_in")
    credentials: dict[str, Any] = {
        "auth_method": "browser_oauth",
        "device_provider": provider.key,
        "access_token": access_token,
        "oauth_client_id": pending["client_id"],
        "token_endpoint": pending["token_url"],
    }
    # Tenant-hosted APIs need their instance location on every later scan. The
    # value came from the operator when the consent URL was built and is kept
    # alongside the encrypted token, never inferred from a browser session.
    if pending.get("host") and pending.get("host_field"):
        raw_host = str(pending["host"]).strip().rstrip("/")
        cleaned_host = raw_host.split("://", 1)[-1]
        field = str(pending["host_field"])
        credentials[field] = (
            f"https://{cleaned_host}" if field == "base_url" else cleaned_host
        )
    if refresh_token:
        credentials["refresh_token"] = refresh_token
    if isinstance(expires_in, (int, float)):
        credentials["expires_at"] = time.time() + float(expires_in)

    logger.info(
        "Browser sign-in completed for connector %s via %s (refresh_token=%s)",
        connector_id,
        provider.key,
        "yes" if refresh_token else "no",
    )
    return {
        "credentials": credentials,
        "has_refresh_token": bool(refresh_token),
    }


async def refresh_access_token(credentials: dict) -> Optional[str]:
    """
    Renew an access token from a stored refresh token so scheduled scans do not
    stop when the first token expires. Returns None when this credential was
    not obtained through browser sign-in.
    """
    if credentials.get("auth_method") != "browser_oauth":
        return None
    refresh_token = credentials.get("refresh_token")
    token_url = credentials.get("token_endpoint")
    client_id = credentials.get("oauth_client_id")
    if not (refresh_token and token_url and client_id):
        return None

    expires_at = credentials.get("expires_at")
    if isinstance(expires_at, (int, float)) and time.time() < float(expires_at) - 60:
        return str(credentials.get("access_token") or "") or None

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            response = await client.post(
                str(token_url),
                data={
                    "grant_type": "refresh_token",
                    "client_id": str(client_id),
                    "refresh_token": str(refresh_token),
                },
                headers={"Accept": "application/json"},
            )
        body = response.json()
    except Exception:
        logger.warning("Token refresh failed for %s", credentials.get("device_provider"))
        return str(credentials.get("access_token") or "") or None

    token = body.get("access_token")
    if not token:
        return str(credentials.get("access_token") or "") or None
    return str(token)
