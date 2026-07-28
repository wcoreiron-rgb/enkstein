"""
Declarative REST provider adapters.

Writing one hand-rolled module per connector does not scale to 56 integrations:
each becomes its own place for an auth bug, a missing timeout, an unvalidated
URL, or a silent failure that looks like a clean scan.  Instead a connector is
described by an :class:`AdapterSpec` — how it authenticates, which endpoints to
read, and how to turn a response row into a Finding — and this module supplies
the shared execution, error handling, and provenance tagging.

Three properties are enforced here rather than trusted to each integration:

  * every outbound call is timeout-bounded and SSRF-validated
  * a provider failure never fabricates results; it raises so the caller can
    fall back to clearly labelled demonstration data
  * live results are tagged with their origin and source connector

Adding a connector should be a matter of describing it, not re-implementing
HTTP.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx

from app.claws import provenance
from app.services import device_code_auth
# Reuse the existing hardened SSRF check rather than maintaining a second one.
from app.services.connector_tester import _validate_endpoint_url as validate_outbound_url

logger = logging.getLogger("claw.rest_adapter")

TIMEOUT = httpx.Timeout(30.0)

# Severity vocabulary used by the finding pipeline.
_SEVERITIES = ("critical", "high", "medium", "low", "info")


def normalize_severity(value: Any, default: str = "medium") -> str:
    """Map a provider's severity vocabulary onto the platform's."""
    if value is None:
        return default
    text = str(value).strip().lower()
    aliases = {
        "crit": "critical", "sev1": "critical", "severe": "critical",
        "1": "critical", "5": "critical", "urgent": "critical",
        "important": "high", "sev2": "high", "2": "high", "4": "high",
        "moderate": "medium", "warning": "medium", "sev3": "medium", "3": "medium",
        "minor": "low", "sev4": "low", "note": "low",
        "informational": "info", "information": "info", "none": "info", "0": "info",
    }
    if text in _SEVERITIES:
        return text
    return aliases.get(text, default)


def risk_from_severity(severity: str) -> float:
    """A defensible default risk score when a provider supplies none."""
    return {
        "critical": 92.0,
        "high": 78.0,
        "medium": 55.0,
        "low": 32.0,
        "info": 12.0,
    }.get(severity, 50.0)


@dataclass(frozen=True)
class Endpoint:
    """One provider API call contributing findings."""

    path: str
    # Where the findings live in the response body; None means the body is a list.
    items_key: Optional[str] = None
    method: str = "GET"
    params: dict[str, Any] = field(default_factory=dict)
    json_body: Optional[dict[str, Any]] = None
    # Convert one provider row into a partial Finding dict.
    parse: Optional[Callable[[dict[str, Any], dict[str, str]], Optional[dict]]] = None
    # Convert the whole payload into findings, for providers whose value is an
    # aggregate (for example "37 assets are missing an agent") rather than rows.
    summarize: Optional[Callable[[Any, dict[str, str]], list[dict]]] = None
    # Cap rows so one noisy tenant cannot flood the finding pipeline.
    limit: int = 100
    # Endpoints that are optional enrichment rather than the core signal.
    optional: bool = False


@dataclass(frozen=True)
class AdapterSpec:
    """A complete description of how to read findings from a provider."""

    provider: str
    connector_type: str
    label: str
    claw: str
    # Auth style: bearer, token, basic, header, query, or device.
    auth: str
    endpoints: tuple[Endpoint, ...]
    # Base URL; may contain {field} placeholders filled from credentials.
    base_url: str = ""
    # Credential field holding the secret.
    token_field: str = "api_key"
    # Credential field holding the base URL when the provider is self-hosted
    # or per-tenant.
    base_url_field: Optional[str] = None
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    # A few providers (Bitsight) pass the API token as the basic-auth username
    # with a deliberately empty password.
    allow_empty_password: bool = False
    # For auth="header"/"query": the header or parameter name.
    auth_name: str = "Authorization"
    # Prefix placed before the secret, e.g. "Bearer" or "SSWS".
    auth_prefix: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)
    required_fields: tuple[str, ...] = ()
    # Some providers need a credential composed from several stored fields,
    # such as Tenable's "accessKey=...;secretKey=..." header. The transform
    # runs before auth is built and returns the effective credential map.
    transform: Optional[Callable[[dict[str, str]], dict[str, str]]] = None

    def prepare(self, credentials: dict[str, str]) -> dict[str, str]:
        """Apply the provider's credential transform, if it has one."""
        if self.transform is None:
            return credentials
        merged = dict(credentials)
        merged.update(self.transform(credentials))
        return merged


class AdapterError(RuntimeError):
    """A provider call could not be completed."""


def resolve_base_url(spec: AdapterSpec, credentials: dict[str, str]) -> str:
    """Determine the provider base URL from the spec and credentials."""
    if spec.base_url_field:
        raw = (credentials.get(spec.base_url_field) or "").strip().rstrip("/")
        if not raw:
            raise AdapterError(
                f"{spec.label} requires {spec.base_url_field} to be configured."
            )
        if not raw.startswith(("http://", "https://")):
            raw = f"https://{raw}"
    else:
        raw = spec.base_url
    try:
        return raw.format(**credentials).rstrip("/")
    except KeyError as exc:
        raise AdapterError(f"{spec.label} is missing credential field {exc}.") from exc


async def build_auth(
    spec: AdapterSpec, credentials: dict[str, str]
) -> tuple[dict[str, str], dict[str, str], Optional[tuple[str, str]]]:
    """Return (headers, query params, basic-auth pair) for this provider."""
    headers: dict[str, str] = {"Accept": "application/json", **spec.extra_headers}
    params: dict[str, str] = {}
    basic: Optional[tuple[str, str]] = None

    missing = [f for f in spec.required_fields if not credentials.get(f)]
    if missing:
        raise AdapterError(
            f"{spec.label} requires {', '.join(missing)} to be configured."
        )

    if spec.auth == "basic":
        user = credentials.get(spec.username_field or "username", "")
        pwd = credentials.get(spec.password_field or "password", "")
        if not user or (not pwd and not spec.allow_empty_password):
            raise AdapterError(f"{spec.label} requires a username and password.")
        basic = (user, pwd)
        return headers, params, basic

    if spec.auth == "device":
        token = await device_code_auth.resolve_access_token(credentials)
        if not token:
            token = credentials.get(spec.token_field, "")
        if not token:
            raise AdapterError(f"{spec.label} is not signed in.")
        headers["Authorization"] = f"Bearer {token}"
        return headers, params, basic

    # Some genuinely useful sources — CISA's KEV catalog, abuse.ch feeds — are
    # public. Demanding a key for them would leave a node inert for no reason.
    if spec.auth == "none":
        return headers, params, basic

    secret = credentials.get(spec.token_field, "")
    if not secret:
        raise AdapterError(
            f"{spec.label} requires {spec.token_field} to be configured."
        )

    if spec.auth == "query":
        params[spec.auth_name] = secret
    else:
        prefix = spec.auth_prefix
        headers[spec.auth_name] = f"{prefix} {secret}".strip() if prefix else secret
    return headers, params, basic


def as_mapping(value: Any) -> dict[str, Any]:
    """
    Read a value a summarizer expects to be an object.

    Vendors return a documented object as a list, a string, or null often
    enough that ``(payload or {}).get(...)`` is a live crash rather than a
    theoretical one. Summarizers use this so an unexpected shape yields no
    findings instead of failing the whole connector.
    """
    return value if isinstance(value, dict) else {}


def _extract(payload: Any, items_key: Optional[str]) -> list[dict]:
    """Pull the list of rows out of a provider response."""
    if items_key:
        for part in items_key.split("."):
            if not isinstance(payload, dict):
                return []
            payload = payload.get(part)
            if payload is None:
                return []
    if isinstance(payload, dict):
        # Some providers wrap a single object rather than a list.
        return [payload]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def finalize(finding: dict, spec: AdapterSpec) -> dict:
    """Apply platform defaults so every adapter yields a consistent Finding."""
    severity = normalize_severity(finding.get("severity"))
    result = {
        "claw": spec.claw,
        "provider": spec.provider,
        "category": "misconfiguration",
        "status": "open",
        **finding,
    }
    result["severity"] = severity
    if result.get("risk_score") is None:
        result["risk_score"] = risk_from_severity(severity)
    result["risk_score"] = float(result["risk_score"])
    return result


async def fetch_findings(
    spec: AdapterSpec, credentials: dict[str, str]
) -> list[dict]:
    """
    Execute every endpoint in the spec and return normalized findings.

    Raises :class:`AdapterError` when the provider cannot be reached or refuses
    the credentials, so the caller falls back to labelled demonstration data
    rather than presenting an empty scan as a clean result.
    """
    credentials = spec.prepare(credentials)
    base = resolve_base_url(spec, credentials)
    headers, auth_params, basic = await build_auth(spec, credentials)
    findings: list[dict] = []
    failures: list[str] = []

    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
        for endpoint in spec.endpoints:
            url = f"{base}{endpoint.path.format(**credentials)}"
            # Query parameters are templated like paths so a provider can take
            # operator-supplied scope, such as Shodan's search query, without
            # each spec re-implementing substitution.
            try:
                endpoint_params = {
                    key: (value.format(**credentials) if isinstance(value, str) else value)
                    for key, value in endpoint.params.items()
                }
            except KeyError as exc:
                raise AdapterError(
                    f"{spec.label} is missing credential field {exc}."
                ) from exc
            try:
                # Self-hosted providers accept an operator-supplied base URL,
                # so every request is checked before it leaves the process.
                safe_url = validate_outbound_url(url)
            except ValueError as exc:
                raise AdapterError(f"{spec.label} endpoint blocked: {exc}") from exc

            try:
                resp = await client.request(
                    endpoint.method,
                    safe_url,
                    headers=headers,
                    params={**auth_params, **endpoint_params},
                    json=endpoint.json_body,
                    auth=basic,
                )
            except Exception as exc:
                if endpoint.optional:
                    failures.append(type(exc).__name__)
                    continue
                raise AdapterError(
                    f"{spec.label} could not be reached ({type(exc).__name__})."
                ) from exc

            if resp.status_code in (401, 403):
                raise AdapterError(
                    f"{spec.label} rejected the credentials (HTTP {resp.status_code})."
                )
            if resp.status_code >= 400:
                if endpoint.optional:
                    failures.append(f"HTTP {resp.status_code}")
                    continue
                raise AdapterError(
                    f"{spec.label} returned HTTP {resp.status_code} for {endpoint.path}."
                )

            try:
                payload = resp.json()
            except ValueError:
                if endpoint.optional:
                    failures.append("unreadable response")
                    continue
                raise AdapterError(f"{spec.label} returned an unreadable response.")

            if endpoint.summarize:
                # A parser is written against the vendor's documented shape.
                # Real APIs deviate: a field documented as an object arrives as
                # a list, an error body replaces the payload, a tenant on an
                # older version returns something else entirely. Letting that
                # raise turns one malformed response into a failed scan for
                # every other endpoint in the spec, so contain it here.
                try:
                    summarized = endpoint.summarize(payload, credentials) or []
                except Exception as exc:
                    if not endpoint.optional:
                        raise AdapterError(
                            f"{spec.label} returned an unexpected payload for "
                            f"{endpoint.path} ({type(exc).__name__})."
                        ) from exc
                    failures.append(f"unexpected payload ({type(exc).__name__})")
                    continue
                for item in summarized:
                    findings.append(finalize(item, spec))
                continue

            rows = _extract(payload, endpoint.items_key)[: endpoint.limit]
            for row in rows:
                if not endpoint.parse:
                    continue
                try:
                    parsed = endpoint.parse(row, credentials)
                except Exception as exc:
                    # One unparseable row must not discard the rows around it.
                    logger.debug(
                        "%s: skipping unparseable row (%s)", spec.label, type(exc).__name__
                    )
                    continue
                if parsed:
                    findings.append(finalize(parsed, spec))

    if failures:
        logger.info(
            "%s: %d optional endpoint(s) unavailable (%s)",
            spec.label,
            len(failures),
            ", ".join(sorted(set(failures))),
        )
    # Tag here rather than in the caller: this is the authenticated path, so
    # anything it returns describes the tenant's own estate. Leaving the tag to
    # each caller means a new call site can silently emit untagged findings,
    # which the console cannot distinguish from demonstration data.
    return provenance.live(
        findings, provider=spec.provider, connector=spec.connector_type
    )


async def get_findings(
    spec: AdapterSpec,
    credentials: Optional[dict] = None,
    *,
    simulated: list[dict] | None = None,
) -> list[dict]:
    """
    Standard adapter entry point: live data when configured, clearly labelled
    demonstration data otherwise.
    """
    if credentials:
        try:
            # fetch_findings tags provenance itself.
            return await fetch_findings(spec, credentials)
        except AdapterError as exc:
            logger.warning("%s: %s — using demonstration data", spec.label, exc)
        except Exception as exc:
            logger.warning(
                "%s call failed (%s) — using demonstration data",
                spec.label,
                type(exc).__name__,
            )
    return provenance.simulated(simulated or [], provider=spec.provider)
