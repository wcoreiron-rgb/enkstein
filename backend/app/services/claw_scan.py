"""
Shared Claw scan execution.

Every Claw answers the same question when it scans: is a real connector wired
up for any of my providers, and if so, what did it return?  Before this helper
each Claw answered it slightly differently, and three behaviours had drifted
apart in ways a beta tenant would notice:

  * Claws with working provider adapters never called them from ``/scan``.
  * Claws that only checked ``is_connector_configured`` hid their demonstration
    findings once a credential existed but had nothing to replace them with, so
    connecting a connector made the module look broken instead of populated.
  * A connector that errored was indistinguishable from one that was absent.

``run_claw_scan`` centralises the resolution order: try every configured
adapter, then return an honest unavailable result unless the operator has
explicitly enabled local demonstration data. Origin tagging is applied here so
no Claw can accidentally present demo data as live.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.connector import Connector
from app.core.config import settings
from app.core.zero_trust import default_pillar
from app.services import secrets_manager
from app.services.finding_pipeline import ingest_findings

logger = logging.getLogger("claw.scan")


def _registry():
    # Imported lazily: the adapter registry imports provider modules, and some
    # Claw route modules are imported while the registry itself is loading.
    from app.claws.adapters import registry

    return registry


def resolve_adapter(cfg: dict[str, Any]):
    """
    Return the adapter for a provider entry.

    An explicit ``adapter`` wins, so a Claw can keep a bespoke module. Otherwise
    the shared registry supplies one for any connector type that has a
    declarative spec, which is what lets every marketplace connector become
    scannable without each Claw restating its own wiring.
    """
    if cfg.get("adapter") is not None:
        return cfg["adapter"]
    raw = cfg.get("connector_types") or cfg.get("connector_type")
    types = raw if isinstance(raw, (list, tuple)) else [raw] if raw else []
    registry = _registry()
    for connector_type in types:
        adapter = registry.adapter_for(connector_type)
        if adapter is not None:
            return adapter
    return None


def has_live_adapter(provider_config: list[dict[str, Any]]) -> bool:
    """True when at least one provider can actually fetch tenant data."""
    return any(resolve_adapter(cfg) is not None for cfg in provider_config)


async def fetch_via_adapter(adapter: Any, credentials: dict) -> list[dict[str, Any]]:
    """
    Fetch findings in a way that lets a provider failure stay a failure.

    Bespoke provider modules expose ``get_findings``, which is designed for
    standalone presentation and swallows errors so a screen is never blank.
    Reporting that as a successful scan is how an operator ends up trusting
    demonstration data. Modules that also expose ``fetch_findings`` raise on
    failure, so prefer it whenever it exists.
    """
    authenticated = getattr(adapter, "fetch_findings", None)
    if callable(authenticated):
        return await authenticated(credentials)
    return await adapter.get_findings(credentials=credentials)


async def resolve_credentials(
    db: AsyncSession, connector_type: str | list[str], *, tenant_id: str
) -> Optional[dict]:
    """Return decrypted credentials for the first configured connector, if any."""
    types = connector_type if isinstance(connector_type, list) else [connector_type]
    for ct in types:
        try:
            result = await db.execute(
                select(Connector)
                .where(Connector.connector_type == ct)
                .where(Connector.tenant_id == tenant_id)
            )
            for connector in result.scalars().all():
                creds = secrets_manager.get_credential(str(connector.id), tenant_id=tenant_id)
                if creds:
                    return creds
        except Exception:
            logger.exception("Failed resolving credentials for connector type %s", ct)
    return None


def _prepare(
    findings: list[dict[str, Any]],
    *,
    claw: str,
    provider: str | None,
    origin: str,
    connector: str | None = None,
) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for raw in findings:
        entry = dict(raw)
        entry.setdefault("claw", claw)
        if provider:
            entry.setdefault("provider", provider)
        if "severity" in entry:
            entry["severity"] = str(entry["severity"]).lower()
        # setdefault so an adapter that already tagged itself keeps its own
        # origin; only untagged findings inherit the caller's classification.
        entry.setdefault("data_origin", origin)
        if connector and entry.get("data_origin") == "live":
            entry.setdefault("source_connector", connector)
        # Every finding carries a Zero Trust pillar so posture can be
        # aggregated per pillar without joining the control catalog. An
        # adapter that states its own pillar keeps it; the node's default
        # only fills the gap, because pillar belongs to the control rather
        # than to whichever node happened to evaluate it.
        entry.setdefault("zt_pillar", default_pillar(claw))
        prepared.append(entry)
    return prepared


async def run_claw_scan(
    db: AsyncSession,
    *,
    claw: str,
    provider_config: list[dict[str, Any]],
    demo_findings: list[dict[str, Any]],
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """
    Execute a Claw scan across its configured providers.

    ``provider_config`` entries may carry an ``adapter`` exposing an async
    ``get_findings(credentials=...)``.  Entries without one are treated as
    connector-aware but not yet adapter-backed, which is reported honestly
    rather than silently returning nothing.
    """
    if not tenant_id:
        logger.warning("Blocked %s scan because no tenant context was supplied", claw)
        return {
            "status": "blocked",
            "mode": "blocked",
            "findings_created": 0,
            "findings_updated": 0,
            "critical": 0,
            "high": 0,
            "providers": {},
            "message": "Scan requires an authenticated tenant context.",
        }

    live_findings: list[dict[str, Any]] = []
    provider_results: dict[str, Any] = {}
    configured_without_adapter: list[str] = []

    for cfg in provider_config:
        connector_type = cfg.get("connector_types") or cfg.get("connector_type")
        if not connector_type:
            continue
        provider_name = cfg.get("provider") or claw
        creds = await resolve_credentials(db, connector_type, tenant_id=tenant_id)
        if not creds:
            provider_results[provider_name] = {"status": "not_configured"}
            continue

        adapter = resolve_adapter(cfg)
        if adapter is None:
            configured_without_adapter.append(provider_name)
            provider_results[provider_name] = {"status": "no_adapter"}
            continue

        primary = connector_type[0] if isinstance(connector_type, list) else connector_type
        try:
            raw = await fetch_via_adapter(adapter, creds)
        except Exception as exc:
            logger.warning(
                "%s: %s connector call failed (%s)",
                claw,
                provider_name,
                type(exc).__name__,
            )
            provider_results[provider_name] = {
                "status": "error",
                "error": type(exc).__name__,
            }
            continue

        prepared = _prepare(
            raw, claw=claw, provider=provider_name, origin="live", connector=primary
        )
        live_findings.extend(prepared)
        provider_results[provider_name] = {
            "status": "success",
            "findings": len(prepared),
        }

    if live_findings:
        summary = await ingest_findings(db, claw, live_findings, tenant_id=tenant_id)
        mode = "live"
    elif settings.REQUIRE_LIVE_DATA:
        # Production data policy: nothing authenticated returned anything, and
        # demonstration findings are not permitted to stand in for a real
        # estate. Report the empty result honestly.
        summary = {"created": 0, "updated": 0, "critical": 0, "high": 0}
        mode = "empty"
    else:
        # No connector produced results.  Demonstration findings are still
        # ingested — clearly labelled — because an empty module reads as a
        # broken product, whereas labelled demo data explains itself.
        prepared = _prepare(demo_findings, claw=claw, provider=None, origin="simulated")
        summary = await ingest_findings(db, claw, prepared, tenant_id=tenant_id)
        mode = "simulated"

    response: dict[str, Any] = {
        "status": "completed",
        "mode": mode,
        "findings_created": summary["created"],
        "findings_updated": summary["updated"],
        "critical": summary["critical"],
        "high": summary["high"],
        "providers": provider_results,
        "data_source": "live_connector" if mode == "live" else (
            "seeded_fallback" if mode == "simulated" else "no_data_source"
        ),
        "evidence_status": "live" if mode == "live" else (
            "demo" if mode == "simulated" else "unavailable"
        ),
    }
    if mode == "simulated" and configured_without_adapter:
        response["message"] = (
            "Connector configured, but no live adapter is available yet for: "
            + ", ".join(sorted(configured_without_adapter))
            + ". No environment findings were created."
        )
    elif mode == "empty":
        configured = [n for n, r in provider_results.items() if r.get("status") != "not_configured"]
        response["message"] = (
            "No authenticated connector returned findings for: "
            + ", ".join(sorted(configured))
            + "."
        ) if configured else (
            "No connector is configured for this Capability Node. Connect and verify "
            "a provider before running an environment scan."
        )
    return response
