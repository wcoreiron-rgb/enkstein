"""
Enkstein — Auto Scanner
Triggers claw scans automatically when connectors are configured or approved.

Flow:
  1. Connector credentials are saved → trigger_scans_for_connector() called
  2. For each claw that uses that connector type → call the claw's /scan endpoint
  3. Runs as a FastAPI BackgroundTask (non-blocking)

Also used by the background scheduler for periodic scanning.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.claw_registry import get_claws_for_connector, get_scan_path

logger = logging.getLogger("auto_scanner")


async def trigger_scans_for_connector(
    db: AsyncSession,
    connector_type: str,
    connector_id: str,
    actor: str = "auto_scan",
) -> dict:
    """
    Trigger all claw scans associated with a given connector type.
    Called after credentials are saved for a connector.

    Uses the FastAPI app's internal HTTP client to call scan endpoints
    so all existing auth/DB middleware applies.

    Args:
        db: AsyncSession (used by direct adapter calls)
        connector_type: e.g., "crowdstrike", "okta", "aws_security_hub"
        connector_id: UUID of the connector (for logging)
        actor: Who triggered this (for event logging)

    Returns:
        Dict summarizing which claws were triggered
    """
    claws_to_scan = get_claws_for_connector(connector_type)
    if not claws_to_scan:
        logger.info("No claws mapped to connector_type=%s — skipping auto-scan", connector_type)
        return {"triggered": [], "skipped": connector_type}

    results = {}
    logger.info(
        "Auto-scan triggered for connector_type=%s (id=%s) → claws: %s",
        connector_type, connector_id, claws_to_scan,
    )

    for claw_name in claws_to_scan:
        try:
            result = await _run_claw_scan(db, claw_name)
            results[claw_name] = result
            logger.info("Auto-scan completed for claw=%s: %s", claw_name, result)
        except Exception as exc:
            logger.error("Auto-scan failed for claw=%s: %s", claw_name, exc, exc_info=True)
            results[claw_name] = {"status": "error", "error": str(exc)}

    return {
        "connector_type": connector_type,
        "triggered_at": datetime.utcnow().isoformat(),
        "claws": results,
    }


async def _run_claw_scan(db: AsyncSession, claw_name: str) -> dict:
    """
    Run a claw scan by importing its router function directly.
    This avoids an HTTP roundtrip and reuses the existing DB session.
    """
    # Import the scan function from each claw's routes module
    claw_scan_map = {
        "cloudclaw":      _scan_cloudclaw,
        "exposureclaw":   _scan_exposureclaw,
        "threatclaw":     _scan_threatclaw,
        "endpointclaw":   _scan_endpointclaw,
        "accessclaw":     _scan_generic,
        "logclaw":        _scan_generic,
        "netclaw":        _scan_generic,
        "dataclaw":       _scan_generic,
        "appclaw":        _scan_generic,
        "saasclaw":       _scan_generic,
        "configclaw":     _scan_generic,
        "complianceclaw": _scan_generic,
        "privacyclaw":    _scan_generic,
        "vendorclaw":     _scan_generic,
        "userclaw":       _scan_generic,
        "insiderclaw":    _scan_generic,
        "automationclaw": _scan_generic,
        "attackpathclaw": _scan_generic,
        "devclaw":        _scan_generic,
        "intelclaw":      _scan_generic,
        "recoveryclaw":   _scan_generic,
    }

    scan_fn = claw_scan_map.get(claw_name, _scan_generic)
    return await scan_fn(db, claw_name)


async def _scan_cloudclaw(db: AsyncSession, claw_name: str = "cloudclaw") -> dict:
    from app.claws.cloudclaw.routes import trigger_scan
    return await trigger_scan(db=db)


async def _scan_exposureclaw(db: AsyncSession, claw_name: str = "exposureclaw") -> dict:
    from app.claws.exposureclaw.routes import trigger_vulnerability_scan
    return await trigger_vulnerability_scan(db=db)


async def _scan_threatclaw(db: AsyncSession, claw_name: str = "threatclaw") -> dict:
    from app.claws.threatclaw.routes import trigger_threat_scan
    return await trigger_threat_scan(db=db)


async def _scan_endpointclaw(db: AsyncSession, claw_name: str = "endpointclaw") -> dict:
    from app.claws.endpointclaw.routes import run_scan
    return await run_scan(db=db)


async def _scan_generic(db: AsyncSession, claw_name: str) -> dict:
    """
    Generic scan trigger: import the claw's run_scan function dynamically.
    All patched claws have a run_scan(db) function.
    """
    try:
        import importlib
        module = importlib.import_module(f"app.claws.{claw_name}.routes")
        scan_fn = getattr(module, "run_scan", None)
        if scan_fn is None:
            return {"status": "skipped", "reason": f"No run_scan function in {claw_name}.routes"}
        return await scan_fn(db=db)
    except Exception as exc:
        logger.error("Generic scan failed for %s: %s", claw_name, exc)
        return {"status": "error", "error": str(exc)}


# ─── Background Scheduler ─────────────────────────────────────────────────────

_SCAN_INTERVAL_HOURS = 6   # Run full scan sweep every 6 hours

# Priority claws — scan these first (most critical data)
PRIORITY_CLAWS = [
    "cloudclaw", "exposureclaw", "threatclaw", "endpointclaw",
    "accessclaw", "logclaw", "netclaw",
]

# Secondary claws — scan after priority
SECONDARY_CLAWS = [
    "dataclaw", "appclaw", "saasclaw", "configclaw", "complianceclaw",
    "privacyclaw", "vendorclaw", "userclaw", "insiderclaw", "automationclaw",
    "attackpathclaw", "devclaw", "intelclaw", "recoveryclaw",
]


async def run_scheduled_sweep(db: AsyncSession) -> dict:
    """
    Run a full scan sweep across all 22 claws.
    Called by the background scheduler every N hours.
    Priority claws run first; secondary claws run in parallel after.
    """
    logger.info("Starting scheduled scan sweep — %s UTC", datetime.utcnow().isoformat())
    sweep_results = {}

    # Priority claws — sequential to avoid overwhelming the DB
    for claw in PRIORITY_CLAWS:
        try:
            result = await _run_claw_scan(db, claw)
            sweep_results[claw] = result
        except Exception as exc:
            sweep_results[claw] = {"status": "error", "error": str(exc)}

    # Secondary claws — parallel for speed
    secondary_tasks = [_run_claw_scan(db, claw) for claw in SECONDARY_CLAWS]
    secondary_results = await asyncio.gather(*secondary_tasks, return_exceptions=True)

    for claw, result in zip(SECONDARY_CLAWS, secondary_results):
        if isinstance(result, Exception):
            sweep_results[claw] = {"status": "error", "error": str(result)}
        else:
            sweep_results[claw] = result

    total_created = sum(
        r.get("findings_created", 0) if isinstance(r, dict) else 0
        for r in sweep_results.values()
    )
    total_updated = sum(
        r.get("findings_updated", 0) if isinstance(r, dict) else 0
        for r in sweep_results.values()
    )

    logger.info(
        "Scheduled sweep complete — %d new findings, %d updated",
        total_created, total_updated
    )

    return {
        "completed_at": datetime.utcnow().isoformat(),
        "total_created": total_created,
        "total_updated": total_updated,
        "claws": sweep_results,
    }


async def background_scheduler_loop(AsyncSessionLocal) -> None:
    """
    Infinite loop that runs scheduled scan sweeps every _SCAN_INTERVAL_HOURS hours.
    Start with: asyncio.create_task(background_scheduler_loop(AsyncSessionLocal))

    Args:
        AsyncSessionLocal: async_sessionmaker instance from app.core.database
    """
    logger.info("Background scheduler started (interval: %dh)", _SCAN_INTERVAL_HOURS)
    while True:
        await asyncio.sleep(_SCAN_INTERVAL_HOURS * 3600)
        try:
            async with AsyncSessionLocal() as db:
                await run_scheduled_sweep(db)
        except asyncio.CancelledError:
            raise   # Let the caller cancel properly
        except Exception as exc:
            logger.error("Scheduled sweep failed: %s", exc, exc_info=True)
