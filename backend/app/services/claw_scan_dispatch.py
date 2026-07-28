"""
Resolve a Capability Node's real scan entrypoint by name.

Agent runs used to return a hardcoded scenario per node: the AI Security agent
always "found" one prompt injection and one DLP violation whether or not any
connector existed. The tally, the Events feed, and the approval queue all
described work that had never happened.

Every node already exposes a governed ``POST /scan`` that runs its configured
provider adapters through the shared scan path. This locates that function so a
run executes the same code the console does, instead of a parallel fiction.
"""
from __future__ import annotations

import importlib
import inspect
import logging
from typing import Any, Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("claw.dispatch")

_CACHE: dict[str, Optional[Callable]] = {}


def _find_scan_callable(module: Any) -> Optional[Callable]:
    """Return the coroutine registered as this module's POST /scan route."""
    router = getattr(module, "router", None)
    if router is None:
        return None
    for route in getattr(router, "routes", []):
        # Routers carry their own prefix, so the registered path is
        # "/<node>/scan" rather than a bare "/scan".
        path = getattr(route, "path", "") or ""
        if path.endswith("/scan") and "POST" in (getattr(route, "methods", None) or set()):
            return getattr(route, "endpoint", None)
    return None


def resolve_scan(claw: str) -> Optional[Callable]:
    """Look up the scan entrypoint for a node, or None when it has none."""
    if claw in _CACHE:
        return _CACHE[claw]
    try:
        module = importlib.import_module(f"app.claws.{claw}.routes")
    except ModuleNotFoundError:
        _CACHE[claw] = None
        return None
    scan = _find_scan_callable(module)
    _CACHE[claw] = scan
    return scan


async def run_node_scan(claw: str, db: AsyncSession) -> Optional[dict[str, Any]]:
    """
    Execute a node's real scan.

    Returns the scan response, or None when the node has no scan entrypoint.
    Provider failures are already reported inside the response rather than
    raised, so the caller can distinguish "nothing configured" from "a
    connector errored" without either becoming a fabricated success.
    """
    scan = resolve_scan(claw)
    if scan is None:
        return None
    kwargs: dict[str, Any] = {}
    parameters = inspect.signature(scan).parameters
    if "db" in parameters:
        kwargs["db"] = db
    return await scan(**kwargs)
