"""
Enkstein — WebSocket Connection Manager

Singleton that tracks all active browser connections and broadcasts
structured events to them.  Import `ws_manager` anywhere in the backend
and call `await ws_manager.broadcast(...)` — it will fan-out to every
connected client, silently dropping any dead connections.

Event envelope:
  {
    "type":      "finding.created" | "agent.run_completed" | "workflow.step" |
                 "workflow.completed" | "dashboard.refresh" | "ping",
    "timestamp": "<ISO-8601>",
    "data":      { ... event-specific payload }
  }
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("regentclaw.ws")


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def connect(self, ws: WebSocket, subprotocol: str | None = None) -> None:
        await ws.accept(subprotocol=subprotocol)
        async with self._lock:
            self._connections.append(ws)
        logger.info("WS client connected — total=%d", len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            try:
                self._connections.remove(ws)
            except ValueError:
                pass
        logger.info("WS client disconnected — total=%d", len(self._connections))

    # ── Broadcasting ─────────────────────────────────────────────────────────

    async def broadcast(self, event_type: str, data: dict[str, Any] | None = None) -> None:
        """Fan-out a JSON event to all connected clients."""
        if not self._connections:
            return

        message = {
            "type":      event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data":      data or {},
        }

        dead: list[WebSocket] = []
        async with self._lock:
            snapshot = list(self._connections)

        for ws in snapshot:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    try:
                        self._connections.remove(ws)
                    except ValueError:
                        pass
            logger.debug("Pruned %d dead WS connections", len(dead))

    @property
    def connection_count(self) -> int:
        return len(self._connections)


# ── Module-level singleton ────────────────────────────────────────────────────
ws_manager = ConnectionManager()


# ── Typed broadcast helpers ───────────────────────────────────────────────────

async def broadcast_finding(
    claw: str,
    severity: str,
    title: str,
    risk_score: float | None = None,
    is_new: bool = True,
) -> None:
    await ws_manager.broadcast("finding.created" if is_new else "finding.updated", {
        "claw":       claw,
        "severity":   severity,
        "title":      title,
        "risk_score": risk_score,
    })


async def broadcast_agent_run(
    agent_name: str,
    run_id: str,
    status: str,
    findings_count: int = 0,
    claw: str = "",
) -> None:
    await ws_manager.broadcast("agent.run_completed", {
        "agent_name":     agent_name,
        "run_id":         run_id,
        "status":         status,
        "findings_count": findings_count,
        "claw":           claw,
    })


async def broadcast_workflow_step(
    workflow_name: str,
    run_id: str,
    step_name: str,
    step_index: int,
    status: str,
) -> None:
    await ws_manager.broadcast("workflow.step", {
        "workflow_name": workflow_name,
        "run_id":        run_id,
        "step_name":     step_name,
        "step_index":    step_index,
        "status":        status,
    })


async def broadcast_workflow_complete(
    workflow_name: str,
    run_id: str,
    status: str,
    steps_run: int = 0,
) -> None:
    await ws_manager.broadcast("workflow.completed", {
        "workflow_name": workflow_name,
        "run_id":        run_id,
        "status":        status,
        "steps_run":     steps_run,
    })


async def broadcast_dashboard_refresh() -> None:
    """Generic signal telling the dashboard to re-fetch its stats."""
    await ws_manager.broadcast("dashboard.refresh", {})
