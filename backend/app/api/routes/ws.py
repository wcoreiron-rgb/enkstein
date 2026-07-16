"""
Enkstein — WebSocket API Route

GET /ws   — upgrade to WebSocket; receives real-time platform events.

Clients receive JSON events:
  { "type": "...", "timestamp": "...", "data": { ... } }

The server sends a "ping" every 30 s to keep the connection alive through
proxies and load balancers.  Clients may respond with any message to confirm
they are alive (the server ignores the payload).

Connection lifecycle:
  1. Client connects → server sends "connected" welcome event
  2. Server pings every 30 s
  3. Client disconnects / network error → connection pruned silently

Authentication:
  In DEBUG mode all connections are allowed.
  In production a valid JWT is passed as the second WebSocket subprotocol,
  after the fixed ``marcellus-auth`` protocol marker. This keeps credentials
  out of request URLs and access logs.
"""
import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.config import settings
from app.core.security import JWTError, decode_access_token
from app.services.ws_manager import ws_manager

logger = logging.getLogger("regentclaw.ws_route")
router = APIRouter(tags=["WebSocket"])

PING_INTERVAL = 30  # seconds
AUTH_SUBPROTOCOL = "marcellus-auth"


def _subprotocol_token(ws: WebSocket) -> tuple[str | None, bool]:
    offered = [
        value.strip()
        for value in ws.headers.get("sec-websocket-protocol", "").split(",")
        if value.strip()
    ]
    if len(offered) >= 2 and offered[0] == AUTH_SUBPROTOCOL:
        return offered[1], True
    return None, False


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    # ── Auth check ────────────────────────────────────────────────────────────
    token, uses_auth_subprotocol = _subprotocol_token(ws)
    if not settings.DEBUG:
        if not token:
            await ws.close(code=4401, reason="Authentication required")
            return
        try:
            payload = decode_access_token(token)
            sub = payload.get("sub", "")
            if not sub:
                raise ValueError("empty sub in token")
        except (JWTError, ValueError) as exc:
            logger.debug("WS auth failed: %s", exc)
            await ws.close(code=4401, reason="Invalid or expired token")
            return

    await ws_manager.connect(
        ws,
        subprotocol=AUTH_SUBPROTOCOL if uses_auth_subprotocol else None,
    )

    # Send welcome so the client knows the connection is live
    await ws.send_json({
        "type":      "connected",
        "timestamp": _now(),
        "data":      {
            "message":     "Enkstein live feed connected",
            "connections": ws_manager.connection_count,
        },
    })

    # Background ping task — keeps the socket alive through proxies
    async def _ping() -> None:
        while True:
            await asyncio.sleep(PING_INTERVAL)
            try:
                await ws.send_json({"type": "ping", "timestamp": _now(), "data": {}})
            except Exception:
                return

    ping_task = asyncio.create_task(_ping())

    try:
        while True:
            # Wait for any client message (pong, keepalive, etc.)
            # We don't act on it, but reading prevents the receive buffer filling up.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WS receive error: %s", exc)
    finally:
        ping_task.cancel()
        await ws_manager.disconnect(ws)


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
