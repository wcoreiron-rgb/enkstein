"""Per-identity rate limiting for expensive AI endpoints (OWASP LLM04).

A governed turn can fan out to several Brains, run a local author pass, and
write files, so an unbounded caller is a model-denial-of-service and a cost
problem at the same time. Auth and model-routing already carry limits; this
applies the same shape to the Cowork/Chat turn surface.

The bucket is keyed on the authenticated identity rather than the client IP:
every desktop request arrives from the same loopback address, so an IP key
would let one runaway conversation throttle the whole tenant.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from fastapi import HTTPException, status

from app.core.config import settings

# Generous for a human operator driving a desktop app, while still bounding an
# automated loop to a predictable ceiling. Deployment-tunable via settings.
TURN_WINDOW_SECONDS = int(settings.AI_RATE_LIMIT_WINDOW_SECONDS)
TURN_MAX_REQUESTS = int(settings.AI_RATE_LIMIT_MAX_REQUESTS)

_store: dict[str, list[float]] = defaultdict(list)
_lock = threading.Lock()


def enforce_ai_rate_limit(
    identity: str,
    *,
    window_seconds: int | None = None,
    max_requests: int | None = None,
) -> None:
    """Raise 429 when ``identity`` exceeds the AI turn budget for the window."""
    # Read the module constants at call time rather than binding them as
    # default arguments, so deployment tuning (and tests) take effect.
    window_seconds = TURN_WINDOW_SECONDS if window_seconds is None else window_seconds
    max_requests = TURN_MAX_REQUESTS if max_requests is None else max_requests
    key = identity or "unknown"
    now = time.monotonic()
    cutoff = now - window_seconds
    with _lock:
        recent = [stamp for stamp in _store[key] if stamp > cutoff]
        if len(recent) >= max_requests:
            _store[key] = recent
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many AI requests — please retry shortly.",
                headers={"Retry-After": str(window_seconds)},
            )
        recent.append(now)
        _store[key] = recent


def reset_ai_rate_limits() -> None:
    """Clear all buckets. Used by tests; not exposed through any route."""
    with _lock:
        _store.clear()
