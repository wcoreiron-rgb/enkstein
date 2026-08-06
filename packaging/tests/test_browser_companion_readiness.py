"""Readiness guarantees for the Browser Companion.

The symptom these pin down is a signed-in, still-open provider tab being
reported as disconnected. Two independent causes were found:

1. The staleness window was shorter than the browser's alarm floor, so a
   suspended MV3 service worker could not possibly check in before expiry.
2. The extension stopped checking in entirely while a turn was in flight, so
   readiness rested on progress events alone and a long silent generation
   looked like a dead session.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "packaging" / "macos" / "MarcellusBrainBridge.swift"
BACKGROUND = ROOT / "browser-extension" / "background.js"

# Chromium enforces a 30s floor on chrome.alarms periods; Edge and older
# builds clamp to 60s, and backgrounded tab timers are throttled similarly.
SLOWEST_ALARM_FLOOR_SECONDS = 60


@pytest.fixture(scope="module")
def bridge() -> str:
    return BRIDGE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def background() -> str:
    return BACKGROUND.read_text(encoding="utf-8")


def _code_only(text: str) -> str:
    """Drops comments so an assertion cannot be satisfied by prose."""
    return "\n".join(
        line
        for line in text.splitlines()
        if not line.strip().startswith(("//", "*", "/*"))
    )


def test_staleness_window_clears_the_slowest_alarm_floor(bridge: str) -> None:
    match = re.search(
        r"connectionStalenessSeconds:\s*TimeInterval\s*=\s*([\d.]+)", bridge
    )
    assert match, "connectionStalenessSeconds is no longer declared as expected"
    window = float(match.group(1))
    # Needs headroom over the floor itself for scheduling jitter and
    # service-worker cold start, not merely to exceed it.
    assert window > SLOWEST_ALARM_FLOOR_SECONDS * 2, (
        f"a {window}s staleness window expires between alarm ticks on a "
        f"{SLOWEST_ALARM_FLOOR_SECONDS}s floor"
    )


def test_alarm_period_stays_under_the_staleness_window(background: str) -> None:
    match = re.search(r"periodInMinutes:\s*([\d.]+)", background)
    assert match, "poll alarm period is no longer declared as expected"
    period = float(match.group(1)) * 60
    staleness = float(
        re.search(r"connectionStalenessSeconds:\s*TimeInterval\s*=\s*([\d.]+)", BRIDGE.read_text(encoding="utf-8")).group(1)
    )
    assert period < staleness, "the alarm cannot fire before readiness expires"


def test_companion_checks_in_while_a_turn_is_active(background: str) -> None:
    code = _code_only(background)
    poll_start = code.index("async function poll()")
    poll_body = code[poll_start:poll_start + 3000]
    assert "hasActive" in poll_body
    active_branch = poll_body[poll_body.index("if (hasActive)"):]
    assert "/v1/browser/poll" in active_branch[:800], (
        "readiness is not refreshed while a turn is in flight"
    )


def test_keepalive_does_not_lease_or_rewind(bridge: str, background: str) -> None:
    assert "keepalive: true" in _code_only(background)
    code = _code_only(bridge)
    assert "keepaliveOnly" in code
    # The early return must come before any leasing or state mutation.
    guard = code.index("if keepaliveOnly")
    requested = code.index("if let requestedTaskID")
    assert guard < requested, "keepalive falls through into the re-lease path"


def test_keepalive_still_refreshes_last_seen(bridge: str) -> None:
    code = _code_only(bridge)
    body = code[code.index("func poll("):]
    guard = body.index("if keepaliveOnly")
    assert "lastSeen = Date()" in body[:guard], (
        "keepalive returns before recording the check-in, so it does nothing"
    )


def test_keepalive_still_delivers_cancel_signals(bridge: str) -> None:
    code = _code_only(bridge)
    body = code[code.index("func poll("):]
    guard_line = body[body.index("if keepaliveOnly"):].splitlines()[0]
    assert "cancelSignal" in guard_line, (
        "a busy Companion would never receive a cancel signal"
    )
