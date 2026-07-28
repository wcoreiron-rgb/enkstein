"""Data-origin tagging for Claw provider output.

A beta tenant usually has one or two live connectors configured while the rest
of the platform still returns realistic demonstration findings. Without an
explicit marker an operator cannot tell which findings describe their own
estate, which is the difference between a useful security console and a demo.

Providers call :func:`live` on the authenticated path and :func:`simulated` on
the fallback path. The finding pipeline constrains whatever arrives to a known
vocabulary and defaults to ``unknown`` when an adapter says nothing, so an
un-tagged adapter can never be presented as verified customer data.
"""

from __future__ import annotations

from typing import Any, Iterable

LIVE = "live"
SIMULATED = "simulated"


def tag(
    findings: Iterable[dict[str, Any]],
    *,
    provider: str,
    origin: str,
    connector: str | None = None,
) -> list[dict[str, Any]]:
    """Stamp provider name and data origin onto each finding dict."""
    stamped: list[dict[str, Any]] = []
    for finding in findings:
        item = {**finding, "provider": provider, "data_origin": origin}
        if connector or origin == LIVE:
            item["source_connector"] = connector or provider
        stamped.append(item)
    return stamped


def live(
    findings: Iterable[dict[str, Any]], *, provider: str, connector: str | None = None
) -> list[dict[str, Any]]:
    """Findings returned by an authenticated provider API call."""
    return tag(findings, provider=provider, origin=LIVE, connector=connector)


def simulated(findings: Iterable[dict[str, Any]], *, provider: str) -> list[dict[str, Any]]:
    """Locally generated demonstration findings."""
    return tag(findings, provider=provider, origin=SIMULATED)
