"""
Community and public-feed adapters.

Several sources a security team relies on daily are free and unauthenticated:
CISA's Known Exploited Vulnerabilities catalog is the clearest example: no
credential, live the moment the connector is enabled. Threat Intelligence
referenced it but had no adapter, so a node that could have been returning
genuinely live data was showing demonstration findings instead.

ThreatFox and MISP are community sources that do need a key — abuse.ch began
requiring an Auth-Key header, and MISP is self-hosted per tenant.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from app.claws.rest_adapter import AdapterSpec, Endpoint, normalize_severity


def _recent(value: Any, days: int) -> bool:
    """True when an ISO-ish date falls inside the window."""
    text = str(value or "").strip()
    if not text:
        return False
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text[: len(fmt) + 2].strip(), fmt)
        except ValueError:
            continue
        parsed = parsed.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - parsed).days <= days
    return False


# CISA Known Exploited Vulnerabilities ----------------------------------------

def _parse_kev(row: dict, _creds: dict) -> Optional[dict]:
    cve = row.get("cveID")
    if not cve:
        return None
    vendor = row.get("vendorProject") or "unknown vendor"
    product = row.get("product") or "unknown product"
    # Everything in this catalog is confirmed exploited in the wild, so the
    # severity floor is high; recency separates urgent from long-known.
    severity = "critical" if _recent(row.get("dateAdded"), 90) else "high"
    return {
        "title": f"CISA KEV: {cve} - {vendor} {product}",
        "description": (row.get("shortDescription") or "")[:600],
        "category": "vulnerability",
        "severity": severity,
        "resource_id": cve,
        "resource_type": "vulnerability",
        "resource_name": f"{vendor} {product}"[:200],
        "external_id": f"KEV-{cve}"[:120],
        "remediation": (
            row.get("requiredAction") or "Apply the vendor update or discontinue use."
        )[:600],
        "actively_exploited": True,
    }


CISA_KEV = AdapterSpec(
    provider="cisa_kev",
    connector_type="cisa_kev",
    label="CISA Known Exploited Vulnerabilities",
    claw="intelclaw",
    auth="none",
    base_url="https://www.cisa.gov",
    endpoints=(
        Endpoint(
            path="/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            items_key="vulnerabilities",
            parse=_parse_kev,
            limit=150,
        ),
    ),
)


# abuse.ch ThreatFox ----------------------------------------------------------

def _parse_threatfox(row: dict, _creds: dict) -> Optional[dict]:
    ioc = row.get("ioc")
    if not ioc:
        return None
    malware = row.get("malware_printable") or row.get("malware") or "unknown malware"
    try:
        confidence = float(row.get("confidence_level"))
    except (TypeError, ValueError):
        confidence = 50.0
    return {
        "title": f"ThreatFox indicator: {malware}"[:200],
        "description": (
            f"{row.get('ioc_type_desc') or row.get('ioc_type') or 'Indicator'} "
            f"{ioc} is associated with {malware}."
        )[:600],
        "category": "threat_intel",
        "severity": normalize_severity("high" if confidence >= 75 else "medium"),
        "risk_score": confidence,
        "resource_id": str(row.get("id") or ioc),
        "resource_type": "indicator",
        "resource_name": str(ioc)[:200],
        "external_id": f"THREATFOX-{row.get('id') or ioc}"[:120],
        "remediation": "Block the indicator and hunt for prior contact in telemetry.",
        "actively_exploited": True,
    }


THREATFOX = AdapterSpec(
    provider="threatfox",
    connector_type="threatfox",
    label="abuse.ch ThreatFox",
    claw="intelclaw",
    # abuse.ch now rejects anonymous queries with 401; an Auth-Key from a free
    # abuse.ch account is required.
    auth="header",
    auth_name="Auth-Key",
    token_field="api_key",
    required_fields=("api_key",),
    base_url="https://threatfox-api.abuse.ch",
    endpoints=(
        Endpoint(
            path="/api/v1/",
            method="POST",
            json_body={"query": "get_iocs", "days": 1},
            items_key="data",
            parse=_parse_threatfox,
            limit=100,
        ),
    ),
)


# MISP (self-hosted) ----------------------------------------------------------

def _parse_misp(row: dict, _creds: dict) -> Optional[dict]:
    event = row.get("Event") or row
    info = event.get("info")
    if not info:
        return None
    # MISP threat levels run 1 (high) through 4 (undefined).
    level = str(event.get("threat_level_id") or "3")
    severity = {"1": "critical", "2": "high", "3": "medium"}.get(level, "low")
    return {
        "title": f"MISP event: {info}"[:200],
        "description": str(info)[:600],
        "category": "threat_intel",
        "severity": severity,
        "resource_id": str(event.get("uuid") or event.get("id") or info),
        "resource_type": "threat_event",
        "resource_name": str(info)[:200],
        "external_id": f"MISP-{event.get('uuid') or event.get('id')}"[:120],
        "remediation": "Review the event's attributes and sweep telemetry for matches.",
    }


MISP = AdapterSpec(
    provider="misp",
    connector_type="misp",
    label="MISP",
    claw="intelclaw",
    auth="header",
    auth_name="Authorization",
    base_url_field="base_url",
    token_field="api_key",
    required_fields=("base_url", "api_key"),
    extra_headers={"Content-Type": "application/json"},
    endpoints=(
        Endpoint(
            path="/events/restSearch",
            method="POST",
            json_body={"returnFormat": "json", "limit": 100, "published": True},
            items_key="response",
            parse=_parse_misp,
        ),
    ),
)


SPECS = (CISA_KEV, THREATFOX, MISP)
