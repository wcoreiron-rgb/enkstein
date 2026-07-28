"""
Third-party and supply-chain risk adapters.

Vendor Risk was the one Capability Node with no live path at all: every
provider it referenced — SecurityScorecard, Bitsight, UpGuard — was absent from
the registry, so the node could only ever show demonstration data no matter
what a tenant configured. These three rating services answer the same question
in different dialects: which of my vendors is weak, and in what way.
"""
from __future__ import annotations

from typing import Any, Optional

from app.claws.rest_adapter import AdapterSpec, Endpoint, normalize_severity


def _grade_severity(grade: Any) -> str:
    """Map a letter security rating onto the platform severity vocabulary."""
    letter = str(grade or "").strip().upper()[:1]
    return {"F": "critical", "D": "high", "C": "medium", "B": "low", "A": "info"}.get(
        letter, "medium"
    )


def _score_severity(score: Any, low_is_bad: bool = True) -> str:
    """Map a 0-100 rating onto severity. Higher is safer for these vendors."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "medium"
    if not low_is_bad:
        value = 100.0 - value
    if value < 40:
        return "critical"
    if value < 60:
        return "high"
    if value < 80:
        return "medium"
    return "low"


# SecurityScorecard --------------------------------------------------------

def _parse_scorecard(row: dict, _creds: dict) -> Optional[dict]:
    domain = row.get("domain")
    if not domain:
        return None
    grade = row.get("grade") or row.get("grade_letter")
    score = row.get("score")
    name = row.get("name") or domain
    return {
        "title": f"Vendor rating {grade or score}: {name}",
        "description": (
            f"SecurityScorecard rates {name} ({domain}) at {grade or 'n/a'} "
            f"with a score of {score if score is not None else 'n/a'}."
        )[:600],
        "category": "vendor_risk",
        "severity": normalize_severity(_grade_severity(grade) if grade else _score_severity(score)),
        "resource_id": str(domain),
        "resource_type": "vendor",
        "resource_name": str(name)[:200],
        "external_id": f"SSC-{domain}"[:120],
        "remediation": "Review the vendor's issue breakdown and raise the findings with their security contact.",
    }


SECURITY_SCORECARD = AdapterSpec(
    provider="security_scorecard",
    connector_type="security_scorecard",
    label="SecurityScorecard",
    claw="vendorclaw",
    auth="header",
    auth_name="Authorization",
    auth_prefix="Token",
    token_field="api_key",
    required_fields=("api_key",),
    base_url="https://api.securityscorecard.io",
    endpoints=(
        Endpoint(path="/portfolios", items_key="entries", optional=True),
        Endpoint(path="/companies", items_key="entries", parse=_parse_scorecard),
    ),
)


# Bitsight -----------------------------------------------------------------

def _parse_bitsight(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("name")
    if not name:
        return None
    rating = row.get("rating")
    # Bitsight ratings run 250-900; below 640 is commonly treated as advanced
    # risk, below 740 as intermediate.
    try:
        value = float(rating)
        severity = "critical" if value < 640 else "high" if value < 740 else "medium" if value < 790 else "low"
    except (TypeError, ValueError):
        severity = "medium"
    return {
        "title": f"Bitsight rating {rating or 'n/a'}: {name}",
        "description": (
            f"Bitsight rates {name} at {rating if rating is not None else 'n/a'}."
        )[:600],
        "category": "vendor_risk",
        "severity": severity,
        "resource_id": str(row.get("guid") or name),
        "resource_type": "vendor",
        "resource_name": str(name)[:200],
        "external_id": f"BITSIGHT-{row.get('guid') or name}"[:120],
        "remediation": "Request the vendor's remediation plan for the findings behind this rating.",
    }


BITSIGHT = AdapterSpec(
    provider="bitsight",
    connector_type="bitsight",
    label="Bitsight",
    claw="vendorclaw",
    # Bitsight authenticates with the API token as the HTTP basic username.
    auth="basic",
    username_field="api_key",
    password_field="_bitsight_empty_password",
    allow_empty_password=True,
    required_fields=("api_key",),
    base_url="https://api.bitsighttech.com",
    endpoints=(
        Endpoint(path="/ratings/v2/companies", items_key="companies", parse=_parse_bitsight),
    ),
)


# UpGuard ------------------------------------------------------------------

def _parse_upguard(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("name") or row.get("primary_hostname")
    if not name:
        return None
    score = row.get("score")
    return {
        "title": f"UpGuard score {score if score is not None else 'n/a'}: {name}",
        "description": f"UpGuard scores {name} at {score if score is not None else 'n/a'} out of 950."[:600],
        "category": "vendor_risk",
        # UpGuard scores run to 950, so normalise before banding.
        "severity": _score_severity((float(score) / 9.5) if _is_number(score) else None),
        "resource_id": str(row.get("id") or name),
        "resource_type": "vendor",
        "resource_name": str(name)[:200],
        "external_id": f"UPGUARD-{row.get('id') or name}"[:120],
        "remediation": "Review the vendor's risk breakdown in UpGuard and track remediation with their team.",
    }


def _is_number(value: Any) -> bool:
    try:
        float(value)
    except (TypeError, ValueError):
        return False
    return True


UPGUARD = AdapterSpec(
    provider="upguard",
    connector_type="upguard",
    label="UpGuard",
    claw="vendorclaw",
    auth="header",
    auth_name="Authorization",
    token_field="api_key",
    required_fields=("api_key",),
    base_url="https://cyber-risk.upguard.com/api/public",
    endpoints=(
        Endpoint(path="/vendors", items_key="vendors", parse=_parse_upguard),
    ),
)


# Shodan -------------------------------------------------------------------

def _parse_shodan(row: dict, _creds: dict) -> Optional[dict]:
    ip = row.get("ip_str") or row.get("ip")
    if not ip:
        return None
    port = row.get("port")
    vulns = row.get("vulns") or {}
    product = row.get("product") or "service"
    hostnames = row.get("hostnames") or []
    detail = (
        f"Known vulnerabilities: {', '.join(sorted(vulns)[:5])}."
        if vulns
        else "No known CVEs reported for this banner."
    )
    return {
        "title": f"Internet-exposed {product} on {ip}:{port}"[:200],
        "description": f"Shodan observed {product} reachable from the internet. {detail}"[:600],
        "category": "exposure",
        "severity": "critical" if vulns else "medium",
        "resource_id": f"{ip}:{port}",
        "resource_type": "host",
        "resource_name": str(hostnames[0] if hostnames else ip)[:200],
        "external_id": f"SHODAN-{ip}-{port}"[:120],
        "remediation": "Restrict the listener to trusted networks or place it behind a gateway.",
        "actively_exploited": bool(vulns),
    }


SHODAN = AdapterSpec(
    provider="shodan",
    connector_type="shodan",
    label="Shodan",
    claw="exposureclaw",
    auth="query",
    auth_name="key",
    token_field="api_key",
    # The tenant supplies the scope, so Enkstein never enumerates assets the
    # operator did not ask about.
    required_fields=("api_key", "query"),
    base_url="https://api.shodan.io",
    endpoints=(
        Endpoint(
            path="/shodan/host/search",
            params={"query": "{query}"},
            items_key="matches",
            parse=_parse_shodan,
        ),
    ),
)


SPECS = (SECURITY_SCORECARD, BITSIGHT, UPGUARD, SHODAN)
