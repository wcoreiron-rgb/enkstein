"""
Vulnerability and exposure management adapters.

Tenable, Qualys, Rapid7, Wiz, Snyk, and Checkmarx all answer the same question
in different dialects: what is exposed, how badly, and on which asset.  Each is
described declaratively and executed by the shared REST adapter, so the auth,
timeout, SSRF, and provenance behaviour is identical across all of them.
"""
from __future__ import annotations

from typing import Any, Optional

from app.claws.rest_adapter import AdapterSpec, Endpoint, normalize_severity


def _cvss(value: Any) -> Optional[float]:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _severity_from_cvss(score: Optional[float], fallback: Any = None) -> str:
    if score is None:
        return normalize_severity(fallback)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# ── Tenable.io ────────────────────────────────────────────────────────────────

def _parse_tenable(row: dict, _creds: dict) -> Optional[dict]:
    plugin = row.get("plugin") or {}
    asset = row.get("asset") or {}
    name = plugin.get("name")
    if not name:
        return None
    cvss = _cvss(plugin.get("cvss3_base_score") or plugin.get("cvss_base_score"))
    host = asset.get("hostname") or asset.get("ipv4") or "unknown asset"
    return {
        "title": f"Tenable: {name}",
        "description": (plugin.get("description") or "")[:600],
        "category": "vulnerability",
        "severity": _severity_from_cvss(cvss, row.get("severity")),
        "cvss_score": cvss,
        "resource_id": str(asset.get("uuid") or host),
        "resource_type": "host",
        "resource_name": host,
        "external_id": f"TENABLE-{plugin.get('id')}-{asset.get('uuid', '')}"[:120],
        "remediation": (plugin.get("solution") or "Apply the vendor patch or mitigation.")[:600],
        "actively_exploited": bool(plugin.get("has_workaround") is False and (cvss or 0) >= 9.0),
    }


TENABLE = AdapterSpec(
    provider="tenable",
    connector_type="tenable",
    label="Tenable.io",
    claw="exposureclaw",
    auth="header",
    auth_name="X-ApiKeys",
    base_url="https://cloud.tenable.com",
    token_field="_tenable_header",
    required_fields=("access_key", "secret_key"),
    transform=lambda c: {
        "_tenable_header": f"accessKey={c.get('access_key', '')};secretKey={c.get('secret_key', '')}"
    },
    endpoints=(
        Endpoint(
            path="/workbenches/vulnerabilities",
            items_key="vulnerabilities",
            params={"severity": "critical,high", "date_range": "30"},
            parse=_parse_tenable,
        ),
    ),
)


# ── Qualys VMDR ───────────────────────────────────────────────────────────────

def _parse_qualys(row: dict, _creds: dict) -> Optional[dict]:
    title = row.get("TITLE") or row.get("title")
    if not title:
        return None
    cvss = _cvss(row.get("CVSS_BASE") or row.get("cvss_base"))
    return {
        "title": f"Qualys: {title}",
        "description": (row.get("DIAGNOSIS") or row.get("diagnosis") or "")[:600],
        "category": "vulnerability",
        "severity": _severity_from_cvss(cvss, row.get("SEVERITY_LEVEL")),
        "cvss_score": cvss,
        "resource_id": str(row.get("QID") or title)[:120],
        "resource_type": "host",
        "external_id": f"QUALYS-{row.get('QID')}"[:120],
        "remediation": (row.get("SOLUTION") or "Apply the Qualys-recommended remediation.")[:600],
    }


QUALYS = AdapterSpec(
    provider="qualys",
    connector_type="qualys",
    label="Qualys VMDR",
    claw="exposureclaw",
    auth="basic",
    username_field="username",
    password_field="password",
    base_url_field="platform",
    required_fields=("username", "password"),
    extra_headers={"X-Requested-With": "Enkstein"},
    endpoints=(
        Endpoint(
            path="/api/2.0/fo/knowledge_base/vuln/",
            items_key="KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN",
            params={"action": "list", "details": "Basic", "severity_levels": "4-5"},
            parse=_parse_qualys,
            limit=50,
        ),
    ),
)


# ── Rapid7 InsightVM ──────────────────────────────────────────────────────────

def _parse_rapid7(row: dict, _creds: dict) -> Optional[dict]:
    title = row.get("title")
    if not title:
        return None
    cvss = _cvss((row.get("cvss") or {}).get("v3", {}).get("score"))
    return {
        "title": f"Rapid7: {title}",
        "description": (str(row.get("description", {}).get("text", "")) or "")[:600],
        "category": "vulnerability",
        "severity": _severity_from_cvss(cvss, row.get("severity")),
        "cvss_score": cvss,
        "resource_id": str(row.get("id") or title)[:120],
        "resource_type": "asset",
        "external_id": f"RAPID7-{row.get('id')}"[:120],
        "remediation": "Apply the remediation identified in InsightVM for this vulnerability.",
        "actively_exploited": bool((row.get("exploits") or 0)),
    }


RAPID7 = AdapterSpec(
    provider="rapid7",
    connector_type="rapid7",
    label="Rapid7 InsightVM",
    claw="exposureclaw",
    auth="header",
    auth_name="X-Api-Key",
    base_url="https://us.api.insight.rapid7.com",
    token_field="api_key",
    required_fields=("api_key",),
    endpoints=(
        Endpoint(
            path="/vm/v4/integration/vulnerabilities",
            items_key="data",
            params={"size": 50},
            parse=_parse_rapid7,
            limit=50,
        ),
    ),
)


# ── Wiz ───────────────────────────────────────────────────────────────────────

def _parse_wiz(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("name") or row.get("title")
    if not name:
        return None
    entity = row.get("entitySnapshot") or {}
    return {
        "title": f"Wiz: {name}",
        "description": (row.get("description") or "")[:600],
        "category": "cloud_posture",
        "severity": normalize_severity(row.get("severity")),
        "resource_id": str(entity.get("id") or entity.get("name") or name)[:120],
        "resource_type": entity.get("type") or "cloud_resource",
        "resource_name": entity.get("name"),
        "region": entity.get("region"),
        "account_id": entity.get("subscriptionExternalId"),
        "external_id": f"WIZ-{row.get('id')}"[:120],
        "remediation": (row.get("remediationInstructions") or "Follow the Wiz remediation guidance.")[:600],
    }


WIZ = AdapterSpec(
    provider="wiz",
    connector_type="wiz",
    label="Wiz",
    claw="cloudclaw",
    auth="bearer",
    auth_name="Authorization",
    auth_prefix="Bearer",
    base_url_field="api_endpoint",
    token_field="client_secret",
    required_fields=("client_id", "client_secret"),
    endpoints=(
        Endpoint(
            path="/issues",
            items_key="data.issues.nodes",
            params={"first": 50, "status": "OPEN"},
            parse=_parse_wiz,
            limit=50,
        ),
    ),
)


# ── Snyk ──────────────────────────────────────────────────────────────────────

def _parse_snyk(row: dict, _creds: dict) -> Optional[dict]:
    attrs = row.get("attributes") or row
    title = attrs.get("title") or attrs.get("key")
    if not title:
        return None
    coordinates = (attrs.get("coordinates") or [{}])[0]
    package = ((coordinates.get("representations") or [{}])[0].get("dependency") or {})
    pkg_name = package.get("package_name")
    return {
        "title": f"Snyk: {title}",
        "description": (attrs.get("description") or "")[:600],
        "category": "dependency",
        "severity": normalize_severity(attrs.get("effective_severity_level")),
        "resource_id": str(pkg_name or row.get("id") or title)[:120],
        "resource_type": "package",
        "resource_name": pkg_name,
        "external_id": f"SNYK-{row.get('id')}"[:120],
        "remediation": "Upgrade the affected dependency to a fixed version.",
    }


SNYK = AdapterSpec(
    provider="snyk",
    connector_type="snyk",
    label="Snyk",
    claw="appclaw",
    auth="header",
    auth_name="Authorization",
    auth_prefix="token",
    base_url="https://api.snyk.io",
    token_field="api_token",
    required_fields=("api_token", "org_id"),
    endpoints=(
        Endpoint(
            path="/rest/orgs/{org_id}/issues",
            items_key="data",
            params={"version": "2024-01-04", "limit": 50, "status": "open"},
            parse=_parse_snyk,
            limit=50,
        ),
    ),
)


# ── Checkmarx ─────────────────────────────────────────────────────────────────

def _parse_checkmarx(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("queryName") or row.get("name")
    if not name:
        return None
    return {
        "title": f"Checkmarx: {name}",
        "description": (row.get("description") or "")[:600],
        "category": "application_security",
        "severity": normalize_severity(row.get("severity")),
        "resource_id": str(row.get("id") or name)[:120],
        "resource_type": "source_file",
        "resource_name": row.get("fileName"),
        "external_id": f"CHECKMARX-{row.get('id')}"[:120],
        "remediation": "Remediate the flagged code path identified by Checkmarx.",
    }


CHECKMARX = AdapterSpec(
    provider="checkmarx",
    connector_type="checkmarx",
    label="Checkmarx",
    claw="appclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url_field="base_url",
    token_field="api_key",
    required_fields=("api_key",),
    endpoints=(
        Endpoint(
            path="/api/sast-results",
            items_key="results",
            params={"limit": 50, "severity": "HIGH,CRITICAL"},
            parse=_parse_checkmarx,
            limit=50,
        ),
    ),
)


SPECS = (TENABLE, QUALYS, RAPID7, WIZ, SNYK, CHECKMARX)
