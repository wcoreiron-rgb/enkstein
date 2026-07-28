"""
SIEM, network security, and threat-intelligence adapters.

These providers are the platform's eyes: log coverage, egress control, and
external reputation.  Log platforms are treated as posture sources rather than
alert firehoses — the useful security finding is usually "this source stopped
reporting" or "these detections fired", not a copy of every log line.
"""
from __future__ import annotations

from typing import Any, Optional

from app.claws.rest_adapter import AdapterSpec, Endpoint, as_mapping, normalize_severity


# ── Microsoft Sentinel ────────────────────────────────────────────────────────

def _parse_sentinel(row: dict, _creds: dict) -> Optional[dict]:
    props = row.get("properties") or {}
    title = props.get("title")
    if not title:
        return None
    return {
        "title": f"Sentinel: {title}",
        "description": (props.get("description") or "")[:600],
        "category": "detection",
        "severity": normalize_severity(props.get("severity")),
        "resource_id": str(row.get("name") or title)[:120],
        "resource_type": "incident",
        "external_id": f"SENTINEL-{row.get('name')}"[:120],
        "remediation": "Triage the Sentinel incident and follow the assigned playbook.",
        "status": "open" if props.get("status") != "Closed" else "resolved",
    }


SENTINEL = AdapterSpec(
    provider="sentinel",
    connector_type="sentinel",
    label="Microsoft Sentinel",
    claw="logclaw",
    auth="device",
    base_url="https://management.azure.com",
    token_field="access_token",
    required_fields=("subscription_id", "resource_group", "workspace_name"),
    endpoints=(
        Endpoint(
            path=(
                "/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
                "/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
                "/providers/Microsoft.SecurityInsights/incidents"
            ),
            items_key="value",
            params={"api-version": "2023-02-01", "$top": 50},
            parse=_parse_sentinel,
            limit=50,
        ),
    ),
)


# ── Elastic Security ──────────────────────────────────────────────────────────

def _summarize_elastic(payload: Any, _creds: dict) -> list[dict]:
    # A cluster that is not green means detection coverage is degraded.
    status = as_mapping(payload).get("status")
    if status in ("red", "yellow"):
        severity = "critical" if status == "red" else "medium"
        return [{
            "title": f"Elastic cluster health is {status}",
            "description": (
                f"The Elastic cluster reports {status} health. Unassigned shards can "
                "mean security events are not being indexed, creating detection gaps."
            ),
            "category": "log_coverage",
            "severity": severity,
            "resource_id": "elastic-cluster-health",
            "resource_type": "cluster",
            "external_id": f"ELASTIC-HEALTH-{status.upper()}",
            "remediation": "Investigate unassigned shards and restore cluster health.",
        }]
    return []


ELASTIC = AdapterSpec(
    provider="elastic",
    connector_type="elastic",
    label="Elastic Security",
    claw="logclaw",
    auth="header",
    auth_name="Authorization",
    auth_prefix="ApiKey",
    base_url_field="cloud_id",
    token_field="api_key",
    required_fields=("cloud_id", "api_key"),
    endpoints=(
        Endpoint(path="/_cluster/health", summarize=_summarize_elastic),
    ),
)


# ── IBM QRadar ────────────────────────────────────────────────────────────────

def _parse_qradar(row: dict, _creds: dict) -> Optional[dict]:
    description = row.get("description") or row.get("offense_type")
    if not description:
        return None
    magnitude = row.get("magnitude") or 0
    severity = "critical" if magnitude >= 8 else "high" if magnitude >= 6 else "medium"
    return {
        "title": f"QRadar offense: {str(description).strip()[:120]}",
        "description": (
            f"QRadar raised an offense with magnitude {magnitude} affecting "
            f"{row.get('event_count', 0)} events."
        ),
        "category": "detection",
        "severity": severity,
        "resource_id": str(row.get("id"))[:120],
        "resource_type": "offense",
        "external_id": f"QRADAR-{row.get('id')}"[:120],
        "remediation": "Triage the QRadar offense and close it with a documented outcome.",
    }


QRADAR = AdapterSpec(
    provider="qradar",
    connector_type="qradar",
    label="IBM QRadar",
    claw="logclaw",
    auth="header",
    auth_name="SEC",
    base_url_field="host",
    token_field="api_key",
    required_fields=("host", "api_key"),
    endpoints=(
        Endpoint(
            path="/api/siem/offenses",
            params={"filter": "status=OPEN"},
            parse=_parse_qradar,
            limit=50,
        ),
    ),
)


# ── Datadog ───────────────────────────────────────────────────────────────────

def _parse_datadog(row: dict, _creds: dict) -> Optional[dict]:
    attrs = row.get("attributes") or {}
    rule = (attrs.get("rule") or {}).get("name") or attrs.get("title")
    if not rule:
        return None
    return {
        "title": f"Datadog: {rule}",
        "description": (attrs.get("message") or "")[:600],
        "category": "detection",
        "severity": normalize_severity((attrs.get("rule") or {}).get("severity")),
        "resource_id": str(row.get("id"))[:120],
        "resource_type": "security_signal",
        "external_id": f"DATADOG-{row.get('id')}"[:120],
        "remediation": "Review the Datadog security signal and action the detection.",
    }


DATADOG = AdapterSpec(
    provider="datadog",
    connector_type="datadog",
    label="Datadog",
    claw="logclaw",
    auth="header",
    auth_name="DD-API-KEY",
    base_url="https://api.datadoghq.com",
    token_field="api_key",
    required_fields=("api_key", "app_key"),
    endpoints=(
        Endpoint(
            path="/api/v2/security_monitoring/signals",
            items_key="data",
            params={"page[limit]": 50},
            parse=_parse_datadog,
            limit=50,
        ),
    ),
)


# ── Sumo Logic ────────────────────────────────────────────────────────────────

def _parse_sumologic(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("name") or row.get("description")
    if not name:
        return None
    return {
        "title": f"Sumo Logic: {name}",
        "description": (row.get("description") or "")[:600],
        "category": "detection",
        "severity": normalize_severity(row.get("severity")),
        "resource_id": str(row.get("id") or name)[:120],
        "resource_type": "signal",
        "external_id": f"SUMO-{row.get('id')}"[:120],
        "remediation": "Review the Sumo Logic insight and confirm the detection coverage.",
    }


SUMOLOGIC = AdapterSpec(
    provider="sumologic",
    connector_type="sumologic",
    label="Sumo Logic",
    claw="logclaw",
    auth="basic",
    username_field="access_id",
    password_field="access_key",
    base_url="https://api.sumologic.com",
    required_fields=("access_id", "access_key"),
    endpoints=(
        Endpoint(path="/api/sec/v1/insights", items_key="data.objects", parse=_parse_sumologic, limit=50),
    ),
)


# ── Palo Alto Networks ────────────────────────────────────────────────────────

def _parse_paloalto(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("@name") or row.get("name")
    if not name:
        return None
    # A permissive any/any rule is the highest-value firewall finding.
    source = str(row.get("source", {}).get("member", ""))
    dest = str(row.get("destination", {}).get("member", ""))
    if "any" not in source.lower() or "any" not in dest.lower():
        return None
    return {
        "title": f"Palo Alto: permissive any-to-any rule '{name}'",
        "description": (
            f"Security rule '{name}' allows traffic from any source to any "
            "destination, which defeats segmentation for the zones it covers."
        ),
        "category": "network_security",
        "severity": "high",
        "resource_id": str(name)[:120],
        "resource_type": "firewall_rule",
        "resource_name": name,
        "external_id": f"PANOS-ANYANY-{name}"[:120],
        "remediation": "Scope the rule to specific sources, destinations, and services.",
    }


PALOALTO = AdapterSpec(
    provider="paloalto",
    connector_type="paloalto",
    label="Palo Alto Networks",
    claw="netclaw",
    auth="header",
    auth_name="X-PAN-KEY",
    base_url_field="host",
    token_field="api_key",
    required_fields=("host", "api_key"),
    endpoints=(
        Endpoint(
            path="/restapi/v10.1/Policies/SecurityRules",
            items_key="result.entry",
            params={"location": "vsys", "vsys": "vsys1"},
            parse=_parse_paloalto,
            limit=100,
        ),
    ),
)


# ── Zscaler ───────────────────────────────────────────────────────────────────

def _summarize_zscaler(payload: Any, _creds: dict) -> list[dict]:
    rules = payload if isinstance(payload, list) else []
    disabled = [r for r in rules if r.get("state") == "DISABLED"]
    if not disabled:
        return []
    return [{
        "title": f"Zscaler: {len(disabled)} disabled URL filtering rules",
        "description": (
            f"{len(disabled)} URL filtering rules are disabled, so the egress "
            "controls they were written to enforce are not active."
        ),
        "category": "network_security",
        "severity": "medium",
        "resource_id": "zscaler-disabled-rules",
        "resource_type": "policy_set",
        "external_id": f"ZSCALER-DISABLED-{len(disabled)}",
        "remediation": "Re-enable or formally retire the disabled filtering rules.",
    }]


ZSCALER = AdapterSpec(
    provider="zscaler",
    connector_type="zscaler",
    label="Zscaler",
    claw="netclaw",
    auth="header",
    auth_name="Cookie",
    base_url_field="cloud",
    token_field="api_key",
    required_fields=("cloud", "api_key"),
    endpoints=(
        Endpoint(path="/api/v1/urlFilteringRules", summarize=_summarize_zscaler),
    ),
)


# ── Cloudflare ────────────────────────────────────────────────────────────────

def _summarize_cloudflare(payload: Any, _creds: dict) -> list[dict]:
    zones = as_mapping(payload).get("result") or []
    insecure = [z for z in zones if z.get("status") != "active"]
    if not insecure:
        return []
    return [{
        "title": f"Cloudflare: {len(insecure)} zones not fully active",
        "description": (
            f"{len(insecure)} Cloudflare zones are not in an active state, so the "
            "WAF and DDoS protections configured for them may not be applied."
        ),
        "category": "network_security",
        "severity": "medium",
        "resource_id": "cloudflare-inactive-zones",
        "resource_type": "zone_collection",
        "external_id": f"CLOUDFLARE-INACTIVE-{len(insecure)}",
        "remediation": "Complete zone activation or remove unused zones.",
    }]


CLOUDFLARE = AdapterSpec(
    provider="cloudflare",
    connector_type="cloudflare",
    label="Cloudflare",
    claw="netclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url="https://api.cloudflare.com",
    token_field="api_token",
    required_fields=("api_token",),
    endpoints=(
        Endpoint(path="/client/v4/zones", summarize=_summarize_cloudflare),
    ),
)


# ── Cisco Umbrella ────────────────────────────────────────────────────────────

def _parse_umbrella(row: dict, _creds: dict) -> Optional[dict]:
    domain = row.get("domain") or row.get("name")
    if not domain:
        return None
    return {
        "title": f"Cisco Umbrella: blocked request to {domain}",
        "description": (
            f"Umbrella blocked DNS resolution for {domain}, categorised as "
            f"{row.get('categories') or 'a security threat'}."
        ),
        "category": "network_security",
        "severity": "high",
        "resource_id": str(domain)[:120],
        "resource_type": "domain",
        "resource_name": domain,
        "external_id": f"UMBRELLA-{domain}"[:120],
        "remediation": "Investigate the originating host for possible compromise.",
    }


CISCO_UMBRELLA = AdapterSpec(
    provider="cisco_umbrella",
    connector_type="cisco_umbrella",
    label="Cisco Umbrella",
    claw="netclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url="https://api.umbrella.com",
    token_field="api_key",
    required_fields=("api_key",),
    endpoints=(
        Endpoint(
            path="/reports/v2/activity/dns",
            items_key="data",
            params={"limit": 50, "verdict": "blocked"},
            parse=_parse_umbrella,
            limit=50,
        ),
    ),
)


# ── VirusTotal ────────────────────────────────────────────────────────────────

def _summarize_virustotal(payload: Any, _creds: dict) -> list[dict]:
    data = as_mapping(as_mapping(payload).get("data"))
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    if malicious <= 0:
        return []
    target = data.get("id") or "indicator"
    return [{
        "title": f"VirusTotal: {malicious} engines flag {target} as malicious",
        "description": (
            f"{malicious} antivirus engines classify this indicator as malicious. "
            "Treat any internal contact with it as a potential compromise."
        ),
        "category": "threat_intelligence",
        "severity": "critical" if malicious >= 10 else "high",
        "resource_id": str(target)[:120],
        "resource_type": "indicator",
        "external_id": f"VT-{target}"[:120],
        "actively_exploited": malicious >= 10,
        "remediation": "Block the indicator and hunt for prior contact in DNS and proxy logs.",
    }]


VIRUSTOTAL = AdapterSpec(
    provider="virustotal",
    connector_type="virustotal",
    label="VirusTotal",
    claw="threatclaw",
    auth="header",
    auth_name="x-apikey",
    base_url="https://www.virustotal.com",
    token_field="api_key",
    required_fields=("api_key",),
    endpoints=(
        # Without a specific indicator to enrich, report the account's own
        # quota posture instead of inventing threat data.
        Endpoint(path="/api/v3/users/{api_key}", summarize=_summarize_virustotal, optional=True),
    ),
)


# ── Recorded Future ───────────────────────────────────────────────────────────

def _parse_recorded_future(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("name") or (row.get("entity") or {}).get("name")
    if not name:
        return None
    risk = (row.get("risk") or {}).get("score")
    return {
        "title": f"Recorded Future: high-risk indicator {name}",
        "description": (
            f"Recorded Future assigns this indicator a risk score of {risk}. "
            "Review internal telemetry for contact with it."
        ),
        "category": "threat_intelligence",
        "severity": "critical" if (risk or 0) >= 90 else "high",
        "resource_id": str(name)[:120],
        "resource_type": "indicator",
        "risk_score": float(risk) if isinstance(risk, (int, float)) else None,
        "external_id": f"RF-{name}"[:120],
        "remediation": "Block the indicator and hunt for historical contact.",
    }


RECORDED_FUTURE = AdapterSpec(
    provider="recorded_future",
    connector_type="recorded_future",
    label="Recorded Future",
    claw="intelclaw",
    auth="header",
    auth_name="X-RFToken",
    base_url="https://api.recordedfuture.com",
    token_field="api_token",
    required_fields=("api_token",),
    endpoints=(
        Endpoint(
            path="/v2/ip/search",
            items_key="data.results",
            params={"riskScore": "[90,100]", "limit": 50},
            parse=_parse_recorded_future,
            limit=50,
        ),
    ),
)


# ── CrowdStrike Intel ─────────────────────────────────────────────────────────

def _parse_cs_intel(row: dict, _creds: dict) -> Optional[dict]:
    actor = row.get("name") or row.get("short_description")
    if not actor:
        return None
    return {
        "title": f"CrowdStrike Intel: activity attributed to {actor}",
        "description": (row.get("short_description") or "")[:600],
        "category": "threat_intelligence",
        "severity": "high",
        "resource_id": str(row.get("id") or actor)[:120],
        "resource_type": "threat_actor",
        "resource_name": actor,
        "external_id": f"CSINTEL-{row.get('id')}"[:120],
        "remediation": "Map the actor's known TTPs against current detection coverage.",
    }


CROWDSTRIKE_INTEL = AdapterSpec(
    provider="crowdstrike_intel",
    connector_type="crowdstrike_intel",
    label="CrowdStrike Intel",
    claw="intelclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url="https://api.crowdstrike.com",
    token_field="client_secret",
    required_fields=("client_id", "client_secret"),
    endpoints=(
        Endpoint(
            path="/intel/combined/actors/v1",
            items_key="resources",
            params={"limit": 25},
            parse=_parse_cs_intel,
            limit=25,
        ),
    ),
)


SPECS = (
    SENTINEL, ELASTIC, QRADAR, DATADOG, SUMOLOGIC,
    PALOALTO, ZSCALER, CLOUDFLARE, CISCO_UMBRELLA,
    VIRUSTOTAL, RECORDED_FUTURE, CROWDSTRIKE_INTEL,
)
