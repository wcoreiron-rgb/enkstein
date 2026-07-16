"""
Enkstein — Claw Registry
Maps connector_type → which claw(s) should be scanned when that connector is configured.

This is the source of truth for "when I plug connector X, which claw wakes up?"
"""
from typing import Optional

# connector_type → list of claw names that use it
CONNECTOR_TO_CLAWS: dict[str, list[str]] = {
    # Cloud
    "aws_security_hub":  ["cloudclaw"],
    "aws_iam":           ["cloudclaw", "devclaw", "appclaw"],
    "azure_defender":    ["cloudclaw"],
    "azure_arm":         ["cloudclaw"],
    "gcp_scc":           ["cloudclaw"],
    "gcp_iam":           ["cloudclaw"],
    "wiz":               ["cloudclaw"],

    # Endpoint
    "crowdstrike":       ["endpointclaw", "threatclaw"],
    "defender_endpoint": ["endpointclaw"],
    "sentinelone":       ["endpointclaw", "threatclaw"],
    "carbonblack":       ["endpointclaw"],
    "tanium":            ["endpointclaw"],

    # Identity / Access
    "okta":              ["accessclaw", "userclaw", "insiderclaw"],
    "entra_id":          ["accessclaw", "userclaw", "identityclaw"],
    "ping_identity":     ["accessclaw"],
    "auth0":             ["accessclaw"],
    "cyberark":          ["accessclaw"],
    "hashicorp_vault":   ["accessclaw"],
    "duo":               ["accessclaw"],

    # SIEM / Log
    "splunk":            ["logclaw", "automationclaw"],
    "sentinel":          ["logclaw", "threatclaw"],
    "elastic":           ["logclaw"],
    "qradar":            ["logclaw"],
    "datadog":           ["logclaw"],
    "sumologic":         ["logclaw"],

    # Threat Intel
    "crowdstrike_intel": ["threatclaw", "intelclaw"],
    "recorded_future":   ["threatclaw", "intelclaw"],
    "virustotal":        ["threatclaw"],

    # Network
    "paloalto":          ["netclaw"],
    "zscaler":           ["netclaw"],
    "cloudflare":        ["netclaw"],
    "cisco_umbrella":    ["netclaw"],
    "netskope":          ["netclaw", "saasclaw"],

    # Data / Privacy
    "purview":           ["dataclaw", "privacyclaw", "insiderclaw"],
    "varonis":           ["dataclaw", "privacyclaw"],
    "nightfall":         ["dataclaw", "privacyclaw"],
    "bigid":             ["dataclaw", "privacyclaw"],

    # App / Dev
    "github":            ["devclaw", "appclaw", "releaseclaw"],
    "gitlab":            ["devclaw", "appclaw", "releaseclaw"],
    "snyk":              ["appclaw", "devclaw"],
    "checkmarx":         ["appclaw"],
    "terraform_cloud":   ["terraclaw", "releaseclaw"],
    "terraform_mcp":     ["terraclaw"],
    "tfsec":             ["terraclaw"],
    "checkov":           ["terraclaw"],
    "infracost":         ["terraclaw"],

    # Compliance
    "drata":             ["complianceclaw"],
    "vanta":             ["complianceclaw"],

    # Vendor
    "servicenow":        ["vendorclaw", "automationclaw"],
    "jira":              ["vendorclaw", "devclaw"],

    # SaaS
    "ms_teams":          ["saasclaw"],
    "slack":             ["saasclaw"],

    # Vulnerability
    "tenable":           ["exposureclaw"],
    "qualys":            ["exposureclaw"],
    "rapid7":            ["exposureclaw"],

    # Alerting (alert_router only, no scan)
    "pagerduty":         [],   # only used for alert routing
}


# Maps claw name → scan HTTP endpoint path (for background scan dispatch)
CLAW_SCAN_PATHS: dict[str, str] = {
    "cloudclaw":       "/cloudclaw/scan",
    "exposureclaw":    "/exposureclaw/scan",
    "threatclaw":      "/threatclaw/scan",
    "endpointclaw":    "/endpointclaw/scan",
    "accessclaw":      "/accessclaw/scan",
    "logclaw":         "/logclaw/scan",
    "netclaw":         "/netclaw/scan",
    "dataclaw":        "/dataclaw/scan",
    "appclaw":         "/appclaw/scan",
    "saasclaw":        "/saasclaw/scan",
    "configclaw":      "/configclaw/scan",
    "complianceclaw":  "/complianceclaw/scan",
    "privacyclaw":     "/privacyclaw/scan",
    "vendorclaw":      "/vendorclaw/scan",
    "userclaw":        "/userclaw/scan",
    "insiderclaw":     "/insiderclaw/scan",
    "automationclaw":  "/automationclaw/scan",
    "attackpathclaw":  "/attackpathclaw/scan",
    "devclaw":         "/devclaw/scan",
    "intelclaw":       "/intelclaw/scan",
    "recoveryclaw":    "/recoveryclaw/scan",
    "releaseclaw":     "/releaseclaw/scan",
    "terraclaw":       "/terraclaw/scan",
    "identityclaw":    "/identityclaw/scan",
}


def get_claws_for_connector(connector_type: str) -> list[str]:
    """Return the list of claw names that should be scanned when this connector is configured."""
    return CONNECTOR_TO_CLAWS.get(connector_type, [])


def get_scan_path(claw_name: str) -> Optional[str]:
    """Return the HTTP path for a claw's scan endpoint."""
    return CLAW_SCAN_PATHS.get(claw_name)
