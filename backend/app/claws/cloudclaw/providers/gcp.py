"""
GCP Provider Adapter
Connects to Google Cloud Security Command Center (SCC) to pull findings.
Real URL: GET https://securitycenter.googleapis.com/v1/organizations/{org_id}/sources/-/findings
Falls back to simulated findings when no credentials configured.
"""
import logging
from datetime import datetime
from typing import Optional

import httpx

from app.claws import credential_aliases, provenance

logger = logging.getLogger("cloudclaw.gcp")

TIMEOUT = httpx.Timeout(30.0)
GCP_TOKEN_URL = "https://oauth2.googleapis.com/token"
SCC_BASE = "https://securitycenter.googleapis.com/v1"


# ─── Simulated findings for demo ─────────────────────────────────────────────

SIMULATED_FINDINGS = [
    {
        "title": "GCS Bucket Publicly Accessible",
        "description": (
            "Cloud Storage bucket 'gs://prod-backup-data' has uniform bucket-level access disabled "
            "and allUsers has 'Storage Object Viewer' permission. "
            "Any internet user can list and download objects."
        ),
        "category": "misconfiguration",
        "severity": "critical",
        "resource_id": "//storage.googleapis.com/projects/_/buckets/prod-backup-data",
        "resource_type": "storage_bucket",
        "resource_name": "prod-backup-data",
        "region": "us-central1",
        "account_id": "project-my-prod-123456",
        "risk_score": 93.0,
        "remediation": (
            "Remove allUsers and allAuthenticatedUsers from the bucket IAM policy. "
            "Enable uniform bucket-level access to prevent per-object ACLs. "
            "Use Cloud Audit Logs to review historical access."
        ),
        "remediation_effort": "quick_win",
        "external_id": "GCP-SCC-STORAGE_SCANNER-PUBLIC_BUCKET_ACL",
        "reference_url": "https://cloud.google.com/storage/docs/access-control/making-data-public",
    },
    {
        "title": "GKE Cluster Legacy Authorization Enabled",
        "description": (
            "GKE cluster 'prod-cluster-01' has ABAC (Attribute-Based Access Control) enabled. "
            "Legacy ABAC grants overly permissive access and bypasses RBAC controls."
        ),
        "category": "misconfiguration",
        "severity": "high",
        "resource_id": "//container.googleapis.com/projects/my-prod-123456/zones/us-central1-a/clusters/prod-cluster-01",
        "resource_type": "gke_cluster",
        "resource_name": "prod-cluster-01",
        "region": "us-central1",
        "account_id": "project-my-prod-123456",
        "risk_score": 78.0,
        "remediation": (
            "Disable legacy ABAC on the GKE cluster: "
            "gcloud container clusters update prod-cluster-01 --no-enable-legacy-authorization. "
            "Migrate all authorization to Kubernetes RBAC with least-privilege roles."
        ),
        "remediation_effort": "medium_term",
        "external_id": "GCP-SCC-CONTAINER_SCANNER-LEGACY_AUTHORIZATION_ENABLED",
        "reference_url": "https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control",
    },
    {
        "title": "Cloud SQL Instance Has Public IP",
        "description": (
            "Cloud SQL instance 'postgres-prod-01' is configured with a public IP address "
            "and no authorized networks are restricted. Any IP can attempt to connect."
        ),
        "category": "misconfiguration",
        "severity": "high",
        "resource_id": "//cloudsql.googleapis.com/projects/my-prod-123456/instances/postgres-prod-01",
        "resource_type": "cloudsql_instance",
        "resource_name": "postgres-prod-01",
        "region": "us-east1",
        "account_id": "project-my-prod-123456",
        "risk_score": 80.0,
        "remediation": (
            "Remove the public IP and use Cloud SQL Private IP with VPC peering. "
            "If public IP is required, restrict authorized networks to specific IP ranges. "
            "Enable Cloud SQL Auth Proxy for application connections."
        ),
        "remediation_effort": "medium_term",
        "external_id": "GCP-SCC-SQL_SCANNER-PUBLIC_IP_ADDRESS",
        "reference_url": "https://cloud.google.com/sql/docs/postgres/configure-private-ip",
    },
    {
        "title": "Service Account Has Project Owner Role",
        "description": (
            "Service account 'redacted_user' "
            "has the 'roles/owner' role at the project level. "
            "This violates least-privilege — the account has unrestricted access to all resources."
        ),
        "category": "misconfiguration",
        "severity": "critical",
        "resource_id": "//iam.googleapis.com/projects/my-prod-123456/serviceAccounts/redacted_user",
        "resource_type": "service_account",
        "resource_name": "sa-app-backend",
        "region": "global",
        "account_id": "project-my-prod-123456",
        "risk_score": 97.0,
        "remediation": (
            "Remove the 'roles/owner' binding from the service account. "
            "Replace with the minimum required roles for the application's functionality. "
            "Use IAM Recommender to identify the least-privilege role set based on actual usage."
        ),
        "remediation_effort": "medium_term",
        "external_id": "GCP-SCC-IAM_SCANNER-SERVICE_ACCOUNT_ROLE_SEPARATION",
        "reference_url": "https://cloud.google.com/iam/docs/understanding-roles",
    },
    {
        "title": "Compute Instance Has Public IP with No Firewall Restrictions",
        "description": (
            "VM instance 'vm-prod-api-01' has an external IP address and the VPC firewall "
            "allows inbound traffic from 0.0.0.0/0 on all ports. "
            "The instance is fully exposed to the internet."
        ),
        "category": "misconfiguration",
        "severity": "critical",
        "resource_id": "//compute.googleapis.com/projects/my-prod-123456/zones/us-central1-a/instances/vm-prod-api-01",
        "resource_type": "compute_instance",
        "resource_name": "vm-prod-api-01",
        "region": "us-central1",
        "account_id": "project-my-prod-123456",
        "risk_score": 91.0,
        "remediation": (
            "Remove the overly permissive ingress firewall rules. "
            "Create specific rules allowing only required ports from known IP ranges. "
            "Consider removing the external IP and using Cloud NAT + Identity-Aware Proxy for access."
        ),
        "remediation_effort": "quick_win",
        "external_id": "GCP-SCC-FIREWALL_SCANNER-OPEN_ALL_PORTS",
        "reference_url": "https://cloud.google.com/vpc/docs/firewalls",
    },
]


# ─── GCP Service Account token acquisition ───────────────────────────────────

async def _get_gcp_token(service_account_json: dict) -> str:
    """
    Acquire a GCP access token using a service account key file (JSON).
    Implements the JWT bearer token flow for GCP OAuth2.
    For production, use google-auth library instead.
    """
    import json
    import time
    import base64

    # Real GCP token acquisition requires the google-auth library for RSA signing.
    # google-auth is not installed in this environment — raise ValueError so
    # the caller falls back to simulated findings without crashing.
    raise ValueError(
        "GCP token acquisition requires the google-auth library. "
        "Install google-auth and use google.oauth2.service_account.Credentials."
    )


async def _fetch_real_findings(credentials: dict) -> list[dict]:
    """
    Call Google Cloud Security Command Center findings API.
    Expects credentials: {service_account_json (dict), organization_id}.
    """
    credentials = credential_aliases.resolve("gcp_scc", credentials)
    org_id = credentials.get("organization_id", "")
    service_account_json = credentials.get("service_account_json", {})

    if not org_id or not service_account_json:
        raise ValueError(
            "GCP requires an organization (or project) ID and a service account key"
        )

    token = await _get_gcp_token(service_account_json)

    url = f"{SCC_BASE}/organizations/{org_id}/sources/-/findings"
    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "filter": "state=\"ACTIVE\"",
        "pageSize": 100,
    }

    all_findings = []
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        while True:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            all_findings.extend(data.get("listFindingsResults", []))
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            params["pageToken"] = next_token

    return all_findings


def _parse_scc_finding(raw: dict, organization_id: str) -> dict:
    """Parse a raw GCP Security Command Center finding into the universal Finding format."""
    finding = raw.get("finding", {})

    severity_map = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }
    severity = severity_map.get(finding.get("severity", "MEDIUM"), "medium")
    resource_name = finding.get("resourceName", "")
    display_name = resource_name.split("/")[-1] if resource_name else "unknown"

    return {
        "claw": "cloudclaw",
        "provider": "gcp",
        "title": finding.get("category", "Unknown GCP Finding")[:512],
        "description": (finding.get("description") or "")[:2000],
        "category": "misconfiguration",
        "severity": severity,
        "resource_id": resource_name[:512],
        "resource_type": finding.get("resourceName", "").split("/")[4] if "/" in resource_name else "gcp_resource",
        "resource_name": display_name[:255],
        "region": "gcp",
        "account_id": organization_id,
        "risk_score": {"CRITICAL": 90.0, "HIGH": 70.0, "MEDIUM": 50.0, "LOW": 25.0}.get(
            finding.get("severity", "MEDIUM"), 50.0
        ),
        "actively_exploited": False,
        "status": "open" if finding.get("state") == "ACTIVE" else "resolved",
        "external_id": finding.get("name", "")[:256],
        "reference_url": finding.get("externalUri", "")[:512],
        "raw_data": str(raw)[:5000],
    }


# ─── Public entry point ───────────────────────────────────────────────────────

async def fetch_findings(credentials: dict) -> list[dict]:
    """Authenticated fetch that propagates failure to the caller."""
    credentials = credential_aliases.resolve("gcp_scc", credentials)
    org_id = credentials.get("organization_id", "unknown")
    raw_findings = await _fetch_real_findings(credentials)
    return provenance.live(
        [_parse_scc_finding(f, org_id) for f in raw_findings],
        provider="gcp",
        connector="gcp_security_command_center",
    )


async def get_findings(credentials: Optional[dict] = None) -> list[dict]:
    """
    Main entry point for the GCP adapter.
    Attempts a real Security Command Center call if credentials are provided.
    Falls back to simulated findings for demo/dev environments.
    """
    if credentials:
        try:
            return await fetch_findings(credentials)
        except NotImplementedError:
            logger.info("GCP adapter: using simulated findings (google-auth not wired up)")
        except Exception as exc:
            logger.warning("GCP Security Command Center call failed: %s — falling back to simulated findings", exc)

    # Return simulated findings with required universal fields
    results = []
    for f in SIMULATED_FINDINGS:
        finding = {
            "claw": "cloudclaw",
            "provider": "gcp",
            "actively_exploited": f.get("actively_exploited", False),
            "status": "open",
            **f,
        }
        results.append({**finding, "data_origin": provenance.SIMULATED})
    return results
