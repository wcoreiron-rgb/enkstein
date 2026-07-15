"""
RegentClaw — Connector Marketplace Seed (v2)
=============================================
Seeds 42 enterprise connectors across 9 categories.
Every connector is scoped, risk-rated, trust-scored, and access-controlled.

Usage:
  docker compose exec backend python seed_connectors.py           # additive
  docker compose exec backend python seed_connectors.py --reset  # wipe + re-seed

Categories:
  Identity & Access       (7)  — IAM, PAM, MFA, directory
  Security & SIEM         (6)  — log mgmt, threat detection, analytics
  Endpoint & EDR          (5)  — device security, EDR, patch mgmt
  Cloud & Infrastructure  (5)  — cloud IAM, posture, resource mgmt
  Network & Zero Trust    (5)  — firewall, SASE, DNS, proxy
  Data & DLP              (4)  — data classification, DLP, privacy
  AI / LLM                (3)  — AI proxy providers
  Dev & Collaboration     (5)  — SCM, ticketing, alerting, chat
  Threat Intel & Vuln     (4)  — threat intel, vulnerability mgmt
  Compliance              (3)  — GRC, audit, evidence collection
"""

import asyncio
import json
import sys
from app.core.database import AsyncSessionLocal
from app.models.connector import Connector, ConnectorStatus, ConnectorRisk


def _ts(risk: str, status: str) -> float:
    """Compute trust score from risk level + approval status."""
    base = {"low": 92, "medium": 72, "high": 45, "critical": 20}.get(risk, 70)
    bonus = 8 if status == "approved" else 0
    return float(min(base + bonus, 100))


CONNECTORS = [

    # ══════════════════════════════════════════════════════════════════
    # IDENTITY & ACCESS MANAGEMENT  (7)
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "Microsoft Entra ID",
        "connector_type": "entra_id",
        "category": "Identity & Access",
        "description": (
            "Microsoft Entra ID (formerly Azure AD). Primary identity provider — "
            "user directory, group membership, MFA status, conditional access policies, "
            "service principal inventory, and sign-in risk signals. Powers IdentityClaw."
        ),
        "status": "approved", "risk_level": "medium",
        "requested_scopes": json.dumps(["User.Read.All", "Group.Read.All", "AuditLog.Read.All", "IdentityRiskEvent.Read.All", "Policy.Read.All"]),
        "approved_scopes":  json.dumps(["User.Read.All", "Group.Read.All", "AuditLog.Read.All", "IdentityRiskEvent.Read.All"]),
        "endpoint": "https://graph.microsoft.com/v1.0",
        "network_access": True,
    },
    {
        "name": "Okta",
        "connector_type": "okta",
        "category": "Identity & Access",
        "description": (
            "Okta Identity Cloud — SSO, user lifecycle, group policies, and MFA enforcement. "
            "Secondary IdP for non-Microsoft workloads. Feeds identity risk signals into IdentityClaw."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["okta.users.read", "okta.groups.read", "okta.logs.read", "okta.policies.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://{your-org}.okta.com/api/v1",
        "network_access": True,
    },
    {
        "name": "Ping Identity",
        "connector_type": "ping_identity",
        "category": "Identity & Access",
        "description": (
            "PingOne / PingFederate — enterprise SSO and federated identity. "
            "Provides SAML/OIDC federation telemetry, user session data, "
            "and adaptive authentication signals for IdentityClaw risk scoring."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["p1:read:user", "p1:read:sessions", "p1:read:logs"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.pingone.com/v1",
        "network_access": True,
    },
    {
        "name": "Auth0",
        "connector_type": "auth0",
        "category": "Identity & Access",
        "description": (
            "Auth0 / Okta Customer Identity — customer-facing IAM. "
            "Surfaces authentication anomalies, brute-force attempts, and bot signals "
            "for customer-facing applications. Read-only Management API access."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["read:users", "read:logs", "read:stats", "read:anomaly_blocks"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://{your-tenant}.auth0.com/api/v2",
        "network_access": True,
    },
    {
        "name": "CyberArk PAM",
        "connector_type": "cyberark",
        "category": "Identity & Access",
        "description": (
            "CyberArk Privileged Access Manager — secrets vault, privileged session management, "
            "and just-in-time access. RegentClaw audits privileged account usage and "
            "flags credential sharing or policy deviations."
        ),
        "status": "pending", "risk_level": "high",
        "requested_scopes": json.dumps(["Safes.Read", "Accounts.Read", "SessionMonitoring.Read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://cyberark.{your-org}.com/PasswordVault",
        "network_access": True,
    },
    {
        "name": "HashiCorp Vault",
        "connector_type": "hashicorp_vault",
        "category": "Identity & Access",
        "description": (
            "HashiCorp Vault — secrets management and dynamic credential generation. "
            "RegentClaw reads audit logs to detect unusual secret access patterns, "
            "token revocations, and policy violations. Never reads secret values."
        ),
        "status": "pending", "risk_level": "high",
        "requested_scopes": json.dumps(["audit.read", "sys/health", "auth/token/lookup"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://vault.{your-org}.com:8200",
        "network_access": True,
    },
    {
        "name": "Duo Security",
        "connector_type": "duo",
        "category": "Identity & Access",
        "description": (
            "Duo Security MFA — multi-factor authentication telemetry. "
            "Pulls authentication logs, failed MFA attempts, device trust posture, "
            "and bypass events. Correlates MFA anomalies with identity risk scores."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["read_log", "read_user", "read_device"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api-{your-host}.duosecurity.com",
        "network_access": True,
    },

    # ══════════════════════════════════════════════════════════════════
    # SECURITY & SIEM  (6)
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "Microsoft Sentinel",
        "connector_type": "sentinel",
        "category": "Security & SIEM",
        "description": (
            "Microsoft Sentinel SIEM — cloud-native security information and event management. "
            "Pulls alerts, incidents, threat intel, and hunting queries. "
            "CoreOS normalizes Sentinel events into the RegentClaw telemetry bus."
        ),
        "status": "approved", "risk_level": "low",
        "requested_scopes": json.dumps(["SecurityIncident.Read", "SecurityAlert.Read", "ThreatIntelligenceIndicator.Read"]),
        "approved_scopes":  json.dumps(["SecurityIncident.Read", "SecurityAlert.Read", "ThreatIntelligenceIndicator.Read"]),
        "endpoint": "https://management.azure.com",
        "network_access": True,
    },
    {
        "name": "Splunk Enterprise",
        "connector_type": "splunk",
        "category": "Security & SIEM",
        "description": (
            "Splunk SIEM — log aggregation, search, alerting, and dashboards for on-prem "
            "and hybrid workloads. Complements Sentinel for non-Azure infrastructure."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["search", "alerts.read", "indexes.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://splunk.{your-org}.com:8089",
        "network_access": True,
    },
    {
        "name": "IBM QRadar",
        "connector_type": "qradar",
        "category": "Security & SIEM",
        "description": (
            "IBM QRadar SIEM — threat detection, log management, and network flow analysis. "
            "RegentClaw pulls offenses, rule violations, and risk ratings from QRadar "
            "to correlate with endpoint and identity telemetry."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["offenses.read", "rules.read", "assets.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://qradar.{your-org}.com/api",
        "network_access": True,
    },
    {
        "name": "Elastic SIEM",
        "connector_type": "elastic",
        "category": "Security & SIEM",
        "description": (
            "Elastic Security — SIEM built on the ELK stack. Pulls detection alerts, "
            "anomaly detections, and ML job results. Integrates with the RegentClaw "
            "event pipeline for correlation with identity and cloud signals."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["read_alerts", "read_cases", "monitor"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://{your-cluster}.es.{region}.aws.elastic.cloud",
        "network_access": True,
    },
    {
        "name": "Datadog Security",
        "connector_type": "datadog",
        "category": "Security & SIEM",
        "description": (
            "Datadog Cloud SIEM — cloud-scale log management and security monitoring. "
            "RegentClaw pulls security signals, detection rule matches, and audit trails "
            "from Datadog for correlation and compliance reporting."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["security_monitoring_signals.read", "logs_read", "audit_logs.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.datadoghq.com",
        "network_access": True,
    },
    {
        "name": "Sumo Logic",
        "connector_type": "sumologic",
        "category": "Security & SIEM",
        "description": (
            "Sumo Logic cloud SIEM — continuous intelligence platform for log analytics "
            "and threat detection. Provides cloud-native security monitoring data for "
            "SaaS, serverless, and container workloads."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["read", "viewCollectors", "viewFields"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.{region}.sumologic.com/api/v1",
        "network_access": True,
    },

    # ══════════════════════════════════════════════════════════════════
    # ENDPOINT & EDR  (5)
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "CrowdStrike Falcon",
        "connector_type": "crowdstrike",
        "category": "Endpoint & EDR",
        "description": (
            "CrowdStrike Falcon EDR — endpoint detection and response. Pulls device health, "
            "threat detections, process telemetry, and prevention events. "
            "Feeds high-fidelity endpoint signals into the risk scoring engine."
        ),
        "status": "approved", "risk_level": "low",
        "requested_scopes": json.dumps(["Detections.Read", "Hosts.Read", "Incidents.Read", "IOC.Read"]),
        "approved_scopes":  json.dumps(["Detections.Read", "Hosts.Read", "Incidents.Read"]),
        "endpoint": "https://api.crowdstrike.com",
        "network_access": True,
    },
    {
        "name": "Microsoft Defender for Endpoint",
        "connector_type": "defender_endpoint",
        "category": "Endpoint & EDR",
        "description": (
            "Microsoft Defender for Endpoint — enterprise EDR built into Windows. "
            "Pulls machine risk scores, active alerts, vulnerable software, "
            "and investigation findings via Microsoft 365 Defender APIs."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["Machine.Read.All", "Alert.Read.All", "Vulnerability.Read.All"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.securitycenter.microsoft.com",
        "network_access": True,
    },
    {
        "name": "SentinelOne",
        "connector_type": "sentinelone",
        "category": "Endpoint & EDR",
        "description": (
            "SentinelOne Singularity — AI-powered endpoint protection and EDR. "
            "Surfaces threats, lateral movement, and MITRE ATT&CK technique mappings. "
            "Deep-visibility telemetry enriches EndpointClaw findings."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["threats.read", "agents.read", "activities.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://{your-org}.sentinelone.net/web/api/v2.1",
        "network_access": True,
    },
    {
        "name": "Carbon Black",
        "connector_type": "carbonblack",
        "category": "Endpoint & EDR",
        "description": (
            "VMware Carbon Black Cloud — behavioral EDR and endpoint standard. "
            "Pulls process events, network connections, and policy violations. "
            "Integrates with EndpointClaw for device risk profiling."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["device.read", "alert.read", "policy.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://defense-{region}.conferdeploy.net",
        "network_access": True,
    },
    {
        "name": "Tanium",
        "connector_type": "tanium",
        "category": "Endpoint & EDR",
        "description": (
            "Tanium — real-time endpoint visibility and control at scale. "
            "Enables live querying of asset inventory, patch state, and process data "
            "for EndpointClaw automated compliance and hygiene checks."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["asset.read", "patch.read", "question.execute"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://tanium.{your-org}.com",
        "network_access": True,
    },

    # ══════════════════════════════════════════════════════════════════
    # CLOUD & INFRASTRUCTURE  (5)
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "AWS IAM",
        "connector_type": "aws_iam",
        "category": "Cloud & Infrastructure",
        "description": (
            "AWS IAM — user, role, and policy inventory for AWS workloads. "
            "Detects overly permissive roles, unused credentials, "
            "and cross-account trust relationships. Read-only via AWS SDK."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["iam:ListUsers", "iam:ListRoles", "iam:ListPolicies", "sts:GetCallerIdentity"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://iam.amazonaws.com",
        "network_access": True,
    },
    {
        "name": "Azure Resource Manager",
        "connector_type": "azure_arm",
        "category": "Cloud & Infrastructure",
        "description": (
            "Azure Resource Manager — resource inventory, RBAC assignments, "
            "and policy compliance state across Azure subscriptions. "
            "CloudClaw uses ARM to detect misconfigured storage, NSGs, and IAM."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["Reader", "Security Reader"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://management.azure.com",
        "network_access": True,
    },
    {
        "name": "Google Cloud IAM",
        "connector_type": "gcp_iam",
        "category": "Cloud & Infrastructure",
        "description": (
            "Google Cloud IAM — service account, role binding, and org policy "
            "inventory for GCP workloads. Detects excessive permissions, "
            "unused service accounts, and cross-project access violations."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["iam.roles.list", "iam.serviceAccounts.list", "resourcemanager.projects.getIamPolicy"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://iam.googleapis.com",
        "network_access": True,
    },
    {
        "name": "GCP Security Command Center",
        "connector_type": "gcp_scc",
        "category": "Cloud & Infrastructure",
        "description": (
            "Google Cloud Security Command Center — centralized vulnerability and "
            "threat findings for GCP assets. Pulls misconfigurations, active threats, "
            "and compliance violations into the RegentClaw event pipeline."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["securitycenter.findings.list", "securitycenter.assets.list"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://securitycenter.googleapis.com",
        "network_access": True,
    },
    {
        "name": "Wiz",
        "connector_type": "wiz",
        "category": "Cloud & Infrastructure",
        "description": (
            "Wiz Cloud Security — agentless CNAPP for cloud risk assessment. "
            "Surfaces critical attack paths, misconfigurations, and CVEs across "
            "AWS, Azure, and GCP without installing any agents."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["read:issues", "read:assets", "read:reports"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.us1.app.wiz.io/graphql",
        "network_access": True,
    },

    # ══════════════════════════════════════════════════════════════════
    # NETWORK & ZERO TRUST  (5)
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "Palo Alto Networks",
        "connector_type": "paloalto",
        "category": "Network & Zero Trust",
        "description": (
            "Palo Alto Networks Panorama — next-gen firewall policy and threat log management. "
            "Pulls traffic anomalies, threat events, and URL filtering blocks. "
            "NetClaw correlates firewall events with endpoint and identity telemetry."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["log.read", "policy.read", "threat.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://panorama.{your-org}.com/restapi/v10.2",
        "network_access": True,
    },
    {
        "name": "Zscaler ZIA",
        "connector_type": "zscaler",
        "category": "Network & Zero Trust",
        "description": (
            "Zscaler Internet Access — cloud-native secure web gateway and SASE proxy. "
            "Pulls URL categories, policy violations, and data loss alerts. "
            "Enables NetClaw visibility into encrypted web traffic."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["read_logs", "read_policy", "read_users"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://zsapi.zscaler.net/api/v1",
        "network_access": True,
    },
    {
        "name": "Cloudflare",
        "connector_type": "cloudflare",
        "category": "Network & Zero Trust",
        "description": (
            "Cloudflare — edge security, Zero Trust Network Access, and DDoS mitigation. "
            "Pulls WAF events, bot scores, Zero Trust access logs, and DNS analytics "
            "for NetClaw perimeter visibility."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["zone:read", "logs:read", "access:read", "gateway:read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.cloudflare.com/client/v4",
        "network_access": True,
    },
    {
        "name": "Cisco Umbrella",
        "connector_type": "cisco_umbrella",
        "category": "Network & Zero Trust",
        "description": (
            "Cisco Umbrella — DNS-layer security and SASE. Surfaces C2 callbacks, "
            "malicious domain lookups, and policy violations at the DNS layer "
            "before network connections are established."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["reports.read", "policy.read", "admin.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.umbrella.com",
        "network_access": True,
    },
    {
        "name": "Netskope",
        "connector_type": "netskope",
        "category": "Network & Zero Trust",
        "description": (
            "Netskope SSE — cloud-native CASB and SWG for SaaS visibility. "
            "Detects shadow IT, DLP violations, and risky cloud app usage. "
            "Feeds cloud access telemetry into RegentClaw's risk pipeline."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["events.read", "alerts.read", "policy.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://{your-tenant}.goskope.com/api/v2",
        "network_access": True,
    },

    # ══════════════════════════════════════════════════════════════════
    # DATA & DLP  (4)
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "Microsoft Purview",
        "connector_type": "purview",
        "category": "Data & DLP",
        "description": (
            "Microsoft Purview — data governance, DLP, and compliance. "
            "Pulls DLP policy matches, sensitivity label events, and data catalog "
            "classifications for DataClaw and ComplianceClaw enforcement."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["InformationProtectionPolicy.Read", "DlpPolicy.Read", "ComplianceManager.Read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://compliance.microsoft.com",
        "network_access": True,
    },
    {
        "name": "Varonis Data Security",
        "connector_type": "varonis",
        "category": "Data & DLP",
        "description": (
            "Varonis — data access governance, insider threat detection, and DLP. "
            "Maps file system permissions, detects anomalous data access, "
            "and surfaces stale or overexposed sensitive data stores."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["users.read", "alerts.read", "reports.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://varonis.{your-org}.com/api",
        "network_access": True,
    },
    {
        "name": "Nightfall AI",
        "connector_type": "nightfall",
        "category": "Data & DLP",
        "description": (
            "Nightfall AI — cloud DLP for SaaS and GenAI. Detects sensitive data "
            "in Slack, GitHub, Google Drive, and LLM outputs in real time. "
            "Integrates with ArcClaw for AI-specific DLP enforcement."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["scan", "findings.read", "policies.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.nightfall.ai/v3",
        "network_access": True,
    },
    {
        "name": "BigID",
        "connector_type": "bigid",
        "category": "Data & DLP",
        "description": (
            "BigID — data privacy and protection intelligence. Discovers, classifies, "
            "and maps PII, PHI, and financial data across cloud, on-prem, and SaaS. "
            "Feeds data risk scores into PrivacyClaw and ComplianceClaw."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["data-catalog.read", "findings.read", "policies.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://{your-org}.bigid.cloud/api/v1",
        "network_access": True,
    },

    # ══════════════════════════════════════════════════════════════════
    # AI / LLM PROVIDERS
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "OpenAI API",
        "connector_type": "openai",
        "category": "AI / LLM",
        "description": (
            "OpenAI GPT-4o / GPT-3.5 — cloud LLM provider for ArcClaw's AI proxy. "
            "Every prompt is inspected and policy-checked before being forwarded. "
            "Raw secrets and sensitive data are redacted before leaving RegentClaw."
        ),
        "status": "approved", "risk_level": "medium",
        "requested_scopes": json.dumps(["chat.completions", "models.read"]),
        "approved_scopes":  json.dumps(["chat.completions"]),
        "endpoint": "https://api.openai.com/v1",
        "network_access": True,
    },
    {
        "name": "Anthropic Claude",
        "connector_type": "anthropic",
        "category": "AI / LLM",
        "description": (
            "Anthropic Claude — constitutional AI model with built-in safety layers. "
            "Used as primary or fallback LLM behind ArcClaw's inspection proxy. "
            "Sensitive data is redacted before forwarding via the ArcClaw pipeline."
        ),
        "status": "approved", "risk_level": "medium",
        "requested_scopes": json.dumps(["messages.create"]),
        "approved_scopes":  json.dumps(["messages.create"]),
        "endpoint": "https://api.anthropic.com/v1",
        "network_access": True,
    },
    {
        "name": "Ollama (Local LLM)",
        "connector_type": "ollama",
        "category": "AI / LLM",
        "description": (
            "Ollama — local LLM runtime. Models run entirely on-premises — no data leaves "
            "the network. Zero cost, full privacy. Supports llama3, mistral, phi3, gemma2 "
            "and any locally pulled model. Preferred for sensitive workloads."
        ),
        "status": "approved", "risk_level": "low",
        "requested_scopes": json.dumps(["chat", "generate", "models.list"]),
        "approved_scopes":  json.dumps(["chat", "generate", "models.list"]),
        "endpoint": "http://host.docker.internal:11434",
        "network_access": True,
    },
    {
        "name": "NVIDIA NIM",
        "connector_type": "nvidia_nim",
        "category": "AI / LLM",
        "description": (
            "NVIDIA NIM — 80+ enterprise-grade AI models via an OpenAI-compatible API. "
            "Free tier available at build.nvidia.com/models. Includes Llama 3, Mistral, "
            "Nemotron, and specialised security/code models. Every prompt is inspected "
            "and policy-checked by ArcClaw before being forwarded to NVIDIA's inference "
            "endpoints. Get your free API key at: https://build.nvidia.com/models"
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["chat.completions", "models.list"]),
        "approved_scopes":  json.dumps(["chat.completions", "models.list"]),
        "endpoint": "https://integrate.api.nvidia.com/v1",
        "network_access": True,
        "credential_fields": json.dumps([
            {"key": "api_key", "label": "NVIDIA API Key", "type": "password",
             "help": "Get a free key at https://build.nvidia.com/models — click any model → Get API Key"}
        ]),
    },
    {
        "name": "Google Gemini",
        "connector_type": "gemini",
        "category": "AI / LLM",
        "description": (
            "Google Gemini Developer API for governed Chat and Cowork reasoning. "
            "Marcellus validates the credential with a minimal inference and routes "
            "every request through Trust Fabric, prompt defense, and DLP redaction."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["generateContent"]),
        "approved_scopes": json.dumps(["generateContent"]),
        "endpoint": "https://generativelanguage.googleapis.com/v1beta",
        "network_access": True,
        "credential_fields": json.dumps([
            {"key": "api_key", "label": "Gemini API Key", "type": "password",
             "help": "Create a key in Google AI Studio; desktop OAuth sessions are not imported."}
        ]),
    },
    {
        "name": "Azure OpenAI",
        "connector_type": "azure_openai",
        "category": "AI / LLM",
        "description": (
            "Azure OpenAI Service — GPT-4o, GPT-4 Turbo, and o1 models hosted in your "
            "Azure subscription. Data stays within your Azure tenant. Supports private "
            "endpoints for zero-internet-egress deployments. Required for enterprise "
            "customers with data-residency requirements."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["chat.completions", "embeddings"]),
        "approved_scopes":  json.dumps(["chat.completions", "embeddings"]),
        "endpoint": "https://<your-resource>.openai.azure.com",
        "network_access": True,
        "credential_fields": json.dumps([
            {"key": "api_key",    "label": "Azure OpenAI API Key",    "type": "password"},
            {"key": "endpoint",   "label": "Azure Endpoint URL",      "type": "text",
             "help": "e.g. https://my-resource.openai.azure.com"},
            {"key": "deployment", "label": "Deployment Name",         "type": "text",
             "help": "e.g. gpt-4o"},
        ]),
    },

    # ══════════════════════════════════════════════════════════════════
    # DEV & COLLABORATION  (5)
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "GitHub",
        "connector_type": "github",
        "category": "Dev & Collaboration",
        "description": (
            "GitHub — source code, pull requests, and Actions workflows. "
            "ArcClaw's supply chain scanner audits dependencies and detects secrets "
            "accidentally committed to repos. Read-only access."
        ),
        "status": "approved", "risk_level": "medium",
        "requested_scopes": json.dumps(["repo:read", "security_events:read", "actions:read"]),
        "approved_scopes":  json.dumps(["repo:read", "security_events:read"]),
        "endpoint": "https://api.github.com",
        "network_access": True,
    },
    {
        "name": "GitLab",
        "connector_type": "gitlab",
        "category": "Dev & Collaboration",
        "description": (
            "GitLab — source code management, CI/CD pipelines, and security scanning. "
            "DevClaw ingests SAST/DAST findings, dependency scan results, "
            "and pipeline security signals for developer risk scoring."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["read_api", "read_repository", "read_security_findings"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://gitlab.com/api/v4",
        "network_access": True,
    },
    {
        "name": "Slack",
        "connector_type": "slack",
        "category": "Dev & Collaboration",
        "description": (
            "Slack — real-time alerts and approval notifications. RegentClaw sends "
            "blocked event alerts, pending approval requests, and daily risk summaries "
            "to configured channels. Outbound only — no message reading."
        ),
        "status": "approved", "risk_level": "low",
        "requested_scopes": json.dumps(["chat:write", "channels:read", "incoming-webhook"]),
        "approved_scopes":  json.dumps(["chat:write", "incoming-webhook"]),
        "endpoint": "https://slack.com/api",
        "network_access": True,
    },
    {
        "name": "Microsoft Teams",
        "connector_type": "ms_teams",
        "category": "Dev & Collaboration",
        "description": (
            "Microsoft Teams — enterprise chat and collaboration. Sends security alerts, "
            "approval requests, and daily risk digests to Teams channels via webhooks. "
            "No message reading — outbound adaptive card notifications only."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["ChannelMessage.Send", "Chat.ReadWrite"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://graph.microsoft.com/v1.0/teams",
        "network_access": True,
    },
    {
        "name": "Email / SMTP",
        "connector_type": "email",
        "category": "Dev & Collaboration",
        "description": (
            "SMTP delivery for verified email sign-in codes, security alerts, and approval notifications. "
            "Credentials are encrypted locally and outbound delivery is enabled only after connector approval."
        ),
        "status": "pending", "risk_level": "medium",
        "requested_scopes": json.dumps(["email:send"]),
        "approved_scopes": json.dumps([]),
        "endpoint": "smtp://configured-by-owner",
        "network_access": True,
    },
    {
        "name": "Jira",
        "connector_type": "jira",
        "category": "Dev & Collaboration",
        "description": (
            "Jira — ticketing for approval workflows and incident response. "
            "When RegentClaw requires approval for a blocked action, it "
            "auto-creates a Jira ticket linked to the event ID and policy triggered."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["issues:write", "projects:read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://{your-org}.atlassian.net/rest/api/3",
        "network_access": True,
    },

    # ══════════════════════════════════════════════════════════════════
    # THREAT INTEL & VULNERABILITY  (4)
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "Tenable.io",
        "connector_type": "tenable",
        "category": "Threat Intel & Vuln",
        "description": (
            "Tenable.io — vulnerability management and exposure assessment. "
            "Pulls asset vulnerability scores to enrich identity and connector risk "
            "profiles. High-CVE assets automatically trigger elevated risk scores."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["vulns.read", "assets.read", "scanners.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://cloud.tenable.com",
        "network_access": True,
    },
    {
        "name": "Qualys VMDR",
        "connector_type": "qualys",
        "category": "Threat Intel & Vuln",
        "description": (
            "Qualys Vulnerability Management, Detection & Response — VM, policy "
            "compliance, and web application scanning. Feeds CVE data and asset "
            "vulnerability state into ExposureClaw risk scoring."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["assets.read", "vulnerabilities.read", "compliance.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://qualysapi.qualys.com/qps/rest/3.0",
        "network_access": True,
    },
    {
        "name": "VirusTotal",
        "connector_type": "virustotal",
        "category": "Threat Intel & Vuln",
        "description": (
            "VirusTotal — malware intelligence and file/URL/IP reputation. "
            "Used by ThreatClaw and ArcClaw to enrich IoC lookups, validate "
            "suspicious file hashes, and check domain reputation in real time."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["file.read", "url.read", "ip_address.read", "domain.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://www.virustotal.com/api/v3",
        "network_access": True,
    },
    {
        "name": "Recorded Future",
        "connector_type": "recorded_future",
        "category": "Threat Intel & Vuln",
        "description": (
            "Recorded Future — AI-driven threat intelligence platform. "
            "Enriches ThreatClaw with actor profiles, malware families, CVE intel, "
            "and real-time risk scores for IPs, domains, hashes, and vulnerabilities."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["intellicards.read", "alerts.read", "risklists.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.recordedfuture.com/v2",
        "network_access": True,
    },

    # ══════════════════════════════════════════════════════════════════
    # ALERTING  (2 — kept separate from Dev/Collab)
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "PagerDuty",
        "connector_type": "pagerduty",
        "category": "Dev & Collaboration",
        "description": (
            "PagerDuty — on-call alerting for critical security events. "
            "High-severity blocks and isolation events trigger PagerDuty incidents "
            "to the on-call security engineer immediately."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["incidents.write", "services.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.pagerduty.com",
        "network_access": True,
    },

    # ══════════════════════════════════════════════════════════════════
    # COMPLIANCE & GRC  (3)
    # ══════════════════════════════════════════════════════════════════

    {
        "name": "Drata",
        "connector_type": "drata",
        "category": "Compliance & GRC",
        "description": (
            "Drata — continuous compliance automation for SOC 2, ISO 27001, HIPAA, PCI. "
            "RegentClaw pushes control evidence and policy decisions to Drata, "
            "automating evidence collection for compliance frameworks."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["controls.read", "evidence.write", "monitors.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://public-api.drata.com",
        "network_access": True,
    },
    {
        "name": "Vanta",
        "connector_type": "vanta",
        "category": "Compliance & GRC",
        "description": (
            "Vanta — automated security and compliance. Monitors controls in real time "
            "and collects evidence for SOC 2, ISO 27001, HIPAA, and GDPR. "
            "RegentClaw findings feed directly into Vanta's control evidence store."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["tests.read", "evidence.write", "integrations.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://api.vanta.com/v1",
        "network_access": True,
    },
    {
        "name": "ServiceNow",
        "connector_type": "servicenow",
        "category": "Compliance & GRC",
        "description": (
            "ServiceNow GRC — governance, risk, and compliance platform. "
            "Used for policy exception management, risk register updates, "
            "and audit-ready evidence requests from ComplianceClaw workflows."
        ),
        "status": "pending", "risk_level": "low",
        "requested_scopes": json.dumps(["incident.write", "risk.write", "compliance.read"]),
        "approved_scopes":  json.dumps([]),
        "endpoint": "https://{your-org}.service-now.com/api/now",
        "network_access": True,
    },
]


# ── Add trust scores from risk + status ───────────────────────────────────────

for c in CONNECTORS:
    c["trust_score"] = _ts(c["risk_level"], c["status"])
    c.setdefault("shell_access", False)
    c.setdefault("filesystem_access", False)
    c.setdefault("credential_ref", None)


# ── Seed function ─────────────────────────────────────────────────────────────

async def seed(reset: bool = False):
    from sqlalchemy import select, delete
    async with AsyncSessionLocal() as db:

        if reset:
            await db.execute(delete(Connector))
            await db.commit()
            print("  RESET  All existing connectors cleared.\n")

        added = updated = 0

        for c in CONNECTORS:
            existing = await db.execute(select(Connector).where(Connector.name == c["name"]))
            row = existing.scalar_one_or_none()

            if row:
                for k, v in c.items():
                    if hasattr(row, k):
                        setattr(row, k, v)
                print(f"  UPDATE  {c['category']:<25} {c['name']}")
                updated += 1
            else:
                connector = Connector(
                    name=c["name"],
                    connector_type=c["connector_type"],
                    category=c.get("category"),
                    description=c.get("description"),
                    status=ConnectorStatus(c["status"]),
                    risk_level=ConnectorRisk(c["risk_level"]),
                    trust_score=c.get("trust_score", 70.0),
                    requested_scopes=c.get("requested_scopes"),
                    approved_scopes=c.get("approved_scopes"),
                    endpoint=c.get("endpoint"),
                    credential_ref=c.get("credential_ref"),
                    network_access=c.get("network_access", False),
                    shell_access=c.get("shell_access", False),
                    filesystem_access=c.get("filesystem_access", False),
                )
                db.add(connector)
                print(f"  ADD     {c['category']:<25} {c['name']}")
                added += 1

        await db.commit()

        # Summary
        cats: dict[str, int] = {}
        for c in CONNECTORS:
            cats[c["category"]] = cats.get(c["category"], 0) + 1

        print(f"\nDone — {added} added, {updated} updated. Total: {len(CONNECTORS)} connectors.\n")
        print("By category:")
        for cat, count in sorted(cats.items()):
            print(f"  {cat:<30} {count}")
        print(f"\n  {'TOTAL':<30} {len(CONNECTORS)}")


if __name__ == "__main__":
    reset_flag = "--reset" in sys.argv
    asyncio.run(seed(reset_flag))
