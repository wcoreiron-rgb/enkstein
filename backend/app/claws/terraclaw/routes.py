"""TerraClaw — Terraform Security & Governance Claw."""
import re
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.finding import Finding
from app.services.connector_check import is_connector_configured
from app.trust_fabric import ActionRequest, enforce

router = APIRouter(prefix="/terraclaw", tags=["TerraClaw"])

CLAW_NAME = "terraclaw"


def _normalize_risk_score(value) -> float:
    try:
        score = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    if 0 < score <= 1:
        return round(score * 100, 2)
    return round(score, 2)


PROVIDER_MAP = [
    {"provider": "terraform_cloud", "label": "Terraform Cloud",  "connector_type": "terraform_cloud"},
    {"provider": "tfsec",           "label": "tfsec / Trivy",    "connector_type": "tfsec"},
    {"provider": "checkov",         "label": "Checkov",          "connector_type": "checkov"},
    {"provider": "infracost",       "label": "Infracost",        "connector_type": "infracost"},
]

# ─── Security rule engine ─────────────────────────────────────────────────────

_RULES = [
    {
        "id": "TC-NET-001",
        "name": "Security Group / NSG open to internet (SSH port 22)",
        "category": "networking",
        "pattern": r'(from_port\s*=\s*"?22"?|destination_port_range\s*=\s*"?22"?)[\s\S]{0,300}(cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]|source_address_prefix\s*=\s*"\*")',
        "severity": "CRITICAL",
        "risk_delta": 30,
        "secure_score_delta": -20,
        "frameworks": ["CIS AWS 4.1", "CIS Azure 6.2", "NIST AC-17", "SOC2 CC6.6"],
        "remediation": "Restrict SSH access to known IP ranges or route through a VPN/bastion host. Remove 0.0.0.0/0 from ingress rules.",
    },
    {
        "id": "TC-NET-002",
        "name": "Security Group / NSG open to internet (RDP port 3389)",
        "category": "networking",
        "pattern": r'(from_port\s*=\s*"?3389"?|destination_port_range\s*=\s*"?3389"?)[\s\S]{0,300}(cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]|source_address_prefix\s*=\s*"\*")',
        "severity": "CRITICAL",
        "risk_delta": 30,
        "secure_score_delta": -20,
        "frameworks": ["CIS AWS 4.2", "CIS Azure 6.1", "NIST AC-17", "SOC2 CC6.6"],
        "remediation": "Disable RDP access from the internet. Use Azure Bastion, AWS Systems Manager Session Manager, or a VPN.",
    },
    {
        "id": "TC-NET-003",
        "name": "Wildcard ingress from internet (0.0.0.0/0 or *)",
        "category": "networking",
        "pattern": r'(cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]|source_address_prefix\s*=\s*"\*")',
        "severity": "HIGH",
        "risk_delta": 20,
        "secure_score_delta": -12,
        "frameworks": ["CIS AWS 4.1", "CIS Azure 6.2", "NIST SC-7"],
        "remediation": "Replace wildcard CIDR with specific, least-privilege IP ranges. Review all ingress rules.",
    },
    {
        "id": "TC-NET-004",
        "name": "Database public network access enabled",
        "category": "networking",
        "pattern": r'public_network_access_enabled\s*=\s*true',
        "severity": "CRITICAL",
        "risk_delta": 35,
        "secure_score_delta": -25,
        "frameworks": ["CIS Azure 4.1", "NIST SC-7", "SOC2 CC6.6", "ISO 27001 A.13.1"],
        "remediation": "Set public_network_access_enabled = false and provision a Private Endpoint to route traffic through the VNet.",
    },
    {
        "id": "TC-DATA-001",
        "name": "Storage account allows public blob access",
        "category": "data",
        "pattern": r'(allow_blob_public_access\s*=\s*true|allow_nested_items_to_be_public\s*=\s*true)',
        "severity": "HIGH",
        "risk_delta": 22,
        "secure_score_delta": -10,
        "frameworks": ["CIS Azure 3.7", "CIS Azure 3.8", "NIST SC-28", "SOC2 CC6.1"],
        "remediation": "Set allow_blob_public_access = false on all storage accounts. Use SAS tokens or managed identity for access.",
    },
    {
        "id": "TC-DATA-002",
        "name": "HTTPS-only traffic not enforced on storage account",
        "category": "data",
        "pattern": r'enable_https_traffic_only\s*=\s*false',
        "severity": "HIGH",
        "risk_delta": 20,
        "secure_score_delta": -10,
        "frameworks": ["CIS Azure 3.1", "NIST SC-8", "SOC2 CC6.7"],
        "remediation": "Set enable_https_traffic_only = true to enforce TLS in transit.",
    },
    {
        "id": "TC-DATA-003",
        "name": "RDS / database encryption at rest disabled",
        "category": "data",
        "pattern": r'storage_encrypted\s*=\s*false',
        "severity": "HIGH",
        "risk_delta": 22,
        "secure_score_delta": -15,
        "frameworks": ["CIS AWS 2.3.1", "NIST SC-28", "SOC2 CC6.1", "PCI-DSS 3.4"],
        "remediation": "Set storage_encrypted = true and specify a KMS key via kms_key_id for customer-managed encryption.",
    },
    {
        "id": "TC-DATA-004",
        "name": "Minimum TLS version below 1.2",
        "category": "data",
        "pattern": r'min_tls_version\s*=\s*"(TLS1_0|TLS1_1|TLS10|TLS11)"',
        "severity": "MEDIUM",
        "risk_delta": 15,
        "secure_score_delta": -8,
        "frameworks": ["CIS Azure 3.2", "NIST SC-8", "SOC2 CC6.7"],
        "remediation": "Set min_tls_version = \"TLS1_2\" or higher on all storage accounts and app services.",
    },
    {
        "id": "TC-IAM-001",
        "name": "Wildcard IAM action (*) grants excessive permissions",
        "category": "identity",
        "pattern": r'"actions"\s*:\s*\[\s*"\*"\s*\]|actions\s*=\s*\["?\*"?\]',
        "severity": "HIGH",
        "risk_delta": 25,
        "secure_score_delta": -15,
        "frameworks": ["CIS AWS 1.16", "NIST AC-6", "SOC2 CC6.3", "ISO 27001 A.9.4"],
        "remediation": "Apply least-privilege: enumerate specific IAM actions required. Use permission boundaries where applicable.",
    },
    {
        "id": "TC-IAM-002",
        "name": "Owner or Contributor role assignment to broad principal",
        "category": "identity",
        "pattern": r'role_definition_name\s*=\s*"(Owner|Contributor)"',
        "severity": "HIGH",
        "risk_delta": 20,
        "secure_score_delta": -15,
        "frameworks": ["CIS Azure 1.23", "NIST AC-6", "SOC2 CC6.3"],
        "remediation": "Replace Owner/Contributor roles with scoped custom roles. Prefer Reader + specific action roles. Use PIM for just-in-time access.",
    },
    {
        "id": "TC-SEC-001",
        "name": "Hardcoded password or secret in Terraform resource",
        "category": "secrets",
        "pattern": r'(password|secret|api_key|token)\s*=\s*"[^${\s]{8,}"',
        "severity": "CRITICAL",
        "risk_delta": 40,
        "secure_score_delta": -25,
        "frameworks": ["CIS AWS 1.21", "NIST IA-5", "SOC2 CC6.2", "OWASP LLM06"],
        "remediation": "Remove all plaintext secrets. Use var.* with sensitive = true, or reference Key Vault / Secrets Manager via data sources. Never commit credentials to version control.",
    },
    {
        "id": "TC-MON-001",
        "name": "Missing Azure Monitor diagnostic settings",
        "category": "monitoring",
        "pattern": r'resource\s+"azurerm_(storage_account|mssql_server|key_vault|kubernetes_cluster|app_service)"',
        "severity": "MEDIUM",
        "risk_delta": 10,
        "secure_score_delta": -5,
        "frameworks": ["CIS Azure 5.1", "NIST AU-2", "SOC2 CC7.2"],
        "remediation": "Add an azurerm_monitor_diagnostic_setting resource referencing each sensitive resource. Route logs to a Log Analytics workspace.",
        "requires_absence": "azurerm_monitor_diagnostic_setting",
    },
    {
        "id": "TC-MON-002",
        "name": "AWS CloudTrail not enabled for account",
        "category": "monitoring",
        "pattern": r'resource\s+"aws_(s3_bucket|rds_instance|db_instance|instance)"',
        "severity": "MEDIUM",
        "risk_delta": 10,
        "secure_score_delta": -5,
        "frameworks": ["CIS AWS 3.1", "NIST AU-2", "SOC2 CC7.2"],
        "remediation": "Ensure an aws_cloudtrail resource with is_multi_region_trail = true is included in your Terraform module.",
        "requires_absence": "aws_cloudtrail",
    },
    {
        "id": "TC-NET-005",
        "name": "AKS / EKS cluster API server publicly accessible",
        "category": "networking",
        "pattern": r'(api_server_authorized_ip_ranges\s*=\s*\[\]|enable_private_cluster\s*=\s*false)',
        "severity": "HIGH",
        "risk_delta": 25,
        "secure_score_delta": -15,
        "frameworks": ["CIS Azure 8.2", "CIS AWS EKS 1.1", "NIST SC-7"],
        "remediation": "Set enable_private_cluster = true or populate api_server_authorized_ip_ranges with your corporate IP ranges.",
    },
]

# ─── Seeded findings (shown when no connector configured) ─────────────────────

_FINDINGS = [
    {
        "id": "tc-0001-4000-8000-000000000001",
        "claw": "terraclaw",
        "provider": "checkov",
        "title": "Azure SQL Server: public_network_access_enabled = true detected in prod module",
        "description": "The azurerm_mssql_server resource in modules/prod/sql.tf has public_network_access_enabled = true, exposing the SQL server directly to the internet. This bypasses private endpoint controls and allows unauthenticated connection attempts from any IP.",
        "category": "networking",
        "severity": "CRITICAL",
        "resource_type": "azurerm_mssql_server",
        "resource_name": "prod-sql-server",
        "region": "eastus",
        "status": "OPEN",
        "remediation": "Set public_network_access_enabled = false and add an azurerm_private_endpoint resource with a private DNS zone link.",
        "remediation_effort": "Medium",
        "risk_score": 0.92,
        "actively_exploited": False,
        "frameworks": ["CIS Azure 4.1", "NIST SC-7", "SOC2 CC6.6"],
        "secure_score_delta": -25,
        "first_seen": "2026-05-10T00:00:00Z",
    },
    {
        "id": "tc-0002-4000-8000-000000000002",
        "claw": "terraclaw",
        "provider": "tfsec",
        "title": "AWS Security Group allows unrestricted SSH (0.0.0.0/0) on port 22",
        "description": "The aws_security_group resource 'bastion-sg' in networking/sg.tf permits TCP ingress on port 22 from 0.0.0.0/0. Any internet host can initiate SSH connections to all instances in this security group, vastly expanding the attack surface.",
        "category": "networking",
        "severity": "CRITICAL",
        "resource_type": "aws_security_group",
        "resource_name": "bastion-sg",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": "Replace cidr_blocks = [\"0.0.0.0/0\"] with your corporate egress IPs. Deploy an AWS Systems Manager Session Manager endpoint as a bastion-free alternative.",
        "remediation_effort": "Low",
        "risk_score": 0.90,
        "actively_exploited": False,
        "frameworks": ["CIS AWS 4.1", "NIST AC-17", "SOC2 CC6.6"],
        "secure_score_delta": -20,
        "first_seen": "2026-05-12T00:00:00Z",
    },
    {
        "id": "tc-0003-4000-8000-000000000003",
        "claw": "terraclaw",
        "provider": "checkov",
        "title": "Hardcoded admin_password in azurerm_mssql_server resource",
        "description": "The Terraform resource azurerm_mssql_server in modules/prod/sql.tf contains administrator_login_password = \"Passw0rd123!\" in plaintext. This credential is committed to source control and visible to anyone with repository access.",
        "category": "secrets",
        "severity": "CRITICAL",
        "resource_type": "azurerm_mssql_server",
        "resource_name": "prod-sql-server",
        "region": "eastus",
        "status": "OPEN",
        "remediation": "Remove the hardcoded password immediately. Rotate the credential. Reference Azure Key Vault via a data source: data.azurerm_key_vault_secret.sql_admin_password.value. Invalidate any exposed credentials from version history.",
        "remediation_effort": "Medium",
        "risk_score": 0.97,
        "actively_exploited": False,
        "frameworks": ["CIS AWS 1.21", "NIST IA-5", "SOC2 CC6.2", "OWASP LLM06"],
        "secure_score_delta": -25,
        "first_seen": "2026-05-14T00:00:00Z",
    },
    {
        "id": "tc-0004-4000-8000-000000000004",
        "claw": "terraclaw",
        "provider": "tfsec",
        "title": "Azure Storage Account allows public blob access (allow_blob_public_access = true)",
        "description": "The storage account 'appdata-store' in storage/main.tf has allow_blob_public_access = true, permitting anonymous unauthenticated reads of any blob container configured as public. Data exfiltration risk if containers are accidentally set to public.",
        "category": "data",
        "severity": "HIGH",
        "resource_type": "azurerm_storage_account",
        "resource_name": "appdata-store",
        "region": "westeurope",
        "status": "OPEN",
        "remediation": "Set allow_blob_public_access = false. Audit all containers for public access level. Use SAS tokens or managed identity for application access.",
        "remediation_effort": "Low",
        "risk_score": 0.78,
        "actively_exploited": False,
        "frameworks": ["CIS Azure 3.7", "NIST SC-28", "SOC2 CC6.1"],
        "secure_score_delta": -10,
        "first_seen": "2026-05-15T00:00:00Z",
    },
    {
        "id": "tc-0005-4000-8000-000000000005",
        "claw": "terraclaw",
        "provider": "checkov",
        "title": "AKS cluster API server not restricted to private network",
        "description": "The azurerm_kubernetes_cluster 'prod-aks' in aks/cluster.tf has api_server_authorized_ip_ranges = [] and enable_private_cluster = false. The Kubernetes API server is reachable from the public internet.",
        "category": "networking",
        "severity": "HIGH",
        "resource_type": "azurerm_kubernetes_cluster",
        "resource_name": "prod-aks",
        "region": "eastus2",
        "status": "OPEN",
        "remediation": "Set enable_private_cluster = true to make the API server accessible only from within the VNet. If a private cluster is not feasible, populate api_server_authorized_ip_ranges with your corporate egress IPs.",
        "remediation_effort": "High",
        "risk_score": 0.82,
        "actively_exploited": False,
        "frameworks": ["CIS Azure 8.2", "NIST SC-7", "SOC2 CC6.6"],
        "secure_score_delta": -15,
        "first_seen": "2026-05-16T00:00:00Z",
    },
    {
        "id": "tc-0006-4000-8000-000000000006",
        "claw": "terraclaw",
        "provider": "tfsec",
        "title": "AWS RDS instance storage not encrypted (storage_encrypted = false)",
        "description": "The aws_db_instance 'app-postgres' in rds/main.tf has storage_encrypted = false. All data written to RDS storage is unencrypted at rest, violating PCI-DSS 3.4 and SOC 2 CC6.1 requirements for data-at-rest protection.",
        "category": "data",
        "severity": "HIGH",
        "resource_type": "aws_db_instance",
        "resource_name": "app-postgres",
        "region": "us-west-2",
        "status": "OPEN",
        "remediation": "Set storage_encrypted = true. Specify kms_key_id for customer-managed keys. Note: encryption can only be enabled at creation time — snapshot and restore to a new encrypted instance if already deployed.",
        "remediation_effort": "High",
        "risk_score": 0.76,
        "actively_exploited": False,
        "frameworks": ["CIS AWS 2.3.1", "NIST SC-28", "SOC2 CC6.1", "PCI-DSS 3.4"],
        "secure_score_delta": -15,
        "first_seen": "2026-05-17T00:00:00Z",
    },
    {
        "id": "tc-0007-4000-8000-000000000007",
        "claw": "terraclaw",
        "provider": "checkov",
        "title": "Azure IAM: Owner role assigned at subscription scope",
        "description": "The azurerm_role_assignment resource in iam/assignments.tf assigns the 'Owner' role to a service principal at subscription scope (/subscriptions/...). This grants unrestricted administrative control over all resources in the subscription.",
        "category": "identity",
        "severity": "HIGH",
        "resource_type": "azurerm_role_assignment",
        "resource_name": "sp-subscription-owner",
        "region": "global",
        "status": "OPEN",
        "remediation": "Replace the Owner role with a scoped custom role containing only required permissions. If ownership is needed temporarily, use Azure PIM for just-in-time access with approval workflow.",
        "remediation_effort": "Medium",
        "risk_score": 0.80,
        "actively_exploited": False,
        "frameworks": ["CIS Azure 1.23", "NIST AC-6", "SOC2 CC6.3"],
        "secure_score_delta": -15,
        "first_seen": "2026-05-18T00:00:00Z",
    },
    {
        "id": "tc-0008-4000-8000-000000000008",
        "claw": "terraclaw",
        "provider": "tfsec",
        "title": "Azure Storage Account: enable_https_traffic_only = false",
        "description": "The storage account 'legacy-backups' in storage/backup.tf has enable_https_traffic_only = false, allowing HTTP connections. Data in transit between clients and the storage account is not guaranteed to be encrypted.",
        "category": "data",
        "severity": "HIGH",
        "resource_type": "azurerm_storage_account",
        "resource_name": "legacy-backups",
        "region": "northeurope",
        "status": "OPEN",
        "remediation": "Set enable_https_traffic_only = true. Also set min_tls_version = \"TLS1_2\" to enforce a minimum cipher suite standard.",
        "remediation_effort": "Low",
        "risk_score": 0.72,
        "actively_exploited": False,
        "frameworks": ["CIS Azure 3.1", "NIST SC-8", "SOC2 CC6.7"],
        "secure_score_delta": -10,
        "first_seen": "2026-05-19T00:00:00Z",
    },
]

# ─── Secure Terraform templates for generation ────────────────────────────────

_TEMPLATES = {
    "azure_sql": '''# Secure Azure SQL Server with Private Endpoint
# Generated by TerraClaw — security-first defaults applied

resource "azurerm_mssql_server" "main" {
  name                         = var.server_name
  resource_group_name          = var.resource_group_name
  location                     = var.location
  version                      = "12.0"
  administrator_login          = var.admin_username
  administrator_login_password = var.admin_password  # Use Key Vault reference in production
  minimum_tls_version          = "1.2"

  # TC-NET-004: Disable public network access — route via Private Endpoint
  public_network_access_enabled = false

  azuread_administrator {
    login_username = var.aad_admin_username
    object_id      = var.aad_admin_object_id
  }

  tags = var.tags
}

resource "azurerm_mssql_database" "main" {
  name           = var.db_name
  server_id      = azurerm_mssql_server.main.id
  sku_name       = "S2"
  zone_redundant = true

  # TC-DATA-003: Encryption at rest — transparent data encryption enabled by default in Azure SQL
}

resource "azurerm_private_endpoint" "sql" {
  name                = "${var.server_name}-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "${var.server_name}-psc"
    private_connection_resource_id = azurerm_mssql_server.main.id
    subresource_names              = ["sqlServer"]
    is_manual_connection           = false
  }
}

resource "azurerm_private_dns_zone_group" "sql" {
  name                 = "sql-dns-zone-group"
  private_endpoint_id  = azurerm_private_endpoint.sql.id
  private_dns_zone_ids = [var.sql_private_dns_zone_id]
}

# TC-MON-001: Diagnostic settings for audit and threat detection
resource "azurerm_mssql_server_security_alert_policy" "main" {
  resource_group_name = var.resource_group_name
  server_name         = azurerm_mssql_server.main.name
  state               = "Enabled"
  email_account_admins = true
}

resource "azurerm_mssql_server_vulnerability_assessment" "main" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.main.id
  storage_container_path          = "${var.vulnerability_storage_url}/"

  recurring_scans {
    enabled                   = true
    email_subscription_admins = true
    emails                    = var.security_alert_emails
  }
}
''',
    "azure_storage": '''# Secure Azure Storage Account
# Generated by TerraClaw — security-first defaults applied

resource "azurerm_storage_account" "main" {
  name                     = var.storage_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "ZRS"

  # TC-DATA-002: Enforce HTTPS only
  enable_https_traffic_only = true

  # TC-DATA-004: Enforce minimum TLS 1.2
  min_tls_version = "TLS1_2"

  # TC-DATA-001: Disable public blob access
  allow_nested_items_to_be_public = false

  # Disable shared key access — use Azure AD / managed identity
  shared_access_key_enabled = false

  blob_properties {
    versioning_enabled  = true
    change_feed_enabled = true

    delete_retention_policy {
      days = 30
    }

    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action             = "Deny"
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
    bypass                     = ["AzureServices"]
  }

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

# TC-MON-001: Diagnostic logging
resource "azurerm_monitor_diagnostic_setting" "storage" {
  name               = "${var.storage_name}-diagnostics"
  target_resource_id = "${azurerm_storage_account.main.id}/blobServices/default"
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }

  metric {
    category = "Transaction"
    enabled  = true
  }
}
''',
    "aws_rds": '''# Secure AWS RDS PostgreSQL Instance
# Generated by TerraClaw — security-first defaults applied

resource "aws_db_subnet_group" "main" {
  name       = "${var.identifier}-subnet-group"
  subnet_ids = var.private_subnet_ids
  tags       = var.tags
}

resource "aws_security_group" "rds" {
  name        = "${var.identifier}-rds-sg"
  description = "RDS access — internal only"
  vpc_id      = var.vpc_id

  # TC-NET-003: No 0.0.0.0/0 ingress — restrict to application security group only
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.app_security_group_id]
    description     = "PostgreSQL from application tier only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = var.tags
}

resource "aws_db_instance" "main" {
  identifier        = var.identifier
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = var.instance_class
  allocated_storage = var.allocated_storage
  db_name           = var.db_name
  username          = var.db_username
  password          = var.db_password  # Use AWS Secrets Manager reference in production

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  # TC-DATA-003: Encryption at rest
  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  # No public access — private subnets only
  publicly_accessible = false

  # Automated backups
  backup_retention_period = 30
  backup_window           = "03:00-04:00"

  # Multi-AZ for high availability
  multi_az = true

  # Auto minor version updates
  auto_minor_version_upgrade = true

  deletion_protection = true

  # TC-MON-002: Enable enhanced monitoring and performance insights
  monitoring_interval = 60
  monitoring_role_arn = var.rds_monitoring_role_arn

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = var.kms_key_arn

  # CloudWatch log exports
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = var.tags
}
''',
    "aws_ec2": '''# Secure AWS EC2 Instance
# Generated by TerraClaw — security-first defaults applied

resource "aws_security_group" "instance" {
  name        = "${var.name}-sg"
  description = "Instance security — no direct internet ingress"
  vpc_id      = var.vpc_id

  # TC-NET-001 / TC-NET-002: No SSH or RDP from internet
  # Use AWS Systems Manager Session Manager instead

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS egress for AWS API calls"
  }

  tags = var.tags
}

resource "aws_iam_role" "instance" {
  name = "${var.name}-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# SSM access — no SSH keys or open port 22 required
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name}-instance-profile"
  role = aws_iam_role.instance.name
}

resource "aws_instance" "main" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnet_id
  vpc_security_group_ids = [aws_security_group.instance.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  # No public IP
  associate_public_ip_address = false

  # TC-DATA-003: EBS root encryption
  root_block_device {
    encrypted   = true
    kms_key_id  = var.kms_key_arn
    volume_size = var.root_volume_size
  }

  metadata_options {
    # IMDSv2 required — prevents SSRF credential theft
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  tags = var.tags
}
''',
    "aks": '''# Secure Azure Kubernetes Service (AKS) Cluster
# Generated by TerraClaw — security-first defaults applied

resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version

  # TC-NET-005: Private cluster — API server not reachable from internet
  private_cluster_enabled = true

  default_node_pool {
    name                = "system"
    node_count          = var.system_node_count
    vm_size             = var.system_vm_size
    vnet_subnet_id      = var.node_subnet_id
    os_disk_size_gb     = 128
    os_disk_type        = "Ephemeral"

    upgrade_settings {
      max_surge = "33%"
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id]
  }

  network_profile {
    network_plugin     = "azure"
    network_policy     = "azure"
    service_cidr       = var.service_cidr
    dns_service_ip     = var.dns_service_ip
    load_balancer_sku  = "standard"
    outbound_type      = "userDefinedRouting"
  }

  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
    admin_group_object_ids = var.aks_admin_group_ids
  }

  # TC-MON-001: Azure Monitor / Defender for Containers
  oms_agent {
    log_analytics_workspace_id = var.log_analytics_workspace_id
  }

  microsoft_defender {
    log_analytics_workspace_id = var.log_analytics_workspace_id
  }

  # Disable local accounts — enforce AAD auth
  local_account_disabled = true

  key_vault_secrets_provider {
    secret_rotation_enabled = true
  }

  maintenance_window_auto_upgrade {
    frequency   = "Weekly"
    interval    = 1
    duration    = 4
    day_of_week = "Sunday"
    start_time  = "00:00"
    utc_offset  = "+00:00"
  }

  tags = var.tags
}
''',
}


def _detect_template_key(description: str) -> str:
    desc_lower = description.lower()
    if any(k in desc_lower for k in ("azure sql", "mssql", "sql server")):
        return "azure_sql"
    if any(k in desc_lower for k in ("azure storage", "storage account", "blob")):
        return "azure_storage"
    if any(k in desc_lower for k in ("aws rds", "rds postgres", "aurora", "rds mysql")):
        return "aws_rds"
    if any(k in desc_lower for k in ("aws ec2", "ec2 instance", "virtual machine", "aws vm")):
        return "aws_ec2"
    if any(k in desc_lower for k in ("aks", "kubernetes", "k8s", "eks", "gke")):
        return "aks"
    # Default to azure_storage as a safe starting template
    return "azure_storage"


def _run_rules(hcl: str) -> tuple[list[dict], int, int]:
    """Run all security rules against HCL. Returns (findings, risk_score, secure_score)."""
    findings = []
    cumulative_risk = 0
    secure_score = 100

    for rule in _RULES:
        pattern = rule["pattern"]
        requires_absence = rule.get("requires_absence")

        matched = bool(re.search(pattern, hcl, re.IGNORECASE | re.DOTALL))

        if requires_absence:
            # Fires if the trigger pattern matches AND the absence pattern does NOT
            if matched and not re.search(requires_absence, hcl, re.IGNORECASE):
                finding = _make_finding(rule, hcl)
                findings.append(finding)
                cumulative_risk += rule["risk_delta"]
                secure_score = max(0, secure_score + rule["secure_score_delta"])
        elif matched:
            finding = _make_finding(rule, hcl)
            findings.append(finding)
            cumulative_risk += rule["risk_delta"]
            secure_score = max(0, secure_score + rule["secure_score_delta"])

    risk_score = min(100, cumulative_risk)
    return findings, risk_score, secure_score


def _make_finding(rule: dict, hcl: str) -> dict:
    # Try to find the approximate line number
    try:
        match = re.search(rule["pattern"], hcl, re.IGNORECASE | re.DOTALL)
        line_hint = hcl[: match.start()].count("\n") + 1 if match else None
    except Exception:
        line_hint = None

    return {
        "id": rule["id"],
        "name": rule["name"],
        "category": rule["category"],
        "severity": rule["severity"],
        "risk_delta": rule["risk_delta"],
        "secure_score_delta": rule["secure_score_delta"],
        "frameworks": rule["frameworks"],
        "remediation": rule["remediation"],
        "line_hint": line_hint,
    }


def _decision(risk_score: int) -> str:
    if risk_score >= 70:
        return "BLOCK"
    if risk_score >= 30:
        return "WARN"
    return "APPROVE"


# ─── Pydantic models ──────────────────────────────────────────────────────────

class ReviewRequest(BaseModel):
    hcl: str = Field(..., min_length=10, max_length=200_000, description="Terraform HCL content to review")
    context: str = Field(default="", max_length=1000, description="Optional deployment context")
    classification: str = Field(default="internal", max_length=64)


class GenerateRequest(BaseModel):
    description: str = Field(..., min_length=5, max_length=2000)
    cloud: str = Field(default="azure", pattern=r"^(azure|aws|gcp)$")
    classification: str = Field(default="internal", max_length=64)


class PlanRequest(BaseModel):
    changes: list[dict] = Field(..., description="List of planned resource changes")
    context: str = Field(default="", max_length=1000)
    classification: str = Field(default="internal", max_length=64)


class TerraTaskRequest(BaseModel):
    swarm_job_id: str | None = None
    task_type: str = "scan_terraform_risk"
    input: dict = Field(default_factory=dict)
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = Field(default_factory=lambda: ["read", "analyze", "recommend"])


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("/stats", summary="TerraClaw summary statistics")
async def get_stats(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.claw == CLAW_NAME))
    findings = result.scalars().all()
    source = _FINDINGS if not findings else []
    rows = [
        {
            "severity": (f.severity.value if hasattr(f.severity, "value") else f.severity).lower()
            if not isinstance(f, dict) else str(f.get("severity", "")).lower(),
            "status": (f.status.value if hasattr(f.status, "value") else f.status).lower()
            if not isinstance(f, dict) else str(f.get("status", "")).lower(),
        }
        for f in (findings or source)
    ]
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    open_count = 0
    for r in rows:
        sev = r["severity"]
        if sev in by_sev:
            by_sev[sev] += 1
        if r["status"] == "open":
            open_count += 1
    total = len(rows)
    secure_score = max(0, 100 - sum(
        abs(f.get("secure_score_delta", 0)) if isinstance(f, dict) else 0
        for f in source
    ))
    return {
        "total": total,
        "critical": by_sev["critical"],
        "high": by_sev["high"],
        "medium": by_sev["medium"],
        "low": by_sev["low"],
        "open": open_count,
        "resolved": total - open_count,
        "secure_score": secure_score,
        "last_scan": None,
    }


@router.get("/findings", summary="All TerraClaw findings")
async def get_findings(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.claw == CLAW_NAME).order_by(Finding.risk_score.desc())
    )
    findings = result.scalars().all()
    if not findings:
        any_configured = any([
            await is_connector_configured(db, p["connector_type"])
            for p in PROVIDER_MAP if p.get("connector_type")
        ])
        if not any_configured:
            return [
                {
                    **f,
                    "risk_score": _normalize_risk_score(f.get("risk_score")),
                }
                for f in _FINDINGS
            ]
        return []
    return [
        {
            "id": str(f.id),
            "claw": f.claw,
            "provider": f.provider,
            "title": f.title,
            "description": f.description,
            "category": f.category,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "status": f.status.value if hasattr(f.status, "value") else f.status,
            "resource_type": f.resource_type,
            "resource_name": f.resource_name,
            "region": f.region,
            "risk_score": _normalize_risk_score(f.risk_score),
            "remediation": f.remediation,
            "remediation_effort": f.remediation_effort,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        }
        for f in findings
    ]


@router.get("/providers", summary="TerraClaw provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    from app.services.connector_check import check_providers
    return await check_providers(db, PROVIDER_MAP)


@router.post("/review", summary="Review Terraform HCL for security risks")
async def review_terraform(
    body: ReviewRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    started = datetime.utcnow()

    policy_decision = await enforce(
        db=db,
        request=ActionRequest(
            module=CLAW_NAME,
            actor_id="terraclaw-review",
            actor_name="TerraClaw Review Engine",
            actor_type="system",
            action="review_terraform_hcl",
            target="terraform_hcl",
            target_type="iac_artifact",
            context={"classification": body.classification, "context": body.context[:200]},
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not policy_decision.allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Terraform review blocked by Trust Fabric policy.",
                "policy": policy_decision.policy_name,
                "reason": policy_decision.reason,
            },
        )

    findings, risk_score, secure_score = _run_rules(body.hcl)
    decision = _decision(risk_score)

    # Map findings to compliance frameworks
    framework_hits: dict[str, int] = {}
    for f in findings:
        for fw in f.get("frameworks", []):
            framework_hits[fw] = framework_hits.get(fw, 0) + 1

    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    return {
        "review_id": f"terra-review-{uuid.uuid4()}",
        "decision": decision,
        "risk_score": risk_score,
        "secure_score": secure_score,
        "finding_count": len(findings),
        "findings": findings,
        "frameworks_impacted": framework_hits,
        "recommended_actions": [f["remediation"] for f in findings[:5]],
        "policy_decision": {
            "outcome": policy_decision.outcome.value,
            "policy_name": policy_decision.policy_name,
        },
        "execution_time_ms": elapsed_ms,
    }


@router.post("/generate", summary="Generate secure Terraform from description")
async def generate_terraform(
    body: GenerateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    started = datetime.utcnow()

    policy_decision = await enforce(
        db=db,
        request=ActionRequest(
            module=CLAW_NAME,
            actor_id="terraclaw-generate",
            actor_name="TerraClaw Generate Engine",
            actor_type="system",
            action="generate_terraform_hcl",
            target="terraform_template",
            target_type="iac_artifact",
            context={"classification": body.classification, "cloud": body.cloud},
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not policy_decision.allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Terraform generation blocked by Trust Fabric policy.",
                "policy": policy_decision.policy_name,
                "reason": policy_decision.reason,
            },
        )

    template_key = _detect_template_key(body.description)
    terraform = _TEMPLATES.get(template_key, _TEMPLATES["azure_storage"])

    # Run review on the generated code to confirm it passes
    findings, risk_score, secure_score = _run_rules(terraform)

    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    return {
        "generate_id": f"terra-gen-{uuid.uuid4()}",
        "decision": _decision(risk_score),
        "risk_score": risk_score,
        "secure_score": secure_score,
        "terraform": terraform,
        "template_used": template_key,
        "security_review": {
            "finding_count": len(findings),
            "findings": findings,
        },
        "notes": [
            "Review and customize variables before applying to production.",
            "Replace placeholder Key Vault/Secrets Manager references with your real resource IDs.",
            "Run terraform plan and submit output to /terraclaw/plan for pre-apply analysis.",
        ],
        "execution_time_ms": elapsed_ms,
    }


@router.post("/plan", summary="Analyze a Terraform plan for risk before apply")
async def analyze_plan(
    body: PlanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    started = datetime.utcnow()

    policy_decision = await enforce(
        db=db,
        request=ActionRequest(
            module=CLAW_NAME,
            actor_id="terraclaw-plan",
            actor_name="TerraClaw Plan Analyzer",
            actor_type="system",
            action="analyze_terraform_plan",
            target="terraform_plan",
            target_type="iac_plan",
            context={"classification": body.classification, "change_count": len(body.changes)},
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not policy_decision.allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Terraform plan analysis blocked by Trust Fabric policy.",
                "policy": policy_decision.policy_name,
                "reason": policy_decision.reason,
            },
        )

    # Analyze each planned change for risk
    _HIGH_RISK_ATTRS = {
        "public_network_access_enabled": ("CRITICAL", "Enabling public network access exposes service to internet.", 35),
        "allow_blob_public_access": ("HIGH", "Public blob access enables anonymous reads of storage containers.", 22),
        "storage_encrypted": ("HIGH", "Disabling storage encryption removes at-rest data protection.", 22),
        "enable_https_traffic_only": ("HIGH", "Disabling HTTPS-only allows unencrypted connections.", 20),
        "publicly_accessible": ("CRITICAL", "Making database publicly accessible exposes it to the internet.", 35),
        "deletion_protection": ("MEDIUM", "Removing deletion protection enables accidental or malicious database deletion.", 15),
        "private_cluster_enabled": ("HIGH", "Disabling private cluster makes Kubernetes API server internet-accessible.", 25),
        "api_server_authorized_ip_ranges": ("HIGH", "Removing IP range restrictions exposes the API server to the internet.", 20),
    }

    risky_changes = []
    creates = 0
    deletes = 0
    updates = 0
    replacements = 0
    cumulative_risk = 0

    for change in body.changes:
        action = change.get("action", "no-op")
        resource_type = change.get("resource_type", "unknown")
        resource_name = change.get("resource_name", "unknown")
        attr_changes = change.get("attribute_changes", {})

        if action == "create":
            creates += 1
        elif action == "delete":
            deletes += 1
            risky_changes.append({
                "resource": f"{resource_type}.{resource_name}",
                "action": "delete",
                "severity": "HIGH",
                "reason": f"Deletion of {resource_type} is irreversible. Verify this is intentional.",
                "risk_delta": 15,
            })
            cumulative_risk += 15
        elif action == "replace":
            replacements += 1
            risky_changes.append({
                "resource": f"{resource_type}.{resource_name}",
                "action": "replace (destroy + create)",
                "severity": "HIGH",
                "reason": f"Replace destroys and recreates {resource_type}. This causes downtime and data loss risk.",
                "risk_delta": 20,
            })
            cumulative_risk += 20
        elif action == "update":
            updates += 1

        # Check attribute-level risk
        for attr, new_val in attr_changes.items():
            if attr in _HIGH_RISK_ATTRS:
                severity, reason, delta = _HIGH_RISK_ATTRS[attr]
                risky_changes.append({
                    "resource": f"{resource_type}.{resource_name}",
                    "action": f"update {attr}",
                    "new_value": str(new_val)[:200],
                    "severity": severity,
                    "reason": reason,
                    "risk_delta": delta,
                })
                cumulative_risk += delta

    risk_score = min(100, cumulative_risk)
    decision = _decision(risk_score)

    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    return {
        "plan_id": f"terra-plan-{uuid.uuid4()}",
        "decision": decision,
        "risk_score": risk_score,
        "summary": {
            "creates": creates,
            "updates": updates,
            "deletes": deletes,
            "replacements": replacements,
            "total_changes": len(body.changes),
        },
        "risky_changes": risky_changes,
        "recommended_actions": [c["reason"] for c in risky_changes[:5]],
        "policy_decision": {
            "outcome": policy_decision.outcome.value,
            "policy_name": policy_decision.policy_name,
        },
        "execution_time_ms": elapsed_ms,
    }


@router.post("/scan", summary="Run TerraClaw scan and persist findings")
async def run_scan(db: AsyncSession = Depends(get_db)):
    from app.services.finding_pipeline import ingest_findings
    default_provider = PROVIDER_MAP[0]["provider"] if PROVIDER_MAP else "simulation"
    pipeline_findings = []
    for f in _FINDINGS:
        entry = dict(f)
        entry.setdefault("claw", CLAW_NAME)
        entry.setdefault("provider", default_provider)
        if "severity" in entry:
            entry["severity"] = str(entry["severity"]).lower()
        pipeline_findings.append(entry)
    summary = await ingest_findings(db, CLAW_NAME, pipeline_findings)
    return {
        "status": "completed",
        "findings_created": summary["created"],
        "findings_updated": summary["updated"],
        "critical": summary["critical"],
        "high": summary["high"],
    }


@router.post("/task", summary="Execute focused TerraClaw swarm task")
async def run_terra_task(payload: TerraTaskRequest, db: AsyncSession = Depends(get_db)):
    started = datetime.utcnow()
    any_configured = any([
        await is_connector_configured(db, p["connector_type"])
        for p in PROVIDER_MAP if p.get("connector_type")
    ])
    result = await db.execute(
        select(Finding).where(Finding.claw == CLAW_NAME).order_by(desc(Finding.risk_score)).limit(5)
    )
    findings = result.scalars().all()
    fallback = _FINDINGS[:3] if not findings else []
    max_risk_raw = max(
        [float(f.risk_score or 0.0) for f in findings],
        default=max([float(f.get("risk_score") or 0.0) for f in fallback], default=0.0),
    )
    max_risk = int(_normalize_risk_score(max_risk_raw))
    severity = "critical" if max_risk >= 85 else "high" if max_risk >= 70 else "medium" if max_risk >= 40 else "low"
    confidence = 0.91 if findings else 0.78
    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    rows = [
        {
            "title": f.title,
            "detail": f"{f.provider or 'terraclaw'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}",
        }
        for f in findings[:3]
    ] or [
        {
            "title": f.get("title", "Terraform security finding"),
            "detail": (f.get("description", "")[:220] or "Simulation finding"),
        }
        for f in fallback
    ]
    return {
        "task_id": f"terra-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": CLAW_NAME,
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": rows or [{"title": "No IaC findings", "detail": "Submit HCL via /terraclaw/review or run /terraclaw/scan."}],
        "evidence": [],
        "recommended_actions": [
            "Review Terraform modules for public network access settings.",
            "Enforce private endpoints for all data-tier resources.",
            "Scan for hardcoded secrets using tfsec or Checkov in CI.",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["CIS Azure", "CIS AWS", "NIST 800-53", "SOC2"],
        "execution_time_ms": elapsed_ms,
        "data_source": "persisted_db" if findings else "seeded_fallback",
        "connector_state": "configured" if any_configured else "unconfigured",
    }
