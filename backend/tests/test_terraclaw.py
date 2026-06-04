"""TerraClaw — backend unit and integration tests."""
import pytest
from httpx import AsyncClient


# ─── /stats ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_terraclaw_stats(client: AsyncClient):
    r = await client.get("/api/v1/terraclaw/stats")
    assert r.status_code == 200
    d = r.json()
    assert "total" in d
    assert "critical" in d
    assert "secure_score" in d
    assert isinstance(d["secure_score"], int)


# ─── /findings ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_terraclaw_findings_returns_seeded(client: AsyncClient):
    r = await client.get("/api/v1/terraclaw/findings")
    assert r.status_code == 200
    findings = r.json()
    assert isinstance(findings, list)
    # Seeded data has 8 entries when no connector configured
    assert len(findings) >= 1
    f = findings[0]
    assert "title" in f
    assert "severity" in f
    assert "resource_type" in f


# ─── /providers ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_terraclaw_providers(client: AsyncClient):
    r = await client.get("/api/v1/terraclaw/providers")
    assert r.status_code == 200
    providers = r.json()
    assert isinstance(providers, list)
    labels = {p["label"] for p in providers}
    assert "Terraform Cloud" in labels


# ─── /review ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_review_clean_hcl_approves(client: AsyncClient):
    hcl = '''
resource "azurerm_mssql_server" "main" {
  name                          = "my-sql-server"
  resource_group_name           = "my-rg"
  location                      = "eastus"
  version                       = "12.0"
  administrator_login           = var.admin_login
  administrator_login_password  = var.admin_password
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false
}
'''
    r = await client.post("/api/v1/terraclaw/review", json={"hcl": hcl})
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] in ("APPROVE", "WARN", "BLOCK")
    assert "risk_score" in d
    assert "findings" in d
    assert isinstance(d["findings"], list)
    # No TC-NET-004 should fire — public_network_access_enabled = false
    ids = [f["id"] for f in d["findings"]]
    assert "TC-NET-004" not in ids


@pytest.mark.asyncio
async def test_review_public_db_blocks(client: AsyncClient):
    hcl = '''
resource "azurerm_mssql_server" "bad" {
  name                          = "bad-sql"
  resource_group_name           = "my-rg"
  location                      = "eastus"
  version                       = "12.0"
  public_network_access_enabled = true
}
'''
    r = await client.post("/api/v1/terraclaw/review", json={"hcl": hcl})
    assert r.status_code == 200
    d = r.json()
    ids = [f["id"] for f in d["findings"]]
    assert "TC-NET-004" in ids
    assert d["decision"] in ("WARN", "BLOCK")


@pytest.mark.asyncio
async def test_review_hardcoded_password_detected(client: AsyncClient):
    hcl = '''
resource "azurerm_mssql_server" "secret" {
  administrator_login          = "sqladmin"
  administrator_login_password = "Passw0rd123!"
  public_network_access_enabled = false
}
'''
    r = await client.post("/api/v1/terraclaw/review", json={"hcl": hcl})
    assert r.status_code == 200
    d = r.json()
    ids = [f["id"] for f in d["findings"]]
    assert "TC-SEC-001" in ids
    # Hardcoded secret should produce BLOCK or WARN
    assert d["decision"] in ("WARN", "BLOCK")


@pytest.mark.asyncio
async def test_review_open_ssh_detected(client: AsyncClient):
    hcl = '''
resource "aws_security_group" "ssh_open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
    r = await client.post("/api/v1/terraclaw/review", json={"hcl": hcl})
    assert r.status_code == 200
    d = r.json()
    ids = [f["id"] for f in d["findings"]]
    assert "TC-NET-001" in ids or "TC-NET-003" in ids


@pytest.mark.asyncio
async def test_review_owner_role_detected(client: AsyncClient):
    hcl = '''
resource "azurerm_role_assignment" "owner" {
  scope                = "/subscriptions/00000000-0000-0000-0000-000000000000"
  role_definition_name = "Owner"
  principal_id         = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
}
'''
    r = await client.post("/api/v1/terraclaw/review", json={"hcl": hcl})
    assert r.status_code == 200
    d = r.json()
    ids = [f["id"] for f in d["findings"]]
    assert "TC-IAM-002" in ids


@pytest.mark.asyncio
async def test_review_returns_framework_mappings(client: AsyncClient):
    hcl = 'resource "azurerm_mssql_server" "x" { public_network_access_enabled = true }'
    r = await client.post("/api/v1/terraclaw/review", json={"hcl": hcl})
    assert r.status_code == 200
    d = r.json()
    assert "frameworks_impacted" in d
    assert isinstance(d["frameworks_impacted"], dict)


@pytest.mark.asyncio
async def test_review_rejects_empty_hcl(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/review", json={"hcl": "x"})
    # Too short — 422 from pydantic min_length=10
    assert r.status_code == 422


# ─── /generate ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_generate_azure_sql(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/generate", json={
        "description": "Deploy secure Azure SQL with Private Endpoint",
        "cloud": "azure",
    })
    assert r.status_code == 200
    d = r.json()
    assert "terraform" in d
    assert "azurerm_mssql_server" in d["terraform"]
    assert "private_endpoint" in d["terraform"].lower() or "private_endpoint" in d["terraform"]
    # Generated templates use secure defaults — should never BLOCK
    assert d["decision"] in ("APPROVE", "WARN")
    assert d["risk_score"] < 70


@pytest.mark.asyncio
async def test_generate_aws_rds(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/generate", json={
        "description": "AWS RDS PostgreSQL with encryption",
        "cloud": "aws",
    })
    assert r.status_code == 200
    d = r.json()
    assert "aws_db_instance" in d["terraform"]
    assert "storage_encrypted" in d["terraform"]


@pytest.mark.asyncio
async def test_generate_aks_cluster(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/generate", json={
        "description": "Private AKS Kubernetes cluster with Defender",
        "cloud": "azure",
    })
    assert r.status_code == 200
    d = r.json()
    assert "azurerm_kubernetes_cluster" in d["terraform"]
    assert "private_cluster_enabled" in d["terraform"]


@pytest.mark.asyncio
async def test_generate_rejects_bad_cloud(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/generate", json={
        "description": "some resource",
        "cloud": "oracle",
    })
    assert r.status_code == 422


# ─── /plan ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_plan_public_access_blocks(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/plan", json={
        "changes": [
            {
                "action": "update",
                "resource_type": "azurerm_mssql_server",
                "resource_name": "prod-sql",
                "attribute_changes": {"public_network_access_enabled": True},
            }
        ]
    })
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] in ("WARN", "BLOCK")
    assert len(d["risky_changes"]) >= 1
    reasons = [c["action"] for c in d["risky_changes"]]
    assert any("public_network_access_enabled" in a for a in reasons)


@pytest.mark.asyncio
async def test_plan_delete_flags_risk(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/plan", json={
        "changes": [
            {
                "action": "delete",
                "resource_type": "azurerm_key_vault",
                "resource_name": "prod-kv",
                "attribute_changes": {},
            }
        ]
    })
    assert r.status_code == 200
    d = r.json()
    assert len(d["risky_changes"]) >= 1
    assert d["summary"]["deletes"] == 1


@pytest.mark.asyncio
async def test_plan_clean_creates_approves(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/plan", json={
        "changes": [
            {
                "action": "create",
                "resource_type": "azurerm_resource_group",
                "resource_name": "my-rg",
                "attribute_changes": {},
            }
        ]
    })
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "APPROVE"
    assert d["risk_score"] == 0
    assert d["summary"]["creates"] == 1


@pytest.mark.asyncio
async def test_plan_summary_fields_present(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/plan", json={
        "changes": [
            {"action": "create", "resource_type": "azurerm_virtual_network", "resource_name": "vnet", "attribute_changes": {}},
            {"action": "update", "resource_type": "azurerm_subnet", "resource_name": "default", "attribute_changes": {}},
        ]
    })
    assert r.status_code == 200
    d = r.json()
    assert "plan_id" in d
    assert "summary" in d
    assert d["summary"]["creates"] == 1
    assert d["summary"]["updates"] == 1


# ─── /task ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_terraclaw_task(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/task", json={
        "task_type": "scan_terraform_risk",
    })
    assert r.status_code == 200
    d = r.json()
    assert d["claw"] == "terraclaw"
    assert d["status"] == "completed"
    assert "risk_score" in d
    assert "confidence" in d
    assert "findings" in d
    assert "compliance_mappings" in d
    assert "CIS Azure" in d["compliance_mappings"]


@pytest.mark.asyncio
async def test_terraclaw_task_with_swarm_job(client: AsyncClient):
    r = await client.post("/api/v1/terraclaw/task", json={
        "swarm_job_id": "swarm-abc-123",
        "task_type": "scan_terraform_risk",
    })
    assert r.status_code == 200
    d = r.json()
    assert d["swarm_job_id"] == "swarm-abc-123"
