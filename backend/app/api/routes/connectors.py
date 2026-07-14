"""CoreOS — Connector Registry routes."""
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID
from pydantic import BaseModel
from typing import Optional

from app.core.database import get_db
from app.models.connector import Connector, ConnectorStatus
from app.schemas.connector import ConnectorCreate, ConnectorRead, ConnectorUpdate
from app.services import secrets_manager
from app.services.connector_tester import test_connector
from app.trust_fabric import enforce, ActionRequest

logger = logging.getLogger("connectors")

router = APIRouter(prefix="/connectors", tags=["CoreOS — Connectors"])


# ── List / Get / Create / Update ──────────────────────────────────────────────

@router.get("", response_model=list[ConnectorRead])
async def list_connectors(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Connector))
    connectors = result.scalars().all()
    # Annotate each with is_configured (from secrets store, not DB)
    configured = set(secrets_manager.list_configured())
    for c in connectors:
        c.__dict__["is_configured"] = str(c.id) in configured
    return connectors


@router.post("", response_model=ConnectorRead, status_code=201)
async def register_connector(payload: ConnectorCreate, db: AsyncSession = Depends(get_db)):
    connector = Connector(**payload.model_dump())
    db.add(connector)
    await db.commit()
    await db.refresh(connector)
    return connector


@router.get("/health-summary", summary="Health status for all connectors (no live test)")
async def get_health_summary(db: AsyncSession = Depends(get_db)):
    """
    Returns a health overview for all connectors based on DB state.
    Does NOT call external APIs — uses trust_score, status, and is_configured
    to derive a health status without making outbound connections.
    """
    result = await db.execute(select(Connector))
    connectors = result.scalars().all()

    def _health(c: Connector) -> str:
        if c.status.value == "blocked":     return "blocked"
        if c.status.value == "restricted":  return "restricted"
        if not secrets_manager.is_configured(str(c.id)): return "unconfigured"
        if c.status.value == "approved":    return "healthy"
        if c.status.value == "pending":     return "pending"
        return "unknown"

    items = [
        {
            "id":               str(c.id),
            "name":             c.name,
            "connector_type":   c.connector_type,
            "category":         c.category,
            "status":           c.status.value,
            "health":           _health(c),
            "is_configured":    secrets_manager.is_configured(str(c.id)),
            "trust_score":      c.trust_score,
            "risk_level":       c.risk_level.value,
            "last_used":        c.last_used.isoformat() if c.last_used else None,
        }
        for c in connectors
    ]

    return {
        "total":        len(items),
        "healthy":      sum(1 for i in items if i["health"] == "healthy"),
        "unconfigured": sum(1 for i in items if i["health"] == "unconfigured"),
        "pending":      sum(1 for i in items if i["health"] == "pending"),
        "blocked":      sum(1 for i in items if i["health"] == "blocked"),
        "configured":   sum(1 for i in items if i["is_configured"]),
        "connectors":   items,
    }


@router.get("/{connector_id}", response_model=ConnectorRead)
async def get_connector(connector_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Connector).where(Connector.id == UUID(connector_id)))
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    connector.__dict__["is_configured"] = secrets_manager.is_configured(connector_id)
    return connector


@router.patch("/{connector_id}", response_model=ConnectorRead)
async def update_connector(connector_id: str, payload: ConnectorUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Connector).where(Connector.id == UUID(connector_id)))
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(connector, field, value)
    await db.commit()
    await db.refresh(connector)
    connector.__dict__["is_configured"] = secrets_manager.is_configured(connector_id)
    return connector


# ── Configure (credentials) ───────────────────────────────────────────────────

class ConfigureRequest(BaseModel):
    credentials: dict[str, str]          # field_name → value (never stored raw)
    actor_id:    Optional[str] = "portal-user"
    actor_name:  Optional[str] = "Portal User"


class ConfigureResponse(BaseModel):
    connector_id:  str
    is_configured: bool
    credential_hint: str                  # masked, e.g. "sk-...abc"
    policy_decision: str                  # allowed / blocked / requires_approval
    policy_name:     Optional[str]
    block_reason:    Optional[str]
    message:         str


@router.post("/{connector_id}/configure", response_model=ConfigureResponse)
async def configure_connector(
    connector_id: str,
    payload: ConfigureRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Store encrypted credentials for a connector.
    Zero Trust flow:
      1. Load connector from registry
      2. Run Trust Fabric enforcement (policy check)
      3. If allowed → encrypt + store credentials
      4. Update connector status to 'pending' (admin approves to activate)
    """
    # 1. Load connector
    result = await db.execute(select(Connector).where(Connector.id == UUID(connector_id)))
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    # 2. Trust Fabric enforcement
    request = ActionRequest(
        module="coreos",
        actor_id=payload.actor_id,
        actor_name=payload.actor_name,
        actor_type="human",
        action="configure_connector",
        target=connector.connector_type,
        target_type="connector",
        context={
            "connector_type": connector.connector_type,
            "risk_level": connector.risk_level.value,
            "shell_access": connector.shell_access,
            "network_access": connector.network_access,
            "is_sensitive": connector.risk_level.value in ("high", "critical"),
        },
    )
    decision = await enforce(db, request)

    if not decision.allowed:
        return ConfigureResponse(
            connector_id=connector_id,
            is_configured=False,
            credential_hint="",
            policy_decision="blocked",
            policy_name=decision.policy_name,
            block_reason=decision.reason,
            message=f"Blocked by Trust Fabric: {decision.reason}",
        )

    # 3. Encrypt and store credentials
    hint = secrets_manager.store_credential(connector_id, payload.credentials)

    # 4. Mark connector as pending (credentials saved, awaiting approval)
    if connector.status == ConnectorStatus.BLOCKED:
        pass  # don't auto-promote blocked connectors
    elif connector.status == ConnectorStatus.APPROVED:
        pass  # already approved — stay approved
    else:
        # Auto-approve low-risk connectors (medium/low risk_level)
        if connector.risk_level.value in ("low", "medium"):
            connector.status = ConnectorStatus.APPROVED
            logger.info(
                "Connector %s (%s) auto-approved (risk_level=%s)",
                connector.name, connector.connector_type, connector.risk_level.value,
            )
        else:
            connector.status = ConnectorStatus.PENDING
        await db.commit()

    # 5. Trigger auto-scan in the background for the affected claws
    from app.services.claw_registry import get_claws_for_connector
    affected_claws = get_claws_for_connector(connector.connector_type)
    if affected_claws and connector.status == ConnectorStatus.APPROVED:
        from app.services.auto_scanner import trigger_scans_for_connector
        from app.core.database import AsyncSessionLocal

        async def _run_auto_scan():
            """Run background scan with a fresh DB session."""
            try:
                async with AsyncSessionLocal() as scan_db:
                    await trigger_scans_for_connector(
                        scan_db,
                        connector.connector_type,
                        connector_id,
                        actor=payload.actor_id or "portal-user",
                    )
            except Exception as exc:
                logger.error("Background auto-scan failed for %s: %s", connector.connector_type, exc)

        background_tasks.add_task(_run_auto_scan)
        logger.info(
            "Auto-scan scheduled for connector %s → claws: %s",
            connector.connector_type, affected_claws,
        )

    status_msg = connector.status.value
    pending_note = "" if status_msg == "approved" else " Ask an admin to approve this connector to activate scanning."
    return ConfigureResponse(
        connector_id=connector_id,
        is_configured=True,
        credential_hint=hint,
        policy_decision="allowed" if decision.allowed else "blocked",
        policy_name=decision.policy_name,
        block_reason=None,
        message=f"Credentials saved securely. Connector status: {status_msg}.{pending_note}",
    )


# ── Test connection ───────────────────────────────────────────────────────────

class TestResponse(BaseModel):
    connector_id: str
    connector_type: str
    success: bool
    message: str
    detail: Optional[str] = None
    verification_level: str = "none"


@router.post("/{connector_id}/test", response_model=TestResponse)
async def test_connector_connection(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Test live connectivity for a connector using stored credentials.
    Always read-only — no writes or side effects.
    """
    result = await db.execute(select(Connector).where(Connector.id == UUID(connector_id)))
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    creds = secrets_manager.get_credential(connector_id)
    if not creds:
        return TestResponse(
            connector_id=connector_id,
            connector_type=connector.connector_type,
            success=False,
            message="No credentials configured — use the Configure button first",
        )

    result_obj = await test_connector(
        connector_type=connector.connector_type,
        creds=creds,
        endpoint=connector.endpoint or "",
    )

    # Only provider-specific credential or local-service verification can establish
    # connector trust. Generic endpoint reachability and format checks cannot.
    was_pending = connector.status == ConnectorStatus.PENDING
    establishes_trust = result_obj.verification_level in {"credential", "service"}
    if result_obj.success and establishes_trust and was_pending:
        connector.status = ConnectorStatus.APPROVED
        await db.commit()
        logger.info("Connector %s auto-approved after successful test", connector.connector_type)

        # Trigger auto-scan since the connector just became active
        from app.services.claw_registry import get_claws_for_connector
        affected_claws = get_claws_for_connector(connector.connector_type)
        if affected_claws:
            from app.services.auto_scanner import trigger_scans_for_connector
            from app.core.database import AsyncSessionLocal
            import asyncio

            async def _run_post_test_scan():
                try:
                    async with AsyncSessionLocal() as scan_db:
                        await trigger_scans_for_connector(scan_db, connector.connector_type, connector_id)
                except Exception as exc:
                    logger.error("Post-test auto-scan failed: %s", exc)

            asyncio.create_task(_run_post_test_scan())

    return TestResponse(
        connector_id=connector_id,
        connector_type=connector.connector_type,
        success=result_obj.success,
        message=result_obj.message,
        detail=result_obj.detail,
        verification_level=result_obj.verification_level,
    )


# ── Clear credentials ─────────────────────────────────────────────────────────

@router.delete("/{connector_id}/credentials", status_code=204)
async def clear_credentials(connector_id: str, db: AsyncSession = Depends(get_db)):
    """Remove stored credentials for a connector (does not delete the connector record)."""
    result = await db.execute(select(Connector).where(Connector.id == UUID(connector_id)))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Connector not found")
    secrets_manager.delete_credential(connector_id)


# ── Credential field definitions (frontend uses these to render the form) ─────

CREDENTIAL_FIELDS: dict[str, list[dict]] = {
    # AI / LLM
    "openai":      [{"name": "api_key", "label": "API Key", "type": "secret", "hint": "sk-..."}],
    "anthropic":   [{"name": "api_key", "label": "API Key", "type": "secret", "hint": "sk-ant-..."}],
    "ollama":      [{"name": "base_url", "label": "Base URL", "type": "text", "hint": "http://localhost:11434"}],
    # Identity
    "entra_id": [
        {"name": "tenant_id",     "label": "Tenant ID",     "type": "text",   "hint": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
        {"name": "client_id",     "label": "Client ID",     "type": "text",   "hint": "App registration client ID"},
        {"name": "client_secret", "label": "Client Secret", "type": "secret", "hint": "App registration secret"},
    ],
    "okta": [
        {"name": "domain",    "label": "Okta Domain", "type": "text",   "hint": "yourorg.okta.com"},
        {"name": "api_token", "label": "API Token",   "type": "secret", "hint": "00..."},
    ],
    "ping_identity": [
        {"name": "env_id",    "label": "Environment ID", "type": "text",   "hint": "PingOne environment UUID"},
        {"name": "client_id", "label": "Client ID",      "type": "text",   "hint": "Worker app client ID"},
        {"name": "client_secret", "label": "Client Secret", "type": "secret", "hint": "Worker app secret"},
    ],
    "auth0": [
        {"name": "domain",        "label": "Auth0 Domain",    "type": "text",   "hint": "yourorg.auth0.com"},
        {"name": "client_id",     "label": "Client ID",       "type": "text",   "hint": "Management API client ID"},
        {"name": "client_secret", "label": "Client Secret",   "type": "secret", "hint": "Management API secret"},
    ],
    "cyberark": [
        {"name": "base_url",  "label": "CyberArk URL",  "type": "text",   "hint": "https://cyberark.yourorg.com"},
        {"name": "username",  "label": "Username",       "type": "text",   "hint": "CyberArk API user"},
        {"name": "password",  "label": "Password",       "type": "secret", "hint": "CyberArk API password"},
    ],
    "hashicorp_vault": [
        {"name": "vault_url",   "label": "Vault URL",    "type": "text",   "hint": "https://vault.yourorg.com:8200"},
        {"name": "token",       "label": "Vault Token",  "type": "secret", "hint": "hvs.XXXXXX"},
    ],
    "duo": [
        {"name": "api_host",       "label": "API Host",      "type": "text",   "hint": "api-XXXXXXXX.duosecurity.com"},
        {"name": "integration_key","label": "Integration Key","type": "text",   "hint": "DI..."},
        {"name": "secret_key",     "label": "Secret Key",    "type": "secret", "hint": "Duo secret key"},
    ],
    # SIEM
    "sentinel": [
        {"name": "workspace_id", "label": "Workspace ID",  "type": "text",   "hint": "Log Analytics workspace ID"},
        {"name": "primary_key",  "label": "Primary Key",   "type": "secret", "hint": "Workspace primary key"},
    ],
    "splunk": [
        {"name": "host",  "label": "Splunk Host",  "type": "text",   "hint": "splunk.yourorg.com"},
        {"name": "token", "label": "HEC Token",    "type": "secret", "hint": "Splunk HTTP Event Collector token"},
    ],
    "qradar": [
        {"name": "host",    "label": "QRadar Host",  "type": "text",   "hint": "qradar.yourorg.com"},
        {"name": "api_key", "label": "SEC Token",    "type": "secret", "hint": "QRadar SEC token"},
    ],
    "elastic": [
        {"name": "cloud_id", "label": "Cloud ID",    "type": "text",   "hint": "deployment:dXMt..."},
        {"name": "api_key",  "label": "API Key",     "type": "secret", "hint": "base64-encoded API key"},
    ],
    "datadog": [
        {"name": "api_key", "label": "API Key",      "type": "secret", "hint": "Datadog API key"},
        {"name": "app_key", "label": "App Key",      "type": "secret", "hint": "Datadog application key"},
    ],
    "sumologic": [
        {"name": "access_id",  "label": "Access ID",  "type": "text",   "hint": "Sumo Logic access ID"},
        {"name": "access_key", "label": "Access Key", "type": "secret", "hint": "Sumo Logic access key"},
    ],
    # Endpoint
    "crowdstrike": [
        {"name": "client_id",     "label": "Client ID",     "type": "text",   "hint": "OAuth2 client ID"},
        {"name": "client_secret", "label": "Client Secret", "type": "secret", "hint": "OAuth2 client secret"},
    ],
    "defender_endpoint": [
        {"name": "tenant_id",     "label": "Tenant ID",     "type": "text",   "hint": "Azure tenant ID"},
        {"name": "client_id",     "label": "Client ID",     "type": "text",   "hint": "App client ID"},
        {"name": "client_secret", "label": "Client Secret", "type": "secret", "hint": "App secret"},
    ],
    "sentinelone": [
        {"name": "base_url", "label": "Console URL", "type": "text",   "hint": "https://yourorg.sentinelone.net"},
        {"name": "api_token","label": "API Token",   "type": "secret", "hint": "SentinelOne API token"},
    ],
    "carbonblack": [
        {"name": "org_key",  "label": "Org Key",    "type": "text",   "hint": "Carbon Black org key"},
        {"name": "api_id",   "label": "API ID",     "type": "text",   "hint": "Carbon Black API ID"},
        {"name": "api_key",  "label": "API Key",    "type": "secret", "hint": "Carbon Black API key"},
    ],
    "tanium": [
        {"name": "host",     "label": "Tanium Host", "type": "text",   "hint": "tanium.yourorg.com"},
        {"name": "api_key",  "label": "API Key",     "type": "secret", "hint": "Tanium API token"},
    ],
    # Cloud
    "aws_iam": [
        {"name": "access_key_id",     "label": "Access Key ID",     "type": "text",   "hint": "AKIA..."},
        {"name": "secret_access_key", "label": "Secret Access Key", "type": "secret", "hint": "AWS secret"},
        {"name": "region",            "label": "Region",            "type": "text",   "hint": "us-east-1"},
    ],
    "azure_arm": [
        {"name": "tenant_id",       "label": "Tenant ID",       "type": "text",   "hint": "Azure tenant ID"},
        {"name": "client_id",       "label": "Client ID",       "type": "text",   "hint": "Service principal ID"},
        {"name": "client_secret",   "label": "Client Secret",   "type": "secret", "hint": "Service principal secret"},
        {"name": "subscription_id", "label": "Subscription ID", "type": "text",   "hint": "Azure subscription ID"},
    ],
    "gcp_iam": [
        {"name": "service_account_json", "label": "Service Account JSON", "type": "secret", "hint": "Paste your GCP service account JSON key"},
    ],
    "gcp_scc": [
        {"name": "service_account_json", "label": "Service Account JSON", "type": "secret", "hint": "Paste your GCP service account JSON key"},
        {"name": "organization_id",      "label": "Organization ID",      "type": "text",   "hint": "GCP organization ID"},
    ],
    "wiz": [
        {"name": "client_id",     "label": "Client ID",     "type": "text",   "hint": "Wiz service account client ID"},
        {"name": "client_secret", "label": "Client Secret", "type": "secret", "hint": "Wiz service account secret"},
    ],
    # Network
    "paloalto": [
        {"name": "host",     "label": "Panorama Host", "type": "text",   "hint": "panorama.yourorg.com"},
        {"name": "api_key",  "label": "API Key",       "type": "secret", "hint": "Panorama API key"},
    ],
    "zscaler": [
        {"name": "cloud",     "label": "Zscaler Cloud", "type": "text",   "hint": "zsapi.zscaler.net"},
        {"name": "api_key",   "label": "API Key",       "type": "secret", "hint": "Zscaler API key"},
        {"name": "username",  "label": "Username",      "type": "text",   "hint": "redacted_user"},
        {"name": "password",  "label": "Password",      "type": "secret", "hint": "Admin password"},
    ],
    "cloudflare": [
        {"name": "api_token",  "label": "API Token",  "type": "secret", "hint": "Cloudflare API token"},
        {"name": "account_id", "label": "Account ID", "type": "text",   "hint": "Cloudflare account ID"},
    ],
    "cisco_umbrella": [
        {"name": "api_key",    "label": "API Key",    "type": "secret", "hint": "Umbrella management API key"},
        {"name": "api_secret", "label": "API Secret", "type": "secret", "hint": "Umbrella management API secret"},
    ],
    "netskope": [
        {"name": "tenant",    "label": "Tenant Name", "type": "text",   "hint": "yourorg (from yourorg.goskope.com)"},
        {"name": "api_token", "label": "REST API Token", "type": "secret", "hint": "Netskope REST API v2 token"},
    ],
    # Data
    "purview": [
        {"name": "tenant_id",     "label": "Tenant ID",     "type": "text",   "hint": "Azure tenant ID"},
        {"name": "client_id",     "label": "Client ID",     "type": "text",   "hint": "App registration ID"},
        {"name": "client_secret", "label": "Client Secret", "type": "secret", "hint": "App secret"},
    ],
    "varonis": [
        {"name": "host",     "label": "Varonis Host", "type": "text",   "hint": "varonis.yourorg.com"},
        {"name": "api_key",  "label": "API Key",      "type": "secret", "hint": "Varonis API token"},
    ],
    "nightfall": [
        {"name": "api_key",  "label": "API Key",  "type": "secret", "hint": "Nightfall API key"},
    ],
    "bigid": [
        {"name": "host",     "label": "BigID Host", "type": "text",   "hint": "yourorg.bigid.cloud"},
        {"name": "token",    "label": "Token",      "type": "secret", "hint": "BigID refresh token"},
    ],
    # Dev / Collab
    "github":      [{"name": "personal_access_token", "label": "Personal Access Token", "type": "secret", "hint": "github_pat_..."}],
    "gitlab":      [{"name": "personal_access_token", "label": "Personal Access Token", "type": "secret", "hint": "glpat-..."}],
    "slack": [
        {"name": "bot_token",   "label": "Bot Token",   "type": "secret", "hint": "xoxb-..."},
        {"name": "webhook_url", "label": "Webhook URL", "type": "text",   "hint": "https://hooks.slack.com/... (optional)"},
    ],
    "ms_teams":    [{"name": "webhook_url", "label": "Incoming Webhook URL", "type": "text", "hint": "https://yourorg.webhook.office.com/..."}],
    "email": [
        {"name": "smtp_host", "label": "SMTP Host", "type": "text", "hint": "smtp.example.com"},
        {"name": "smtp_port", "label": "SMTP Port", "type": "number", "hint": "587"},
        {"name": "username", "label": "SMTP Username", "type": "text", "hint": "mailer@example.com"},
        {"name": "password", "label": "SMTP Password", "type": "secret", "hint": "App-specific password"},
        {"name": "from_addr", "label": "From Address", "type": "text", "hint": "security@example.com"},
    ],
    "jira": [
        {"name": "domain",    "label": "Jira Domain", "type": "text",   "hint": "yourorg.atlassian.net"},
        {"name": "email",     "label": "Email",       "type": "text",   "hint": "redacted_user"},
        {"name": "api_token", "label": "API Token",   "type": "secret", "hint": "Atlassian API token"},
    ],
    "pagerduty":   [{"name": "routing_key", "label": "Events API v2 Routing Key", "type": "secret", "hint": "32-char routing key"}],
    "servicenow": [
        {"name": "instance", "label": "Instance Name", "type": "text",   "hint": "yourorg (from yourorg.service-now.com)"},
        {"name": "username", "label": "Username",      "type": "text",   "hint": "API service account"},
        {"name": "password", "label": "Password",      "type": "secret", "hint": "API service account password"},
    ],
    # Threat Intel / Vuln
    "tenable": [
        {"name": "access_key", "label": "Access Key", "type": "text",   "hint": "Tenable access key"},
        {"name": "secret_key", "label": "Secret Key", "type": "secret", "hint": "Tenable secret key"},
    ],
    "qualys": [
        {"name": "username", "label": "Username", "type": "text",   "hint": "Qualys API username"},
        {"name": "password", "label": "Password", "type": "secret", "hint": "Qualys API password"},
        {"name": "platform", "label": "Platform URL", "type": "text", "hint": "qualysapi.qualys.com"},
    ],
    "virustotal":       [{"name": "api_key", "label": "API Key", "type": "secret", "hint": "VirusTotal API key"}],
    "recorded_future":  [{"name": "api_token", "label": "API Token", "type": "secret", "hint": "Recorded Future API token"}],
    # Compliance
    "drata":  [{"name": "api_key", "label": "API Key", "type": "secret", "hint": "Drata public API key"}],
    "vanta":  [{"name": "api_token", "label": "API Token", "type": "secret", "hint": "Vanta API token"}],
}


@router.get("/{connector_id}/fields")
async def get_credential_fields(connector_id: str, db: AsyncSession = Depends(get_db)):
    """Return the credential fields needed for this connector type."""
    result = await db.execute(select(Connector).where(Connector.id == UUID(connector_id)))
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    fields = CREDENTIAL_FIELDS.get(connector.connector_type, [
        {"name": "api_key", "label": "API Key / Token", "type": "secret", "hint": ""}
    ])
    is_conf = secrets_manager.is_configured(connector_id)

    return {
        "connector_id":   connector_id,
        "connector_type": connector.connector_type,
        "connector_name": connector.name,
        "fields":         fields,
        "is_configured":  is_conf,
        "risk_level":     connector.risk_level.value,
        "status":         connector.status.value,
    }
