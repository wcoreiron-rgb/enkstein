"""
RegentClaw — Zero Trust Security Ecosystem
FastAPI Backend Entrypoint
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.deps import get_current_user

# Global rate limiter instance — auth routes attach decorators to this
limiter = Limiter(key_func=get_remote_address)
from app.core.database import engine, Base, AsyncSessionLocal

logger = logging.getLogger("regentclaw")

# Import all models so Alembic/SQLAlchemy discovers them
import app.models  # noqa: F401
from app.claws.arcclaw.models import AIEvent  # noqa: F401
from app.claws.identityclaw.models import IdentityRiskEvent, PrivilegedAction  # noqa: F401
from app.models.agent import Agent, Schedule, AgentRun, PlatformSettings  # noqa: F401
from app.models.policy_pack import PolicyPack  # noqa: F401
from app.models.workflow import Workflow, WorkflowRun  # noqa: F401
from app.models.finding import Finding  # noqa: F401
from app.models.trigger import EventTrigger  # noqa: F401
from app.models.memory import IncidentMemory, AssetMemory, TenantMemory, RiskTrendSnapshot  # noqa: F401
from app.models.skill_pack import SkillPack  # noqa: F401
from app.models.exchange import ExchangePublisher, ExchangePackage, ExchangeInstallRecord  # noqa: F401
from app.models.channel_gateway import ChannelMessage, ChannelIdentity, ChannelConfig  # noqa: F401
from app.models.exec_channels import ExecRequest, CredentialBrokerEntry, ProductionGate  # noqa: F401
from app.models.entity_profile import EntityProfile, BehaviorEvent  # noqa: F401
from app.models.customclaw import CustomClawDefinition  # noqa: F401
from app.models.remediation import RemediationAction, RemediationPlaybook  # noqa: F401
from app.models.swarm import SwarmJob, SwarmTask  # noqa: F401

# Routers
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.policies import router as policies_router
from app.api.routes.connectors import router as connectors_router
from app.api.routes.events import router as events_router
from app.api.routes.audit import router as audit_router
from app.api.routes.agents import router as agents_router
from app.api.routes.schedules import router as schedules_router
from app.api.routes.policy_packs import router as policy_packs_router
from app.api.routes.orchestrations import router as orchestrations_router
from app.api.routes.findings import router as findings_router
from app.api.routes.triggers import router as triggers_router
from app.api.routes.autonomy import router as autonomy_router
from app.api.routes.copilot import router as copilot_router
from app.api.routes.model_router import router as model_router_router
from app.api.routes.memory import router as memory_router
from app.api.routes.skill_packs_v2 import router as skill_packs_v2_router
from app.api.routes.exchange import router as exchange_router
from app.api.routes.channel_gateway import router as channel_gateway_router
from app.api.routes.exec_channels import router as exec_channels_router
from app.api.routes.profiles import router as profiles_router
from app.api.routes.external_agents import router as external_agents_router
from app.api.routes.remote_control import router as remote_control_router
from app.api.routes.ws import router as ws_router
from app.api.routes.auth import router as auth_router
from app.api.routes.trust_fabric import router as trust_fabric_router
from app.claws.arcclaw.routes import router as arcclaw_router
from app.claws.identityclaw.routes import router as identityclaw_router
from app.claws.cloudclaw.routes import router as cloudclaw_router
from app.claws.exposureclaw.routes import router as exposureclaw_router
from app.claws.threatclaw.routes import router as threatclaw_router
from app.claws.netclaw.routes import router as netclaw_router
from app.claws.endpointclaw.routes import router as endpointclaw_router
from app.claws.logclaw.routes import router as logclaw_router
from app.claws.accessclaw.routes import router as accessclaw_router
from app.claws.dataclaw.routes import router as dataclaw_router
from app.claws.appclaw.routes import router as appclaw_router
from app.claws.saasclaw.routes import router as saasclaw_router
from app.claws.configclaw.routes import router as configclaw_router
from app.claws.complianceclaw.routes import router as complianceclaw_router
from app.claws.privacyclaw.routes import router as privacyclaw_router
from app.claws.vendorclaw.routes import router as vendorclaw_router
from app.claws.userclaw.routes import router as userclaw_router
from app.claws.insiderclaw.routes import router as insiderclaw_router
from app.claws.automationclaw.routes import router as automationclaw_router
from app.claws.attackpathclaw.routes import router as attackpathclaw_router
from app.claws.devclaw.routes import router as devclaw_router
from app.claws.intelclaw.routes import router as intelclaw_router
from app.claws.recoveryclaw.routes import router as recoveryclaw_router
from app.claws.releaseclaw.routes import router as releaseclaw_router
from app.claws.customclaw.routes import router as customclaw_router
from app.claws.terraclaw.routes import router as terraclaw_router
from app.api.routes.remediation import router as remediation_router
from app.core.swarm.routes import router as swarm_router
from app.core.modelclaw.routes import router as modelclaw_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Validate security config — raises in production with insecure defaults
    settings.validate_security()

    # Create all tables on startup (dev mode — use Alembic in production)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Start background scan scheduler
    from app.services.auto_scanner import background_scheduler_loop
    scheduler_task = asyncio.create_task(
        background_scheduler_loop(AsyncSessionLocal),
        name="background-scan-scheduler",
    )
    logger.info("Background scan scheduler started")

    yield

    # Shutdown — cancel the scheduler
    scheduler_task.cancel()
    try:
        await scheduler_task
    except asyncio.CancelledError:
        logger.info("Background scan scheduler stopped")


app = FastAPI(
    title="RegentClaw API",
    description="Zero Trust Security Ecosystem — CoreOS, Trust Fabric, ArcClaw, IdentityClaw, Agent Scheduler",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    dependencies=[Depends(get_current_user)],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Wire rate limiter (Finding 12)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Security response headers (Finding 13) ────────────────────────────────────
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]          = "DENY"
        response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]       = "geolocation=(), microphone=(), camera=()"
        response.headers["X-XSS-Protection"]         = "1; mode=block"
        # Only set HSTS when not in DEBUG (not served over HTTP in dev)
        if not settings.DEBUG:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Register all routers under /api/v1
PREFIX = "/api/v1"
app.include_router(dashboard_router, prefix=PREFIX)
app.include_router(policies_router, prefix=PREFIX)
app.include_router(connectors_router, prefix=PREFIX)
app.include_router(events_router, prefix=PREFIX)
app.include_router(audit_router, prefix=PREFIX)
app.include_router(agents_router, prefix=PREFIX)
app.include_router(schedules_router, prefix=PREFIX)
app.include_router(policy_packs_router, prefix=PREFIX)
app.include_router(orchestrations_router, prefix=PREFIX)
app.include_router(findings_router, prefix=PREFIX)
app.include_router(triggers_router, prefix=PREFIX)
app.include_router(autonomy_router, prefix=PREFIX)
app.include_router(copilot_router, prefix=PREFIX)
app.include_router(model_router_router, prefix=PREFIX)
app.include_router(memory_router, prefix=PREFIX)
app.include_router(skill_packs_v2_router, prefix=PREFIX)
app.include_router(exchange_router, prefix=PREFIX)
app.include_router(channel_gateway_router, prefix=PREFIX)
app.include_router(exec_channels_router, prefix=PREFIX)
app.include_router(profiles_router, prefix=PREFIX)
app.include_router(external_agents_router, prefix=PREFIX)
app.include_router(remote_control_router, prefix=PREFIX)
app.include_router(ws_router, prefix=PREFIX)   # WebSocket — no HTTP prefix stripping needed
app.include_router(auth_router, prefix=PREFIX)
app.include_router(trust_fabric_router, prefix=PREFIX)
app.include_router(arcclaw_router, prefix=PREFIX)
app.include_router(identityclaw_router, prefix=PREFIX)
app.include_router(cloudclaw_router, prefix=PREFIX)
app.include_router(exposureclaw_router, prefix=PREFIX)
app.include_router(threatclaw_router, prefix=PREFIX)
app.include_router(netclaw_router, prefix=PREFIX)
app.include_router(endpointclaw_router, prefix=PREFIX)
app.include_router(logclaw_router, prefix=PREFIX)
app.include_router(accessclaw_router, prefix=PREFIX)
app.include_router(dataclaw_router, prefix=PREFIX)
app.include_router(appclaw_router, prefix=PREFIX)
app.include_router(saasclaw_router, prefix=PREFIX)
app.include_router(configclaw_router, prefix=PREFIX)
app.include_router(complianceclaw_router, prefix=PREFIX)
app.include_router(privacyclaw_router, prefix=PREFIX)
app.include_router(vendorclaw_router, prefix=PREFIX)
app.include_router(userclaw_router, prefix=PREFIX)
app.include_router(insiderclaw_router, prefix=PREFIX)
app.include_router(automationclaw_router, prefix=PREFIX)
app.include_router(attackpathclaw_router, prefix=PREFIX)
app.include_router(devclaw_router, prefix=PREFIX)
app.include_router(intelclaw_router, prefix=PREFIX)
app.include_router(recoveryclaw_router, prefix=PREFIX)
app.include_router(releaseclaw_router, prefix=PREFIX)
app.include_router(customclaw_router, prefix=PREFIX)
app.include_router(terraclaw_router, prefix=PREFIX)
app.include_router(remediation_router, prefix=PREFIX)
app.include_router(swarm_router, prefix=PREFIX)
app.include_router(modelclaw_router, prefix=PREFIX)


@app.get("/health")
async def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}
