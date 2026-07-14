"""Shared pytest fixtures for RegentClaw backend tests."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Use the app's core Base so all models are registered
from app.core.database import Base, get_db
from app.database import get_db as get_db_sync
from main import app

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def db_session():
    """
    Provide an in-memory SQLite session for each test.
    All tables are created fresh and dropped after the test.
    """
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)

    # Import all models so they are registered with Base.metadata
    import app.models  # noqa: F401 — registers models without core.database Base
    from app.models.agent import Agent, Schedule, AgentRun, PlatformSettings  # noqa
    from app.models.policy_pack import PolicyPack  # noqa
    from app.models.workflow import Workflow, WorkflowRun  # noqa
    from app.models.finding import Finding  # noqa
    from app.models.trigger import EventTrigger  # noqa
    from app.models.memory import IncidentMemory, AssetMemory, TenantMemory, RiskTrendSnapshot  # noqa
    from app.models.skill_pack import SkillPack  # noqa
    from app.models.exchange import ExchangePublisher, ExchangePackage, ExchangeInstallRecord  # noqa
    from app.models.channel_gateway import ChannelMessage, ChannelIdentity, ChannelConfig  # noqa
    from app.models.exec_channels import ExecRequest, CredentialBrokerEntry, ProductionGate  # noqa
    from app.models.entity_profile import EntityProfile, BehaviorEvent  # noqa
    from app.models.customclaw import CustomClawDefinition  # noqa
    from app.models.audit import AuditLog  # noqa
    from app.models.marcellus import (  # noqa
        CapabilityNodeRuntime,
        NodeCheckpoint,
        PlexusMessage,
        ReflexDefinition,
        ReflexExecution,
        RegenerationRun,
    )
    from app.claws.arcclaw.models import AIEvent  # noqa
    from app.claws.identityclaw.models import IdentityRiskEvent, PrivilegedAction  # noqa

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    AsyncTestSession = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with AsyncTestSession() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
def db_session_sync():
    """
    Provide a shared in-memory SQLite sync session for sync routes that depend on
    app.database.get_db.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SyncTestSession = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    session = SyncTestSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest_asyncio.fixture
async def client(db_session, db_session_sync):
    """
    Provide an httpx AsyncClient wired to the FastAPI app with:
      - DB dependency overridden to the in-memory test session.
      - Auth dependency overridden to bypass JWT validation.
    """
    async def override_get_db():
        yield db_session

    def override_get_db_sync():
        yield db_session_sync

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_db_sync] = override_get_db_sync

    # Bypass JWT authentication for tests
    try:
        from app.core.deps import get_current_user
        app.dependency_overrides[get_current_user] = lambda: {
            "id": "test-user",
            "sub": "test-user",
            "email": "redacted_user",
            "role": "admin",
        }
    except ImportError:
        pass

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
