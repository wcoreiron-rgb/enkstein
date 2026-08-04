import secrets as _secrets
from pydantic_settings import BaseSettings
from typing import Optional

# Known insecure default keys — reject these in production
_INSECURE_DEFAULTS = frozenset({
    "change-me-in-production-use-a-long-random-string",
    "dev-secret-key-change-in-production",
    "secret",
    "changeme",
})


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Enkstein"
    APP_VERSION: str = "0.7.1"
    DEBUG: bool = False

    # Production data policy.
    #
    # Capability Nodes fall back to labelled demonstration findings when no
    # connector is configured, so a new install is explorable rather than a
    # wall of empty screens. In a real deployment that fallback is a liability:
    # an operator can mistake sample data for their own estate. Setting this
    # makes every node return nothing instead, so anything on screen came from
    # an authenticated connector.
    # Production is evidence-first by default. Demonstration findings remain
    # available only when an operator deliberately opts into a local walkthrough.
    REQUIRE_LIVE_DATA: bool = True

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://regentclaw:regentclaw@db:5432/regentclaw"
    DATABASE_URL_SYNC: str = "postgresql://regentclaw:regentclaw@db:5432/regentclaw"
    # Compose writes these conventional variables into the shared .env file.
    # The application uses DATABASE_URL above, but accepting the values here
    # keeps local pytest/imports compatible with the packaged runtime instead
    # of rejecting a valid Compose environment as unknown settings.
    POSTGRES_USER: str | None = None
    POSTGRES_PASSWORD: str | None = None
    POSTGRES_DB: str | None = None

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"
    REDIS_PASSWORD: str | None = None

    # Security
    SECRET_KEY: str = "change-me-in-production-use-a-long-random-string"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    OWNER_SETUP_TTL_SECONDS: int = 900
    EMAIL_AUTH_ENABLED: bool = True
    EMAIL_AUTH_CODE_TTL_SECONDS: int = 600
    EMAIL_AUTH_MAX_ATTEMPTS: int = 5
    EMAIL_AUTH_SMTP_HOST: str = ""
    EMAIL_AUTH_SMTP_PORT: int = 587
    EMAIL_AUTH_SMTP_USERNAME: str = ""
    EMAIL_AUTH_SMTP_PASSWORD: str = ""
    EMAIL_AUTH_FROM: str = ""
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = ""

    # Native host Brain Bridge. The bridge owns vendor subscription sessions;
    # containers receive only a short-lived invocation surface and never tokens.
    BRAIN_BRIDGE_URL: str = ""
    BRAIN_BRIDGE_SECRET: str = ""
    BRAIN_BRIDGE_TIMEOUT_SECONDS: int = 180

    # Cowork/Cortex turn streaming bounds. The SSE turn stream emits a heartbeat
    # every HEARTBEAT seconds while the governed turn is still running so proxies
    # and browsers never see an idle connection, and it is hard-bounded by
    # DEADLINE so a stalled Brain can never leave the client streaming forever —
    # the deadline always resolves to a terminal turn_timeout event.
    WORKSPACE_STREAM_HEARTBEAT_SECONDS: float = 10.0
    # AI endpoint rate limiting (OWASP LLM04). Applies per authenticated
    # identity to governed turn, stream, and research endpoints.
    AI_RATE_LIMIT_WINDOW_SECONDS: int = 60
    AI_RATE_LIMIT_MAX_REQUESTS: int = 20
    # OAuth client ID for GitHub device-code sign-in. GitHub has no first-party
    # public client, so interactive sign-in stays disabled until a deployment
    # supplies its own OAuth app; credential configuration still works.
    GITHUB_OAUTH_CLIENT_ID: str = ""
    # Browser sign-in (authorization code + PKCE) client IDs. These vendors
    # publish no first-party public client, so a deployment registers a native
    # OAuth app once. PKCE means no client secret is ever needed or stored.
    GITLAB_OAUTH_CLIENT_ID: str = ""
    GOOGLE_OAUTH_CLIENT_ID: str = ""
    SLACK_OAUTH_CLIENT_ID: str = ""
    ATLASSIAN_OAUTH_CLIENT_ID: str = ""
    DATADOG_OAUTH_CLIENT_ID: str = ""
    SNYK_OAUTH_CLIENT_ID: str = ""
    PAGERDUTY_OAUTH_CLIENT_ID: str = ""
    SALESFORCE_OAUTH_CLIENT_ID: str = ""
    WORKSPACE_STREAM_DEADLINE_SECONDS: float = 180.0
    # Browser Companion sessions run at human/page speed and need a longer
    # deadline than a direct API/CLI Brain call; this stays comfortably above
    # brain_bridge._BROWSER_BRAIN_TIMEOUT_SECONDS (890s) so the per-Brain
    # timeout there always resolves before this outer turn deadline would.
    # A large multi-file/full-app generation can legitimately run ChatGPT/
    # Claude/Gemini for several minutes; 900s (15 minutes) gives real headroom
    # for that without leaving a genuinely-stuck session streaming forever.
    WORKSPACE_STREAM_BROWSER_DEADLINE_SECONDS: float = 900.0

    def validate_security(self) -> None:
        """Call at startup. Raises if running in production with insecure defaults."""
        if not self.DEBUG and self.SECRET_KEY in _INSECURE_DEFAULTS:
            raise RuntimeError(
                "SECRET_KEY is set to an insecure default value. "
                "Generate a strong key: python -c \"import secrets; print(secrets.token_hex(32))\" "
                "and set it as the SECRET_KEY environment variable."
            )
        if not self.DEBUG and len(self.SECRET_KEY) < 32:
            raise RuntimeError(
                f"SECRET_KEY is too short ({len(self.SECRET_KEY)} chars). "
                "Use at least 32 characters."
            )

    # CORS
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000", "http://frontend:3000"]

    # AGT provider feature flags (opt-in rollout)
    AGT_VERSION_MODE: str = "v1_compat"
    AGT_ENABLE_AGENT_MESH: bool = False
    AGT_ENABLE_E2E_MESSAGING: bool = False
    AGT_ENABLE_MCP_GATEWAY: bool = False
    AGT_ENABLE_SHADOW_DISCOVERY: bool = False

    # SRE policy primitives (SLO/error budget/circuit breaker)
    SRE_POLICY_ENABLED: bool = True
    SRE_WINDOW_MINUTES: int = 30
    SRE_ERROR_BUDGET: float = 0.10
    SRE_CIRCUIT_BREAKER_THRESHOLD: float = 0.50
    SRE_CIRCUIT_BREAKER_OPEN_SECONDS: int = 120
    SRE_MIN_SAMPLES: int = 5

    class Config:
        env_file = ".env"


settings = Settings()
