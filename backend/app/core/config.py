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
    APP_VERSION: str = "0.3.3"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://regentclaw:regentclaw@db:5432/regentclaw"
    DATABASE_URL_SYNC: str = "postgresql://regentclaw:regentclaw@db:5432/regentclaw"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"

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

    # Native host Brain Bridge. The bridge owns vendor subscription sessions;
    # containers receive only a short-lived invocation surface and never tokens.
    BRAIN_BRIDGE_URL: str = ""
    BRAIN_BRIDGE_SECRET: str = ""
    BRAIN_BRIDGE_TIMEOUT_SECONDS: int = 180

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
