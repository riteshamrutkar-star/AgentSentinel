import os
from typing import List, Optional
from urllib.parse import quote_plus
from pydantic import ConfigDict
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """
    Centralized application configuration for AgentSentinel.
    Supports development, testing, and production environments with strict validation.
    """
    model_config = ConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "AgentSentinel"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"  # "development", "testing", "production"
    DEBUG: bool = True
    TESTING: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"
    STRUCTURED_LOGGING: bool = False

    # Secret Management & Authentication
    API_SECRET_KEY: str = "insecure-dev-secret-key-change-in-production-min32"
    ALLOW_DEV_ANONYMOUS: bool = True  # Labeled dev identity; strictly denied in production

    # CORS Allowed Origins
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # API Security & Request Limits
    MAX_REQUEST_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB payload limit
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 10

    # Distributed State & Redis Settings (Phase 0.9)
    DISTRIBUTED_STATE_ENABLED: bool = False
    RATE_LIMIT_DISTRIBUTED: bool = False
    REDIS_HOST: str = "127.0.0.1"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    REDIS_URL: Optional[str] = None
    REDIS_CONNECT_TIMEOUT: float = 2.0
    REDIS_SOCKET_TIMEOUT: float = 2.0
    REDIS_PREFIX: str = "agentsentinel:"

    # Operator Identity Federation / OIDC (Phase 0.9)
    OIDC_ENABLED: bool = False
    OIDC_ISSUER: Optional[str] = None
    OIDC_CLIENT_ID: Optional[str] = None
    OIDC_CLIENT_SECRET: Optional[str] = None
    OIDC_JWKS_URI: Optional[str] = None
    OIDC_ROLE_CLAIM: str = "roles"
    OIDC_ALGORITHMS: List[str] = ["RS256"]

    # Security Event Webhooks & SIEM (Phase 0.9)
    WEBHOOK_ENABLED: bool = False
    WEBHOOK_URLS: List[str] = []
    WEBHOOK_SIGNING_SECRET: str = "default-webhook-secret-min32-chars-long-here"
    WEBHOOK_TIMEOUT_SECONDS: float = 5.0
    WEBHOOK_MAX_RETRIES: int = 3
    SIEM_ENABLED: bool = False
    SIEM_TYPE: str = "generic_http"  # "generic_http" or "datadog"
    SIEM_ENDPOINT: Optional[str] = None
    SIEM_API_KEY: Optional[str] = None

    # Multi-Tenancy / Namespace (Phase 0.9)
    DEFAULT_NAMESPACE: str = "default"

    # PostgreSQL Database Configuration & Connection Pool Bounds
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_HOST: str = "127.0.0.1"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "agentsentinel"
    DATABASE_URL: Optional[str] = None

    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800

    @property
    def sync_database_url(self) -> str:
        """Returns configured DATABASE_URL or constructs PostgreSQL connection URL with URL-encoded credentials."""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        
        encoded_password = quote_plus(self.POSTGRES_PASSWORD)
        encoded_user = quote_plus(self.POSTGRES_USER)
        return f"postgresql://{encoded_user}:{encoded_password}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    @property
    def masked_database_url(self) -> str:
        """Returns database URL with credential password masked for safe logging."""
        encoded_user = quote_plus(self.POSTGRES_USER)
        return f"postgresql://{encoded_user}:***@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    @property
    def is_production(self) -> bool:
        """Returns True if the current deployment environment is production."""
        return self.ENVIRONMENT.lower() == "production"

    def validate_production_configuration(self) -> None:
        """
        Enforces strict fail-closed production readiness checks.
        Must be called during application startup when ENVIRONMENT == 'production'.
        """
        if not self.is_production:
            return

        errors = []
        if self.DEBUG:
            errors.append("DEBUG must be False in production.")
        if self.POSTGRES_PASSWORD in ("", "postgres"):
            errors.append("Default or blank POSTGRES_PASSWORD is not permitted in production.")
        if self.API_SECRET_KEY == "insecure-dev-secret-key-change-in-production-min32" or len(self.API_SECRET_KEY) < 32:
            errors.append("API_SECRET_KEY must be a cryptographically strong secret of at least 32 characters.")
        if self.ALLOW_DEV_ANONYMOUS:
            errors.append("ALLOW_DEV_ANONYMOUS must be False in production.")
        for origin in self.CORS_ORIGINS:
            if "*" in origin or "localhost" in origin or "127.0.0.1" in origin:
                errors.append(f"Insecure CORS origin '{origin}' not permitted in production.")

        if errors:
            raise ValueError(f"Production Configuration Validation Failed:\n - " + "\n - ".join(errors))


# Global settings instance
settings = Settings()
