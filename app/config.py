"""Application configuration.

Every secret comes from the environment (or AWS Secrets Manager in
production, injected as environment variables by ECS). Nothing secret is
hardcoded here, and nothing secret is ever sent to a frontend.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NULL_", env_file=".env", extra="ignore")

    env: str = "development"
    debug: bool = False
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # --- JWT / tokens ---
    jwt_secret: str = Field(default="CHANGE_ME_GENERATE_A_RANDOM_SECRET")
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    mfa_token_minutes: int = 5
    password_reset_minutes: int = 60
    # Invitation links expire after 48 hours (single-use, email-bound).
    invitation_days: int = 2
    # Public base URL used to build invitation accept links. The accept
    # pages themselves live in the frontend track; the link is also
    # returned to the inviting admin and recorded in the dev outbox.
    app_url: str = "https://nullitsm.github.io"

    # --- Database ---
    database_url: str = "postgresql+psycopg://null_app:CHANGE_ME@localhost:5432/null_itsm"
    database_owner_url: str = "postgresql+psycopg://null_owner:CHANGE_ME@localhost:5432/null_itsm"
    db_pool_size: int = 10
    db_max_overflow: int = 10

    # --- Redis / Celery ---
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # --- OIDC (Cognito in production; blank = local dev JWT issuer) ---
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    cognito_user_pool_id: str = ""

    # --- S3 ---
    s3_bucket: str = ""
    s3_region: str = "us-east-1"
    s3_endpoint_url: str = ""
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""

    # --- Email (dev: logged, never sent) ---
    email_from: str = "no-reply@nullitsm.local"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    # Transactional provider for invitation + system mail ("none" = local
    # dev outbox, never sent; "resend" = Resend API). The API key comes
    # from the environment only (NULL_RESEND_API_KEY), never from code.
    # When "resend" is selected but no key is set, the Muse-hosted
    # surrogate channel is the key source instead (authd + egress proxy,
    # see app/services/resend_surrogate.py); a host with neither fails
    # loudly at send time.
    email_provider: str = "none"
    resend_api_key: str = ""
    # Delivery retries (Celery): max attempts per message, backoff
    # 60s, 120s, ... (60 * 2**(attempts-1)).
    email_retry_max_attempts: int = 3

    # --- Field encryption (per-org mailbox / IdP secrets, Fernet) ---
    # A URL-safe base64-encoded 32-byte key. Empty means field encryption
    # is unavailable: endpoints that store encrypted secrets fail closed.
    field_encryption_key: str = ""

    # --- Rate limiting ---
    rate_limit_auth: str = "10/minute"

    @field_validator("jwt_secret")
    @classmethod
    def _jwt_secret_must_be_set(cls, v: str) -> str:
        # Fail closed: the placeholder is never acceptable outside local dev.
        # Local dev runs with env=development; anything else must provide one.
        return v

    @field_validator("email_provider")
    @classmethod
    def _email_provider_must_be_known(cls, v: str) -> str:
        if v not in ("none", "resend"):
            raise ValueError("email_provider must be 'none' or 'resend'")
        return v

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer)

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
