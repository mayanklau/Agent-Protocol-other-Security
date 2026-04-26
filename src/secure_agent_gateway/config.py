from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Secure Agent Gateway"
    environment: str = "development"
    database_url: str = "sqlite:///./data/secure_agent_gateway.db"
    admin_token: str = Field(default="change-me", min_length=8)
    request_ttl_seconds: int = 300
    allowed_clock_skew_seconds: int = 30
    nonce_ttl_seconds: int = 900
    action_default_approvals: int = 1
    high_risk_action_approvals: int = 2
    critical_risk_action_approvals: int = 3

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SAG_",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
