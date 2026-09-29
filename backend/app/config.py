"""
Application Configuration using Pydantic Settings
"""
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """ShieldX SOC Backend Application Settings."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "ShieldX SOC Enclave Backend"
    app_version: str = "1.0.0"
    app_description: str = "Backend API for ShieldX Security Operations Center & Hardware Data Diode"
    debug: bool = False

    # Server settings
    host: str = "127.0.0.1"
    port: int = 8000

    # CORS configuration - strictly configurable, NO wildcard allow_origins=["*"]
    allowed_origins: Union[List[str], str] = [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:8081",
        "http://127.0.0.1:8081",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]

    # Database URLs
    sync_db_url: str = "sqlite:///./shieldx.db"
    async_db_url: str = "sqlite+aiosqlite:///./shieldx.db"

    # Telemetry streaming default interval in ms
    ws_batch_rate_ms: int = 1000

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [orig.strip() for orig in v.split(",") if orig.strip()]
        return v


settings = Settings()
