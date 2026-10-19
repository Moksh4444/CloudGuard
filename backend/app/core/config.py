"""
Application configuration for CloudGuard.
"""
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "CloudGuard — Cloud Security & Network Troubleshooting Platform"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    DATABASE_URL: str = "sqlite:///./cloudguard.db"

    # CORS configuration
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # SSRF Protection Boundaries
    # By default, private/internal IPs, AWS metadata, and loopback are strictly blocked
    ALLOW_PRIVATE_IPS: bool = False

    # Network timeouts and limits
    DEFAULT_TIMEOUT_SECONDS: float = 6.0
    MAX_REDIRECTS: int = 5
    MAX_RESPONSE_BYTES: int = 1_048_576  # 1 MB max response body inspection

    # Allowed TCP ports for connectivity diagnostics (prevents arbitrary network port scanning)
    ALLOWED_PORTS: List[int] = [
        21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995,
        3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017
    ]

    # Traceroute configuration
    TRACEROUTE_MAX_HOPS: int = 15
    TRACEROUTE_TIMEOUT_SECONDS: int = 10

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)


settings = Settings()
