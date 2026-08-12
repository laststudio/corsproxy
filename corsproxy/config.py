from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _csv(name: str, default: str = "", *, lower: bool = False) -> tuple[str, ...]:
    values = tuple(x.strip() for x in os.getenv(name, default).split(",") if x.strip())
    return tuple(x.lower() for x in values) if lower else values


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("CORS_PROXY_HOST", "127.0.0.1")
    port: int = int(os.getenv("CORS_PROXY_PORT", "9800"))
    db_path: Path = Path(os.getenv("CORS_PROXY_DB", "data/corsproxy.db"))
    admin_key: str = os.getenv("CORS_PROXY_ADMIN_KEY", "")
    api_keys: tuple[str, ...] = field(default_factory=lambda: _csv("CORS_PROXY_API_KEYS"))
    allowed_targets: tuple[str, ...] = field(default_factory=lambda: _csv("CORS_PROXY_ALLOWED_TARGETS", lower=True))
    allowed_origins: tuple[str, ...] = field(default_factory=lambda: _csv("CORS_PROXY_ALLOWED_ORIGINS"))
    cf_test_hosts: tuple[str, ...] = field(default_factory=lambda: _csv("CF_TEST_HOSTS", lower=True))
    scheduler: str = os.getenv("CORS_PROXY_SCHEDULER", "off").lower()
    request_limit_per_minute: int = int(os.getenv("CORS_PROXY_RPM", "60"))
    concurrent_limit: int = int(os.getenv("CORS_PROXY_CONCURRENCY", "4"))
    daily_byte_limit: int = int(os.getenv("CORS_PROXY_DAILY_BYTES", str(100 * 1024 * 1024)))
    max_request_bytes: int = int(os.getenv("CORS_PROXY_MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))
    max_response_bytes: int = int(os.getenv("CORS_PROXY_MAX_RESPONSE_BYTES", str(8 * 1024 * 1024)))
    request_timeout: float = float(os.getenv("CORS_PROXY_TIMEOUT", "20"))
    reference_dir: Path | None = (Path(os.environ["CORS_PROXY_REFERENCE_DIR"]) if os.getenv("CORS_PROXY_REFERENCE_DIR") else None)


def load_settings() -> Settings:
    return Settings()
