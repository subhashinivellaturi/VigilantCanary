from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    app_name: str = "Vigilant Canary – Production-Grade Web Vulnerability Scanner"
    api_prefix: str = "/api/v1"
    model_refresh_minutes: int = 30
    retrain_on_startup: bool = False
    frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:5173")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
