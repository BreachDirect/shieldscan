"""Startup secrets validation (Drips Wave #29 pattern)."""

import logging
import os

from app.config import Settings

logger = logging.getLogger(__name__)

DEFAULT_ZAP_KEY = "changeme"
INSECURE_ZAP_KEYS = frozenset({"changeme", "zap", "password", "admin", ""})


def validate_settings(settings: Settings) -> list[str]:
    """Return non-fatal warnings about secret configuration."""
    warnings: list[str] = []
    env = os.getenv("SHIELDSCAN_ENV", "development").lower()

    if settings.zap_api_key.lower() in INSECURE_ZAP_KEYS:
        msg = "ZAP_API_KEY is using a default or empty value"
        if env == "production":
            warnings.append(f"CRITICAL: {msg} — change before production deploy")
        else:
            warnings.append(f"WARNING: {msg} — acceptable for local lab only")

    if settings.scanner_mode == "zap" and not settings.zap_api_url:
        warnings.append("WARNING: SCANNER_MODE=zap but ZAP_API_URL is empty")

    if env == "production" and settings.anthropic_api_key.startswith("sk-ant-"):
        if len(settings.anthropic_api_key) < 20:
            warnings.append("WARNING: ANTHROPIC_API_KEY appears truncated")

    for w in warnings:
        logger.warning("[secrets] %s", w)

    return warnings
