"""Scan target safety and authorisation guard (Drips Wave #231 pattern)."""

import ipaddress
import logging
from urllib.parse import urlparse

from app.errors import raise_api_error

logger = logging.getLogger(__name__)

# Lab targets allowed in development (DVWA, Juice Shop, ZAP)
LAB_HOSTS = frozenset({
    "127.0.0.1",
    "localhost",
    "::1",
    "host.docker.internal",
})

BLOCKED_SCHEMES = frozenset({"file", "ftp", "gopher", "data"})


def _host_is_private(hostname: str) -> bool:
    if hostname in LAB_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def validate_scan_request(target_url: str, authorised: bool, *, allow_private: bool = True) -> str:
    """
    Validate and normalise a scan target URL.

    Raises HTTPException with stable error codes on rejection.
    """
    if not authorised:
        raise_api_error(
            400,
            "AUTHORISATION_REQUIRED",
            "You must confirm authorisation to scan this target.",
        )

    url = target_url.strip()
    if not url:
        raise_api_error(422, "VALIDATION_ERROR", "target_url is required")

    if "://" in url:
        scheme = urlparse(url).scheme.lower()
        if scheme in BLOCKED_SCHEMES:
            raise_api_error(
                400,
                "TARGET_NOT_ALLOWED",
                f"Scheme '{scheme}' is not permitted for scanning.",
            )

    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise_api_error(400, "VALIDATION_ERROR", "target_url must include a valid hostname")

    if not allow_private and _host_is_private(hostname):
        raise_api_error(
            400,
            "TARGET_NOT_ALLOWED",
            "Private and loopback targets are blocked in this environment.",
            details={"hostname": hostname},
        )

    logger.info("Scan authorised for target: %s", url)
    return url
