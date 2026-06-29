import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.schemas import Finding
from app.services.owasp import classify_owasp

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Missing Strict-Transport-Security Header",
        "risk": "Medium",
        "description": "HSTS instructs browsers to only connect via HTTPS, preventing downgrade attacks.",
        "solution": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "name": "Missing Content-Security-Policy Header",
        "risk": "Medium",
        "description": "CSP helps prevent XSS by controlling which resources the browser may load.",
        "solution": "Add a Content-Security-Policy header appropriate for your application.",
    },
    "x-frame-options": {
        "name": "Missing X-Frame-Options Header",
        "risk": "Low",
        "description": "Without X-Frame-Options, the site may be embedded in iframes for clickjacking.",
        "solution": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "name": "Missing X-Content-Type-Options Header",
        "risk": "Low",
        "description": "Prevents MIME-type sniffing attacks.",
        "solution": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "name": "Missing Referrer-Policy Header",
        "risk": "Informational",
        "description": "Controls how much referrer information is sent with requests.",
        "solution": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Missing Permissions-Policy Header",
        "risk": "Low",
        "description": "Permissions-Policy restricts browser features (camera, geolocation, etc.) on your site.",
        "solution": "Add a Permissions-Policy header limiting unused browser features.",
    },
}

XSS_PAYLOAD = "<script>shieldscan</script>"
SQLI_PAYLOAD = "' OR '1'='1"


async def check_security_headers(url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = await client.get(url, follow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, meta in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    Finding(
                        id=f"header-{header}",
                        name=meta["name"],
                        risk=meta["risk"],
                        confidence="High",
                        url=url,
                        evidence=f"Response headers missing {header}",
                        description=meta["description"],
                        solution=meta["solution"],
                        owasp_category=classify_owasp(alert_name=meta["name"]),
                        source="passive",
                    )
                )

        set_cookie = headers.get("set-cookie", "")
        if set_cookie and "httponly" not in set_cookie.lower():
            findings.append(
                Finding(
                    id="cookie-httponly",
                    name="Cookie Without HttpOnly Flag",
                    risk="Low",
                    confidence="Medium",
                    url=url,
                    evidence=set_cookie[:200],
                    description="Session cookies without HttpOnly can be accessed by client-side scripts.",
                    solution="Set the HttpOnly flag on all session cookies.",
                    cwe="1004",
                    owasp_category=classify_owasp("287"),
                    source="passive",
                )
            )

        if url.startswith("https://"):
            findings.extend(await _check_tls(url))
    except Exception as exc:
        logger.warning("Header check failed for %s: %s", url, exc)
    return findings


async def _check_tls(url: str) -> list[Finding]:
    findings: list[Finding] = []
    host = urlparse(url).hostname
    if not host:
        return findings
    try:
        import ssl
        import socket

        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        from datetime import datetime

                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.utcnow()).days
                        if days_left < 30:
                            findings.append(
                                Finding(
                                    id="tls-expiry",
                                    name="TLS Certificate Expiring Soon",
                                    risk="Medium",
                                    confidence="High",
                                    url=url,
                                    evidence=f"Certificate expires in {days_left} days",
                                    description="An expiring certificate will cause browser warnings and outages.",
                                    solution="Renew the TLS certificate before expiry.",
                                    owasp_category=classify_owasp("295"),
                                    source="passive",
                                )
                            )
    except Exception as exc:
        findings.append(
            Finding(
                id="tls-error",
                name="TLS Configuration Issue",
                risk="High",
                confidence="Medium",
                url=url,
                evidence=str(exc)[:300],
                description="Could not establish a secure TLS connection.",
                solution="Verify certificate installation and TLS configuration.",
                owasp_category=classify_owasp("295"),
                source="passive",
            )
        )
    return findings


async def probe_forms_for_injection(url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Lightweight injection probes on discovered forms (builtin mode supplement)."""
    findings: list[Finding] = []
    try:
        resp = await client.get(url, follow_redirects=True)
        html = resp.text
        forms = re.findall(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>(.*?)</form>", html, re.I | re.S)
        if not forms:
            return findings

        for action, body in forms[:5]:
            action_url = urljoin(url, action)
            inputs = re.findall(r"<input[^>]*name=[\"']([^\"']+)[\"']", body, re.I)
            for field in inputs[:3]:
                if any(k in field.lower() for k in ("id", "user", "search", "q", "name", "email")):
                    # XSS probe
                    data = {field: XSS_PAYLOAD}
                    try:
                        probe = await client.post(action_url, data=data, follow_redirects=True, timeout=10.0)
                        if XSS_PAYLOAD in probe.text:
                            findings.append(
                                Finding(
                                    id=f"xss-{field}-{action_url}",
                                    name="Reflected Cross-Site Scripting (XSS)",
                                    risk="High",
                                    confidence="Medium",
                                    url=action_url,
                                    parameter=field,
                                    evidence=f"Payload reflected in response for field '{field}'",
                                    description="User input is reflected without encoding, allowing script injection.",
                                    solution="Encode all user output contextually. Implement Content-Security-Policy.",
                                    cwe="79",
                                    owasp_category=classify_owasp("79"),
                                    source="builtin",
                                )
                            )
                    except Exception:
                        pass

                    # SQLi probe
                    data = {field: SQLI_PAYLOAD}
                    try:
                        probe = await client.post(action_url, data=data, follow_redirects=True, timeout=10.0)
                        err_signs = ("sql syntax", "mysql", "sqlite", "postgresql", "ora-", "syntax error")
                        body_lower = probe.text.lower()
                        if any(sig in body_lower for sig in err_signs):
                            findings.append(
                                Finding(
                                    id=f"sqli-{field}-{action_url}",
                                    name="SQL Injection",
                                    risk="High",
                                    confidence="Firm",
                                    url=action_url,
                                    parameter=field,
                                    evidence="Database error message detected in response",
                                    description="Application may be vulnerable to SQL injection via this parameter.",
                                    solution="Use parameterised queries / prepared statements. Never concatenate SQL.",
                                    cwe="89",
                                    owasp_category=classify_owasp("89"),
                                    source="builtin",
                                )
                            )
                    except Exception:
                        pass
    except Exception as exc:
        logger.warning("Form probe failed: %s", exc)
    return findings


def zap_alert_to_finding(alert: dict[str, Any], index: int) -> Finding:
    risk = alert.get("risk", "Informational")
    cwe = alert.get("cweid", "") or ""
    name = alert.get("alert", "Unknown Alert")
    return Finding(
        id=f"zap-{index}-{alert.get('pluginId', index)}",
        name=name,
        risk=risk,
        confidence=alert.get("confidence", "Medium"),
        url=alert.get("url", ""),
        parameter=alert.get("param", ""),
        evidence=(alert.get("evidence", "") or alert.get("attack", ""))[:500],
        description=alert.get("description", ""),
        solution=alert.get("solution", ""),
        cwe=cwe,
        owasp_category=classify_owasp(cwe, name),
        source="zap",
    )
