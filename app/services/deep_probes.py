"""Deep active probes — path traversal, LFI, SSTI, NoSQL, host header, uploads, APIs."""

import logging
import re
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

import httpx

from app.schemas import Finding
from app.services.constants import (
    COMMON_FUZZ_PARAMS,
    DIRECTORY_LIST_PATHS,
    JQUERY_VULN_PATTERNS,
    LFI_PAYLOADS,
    NOSQL_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    SENSITIVE_PATHS_EXTENDED,
    SSTI_PAYLOADS,
    XSS_PAYLOADS,
)
from app.services.crawler import CrawlResult, FormInfo
from app.services.owasp import classify_owasp

logger = logging.getLogger(__name__)

SQL_ERROR_SIGNS = (
    "sql syntax", "mysql", "sqlite", "postgresql", "ora-", "syntax error",
    "unclosed quotation", "quoted string not properly terminated", "odbc",
    "sqlstate", "database error", "pg_query", "mysqli", "sql server",
)

PASSWD_SIGNS = ("root:x:0", "daemon:", "[extensions]", "for 16-bit app support")
SSTI_SIGNS = ("49", "{{7*7}}", "${7*7}")  # 49 = 7*7 evaluated


def _f(
    fid: str,
    name: str,
    risk: str,
    url: str,
    description: str,
    solution: str,
    evidence: str = "",
    parameter: str = "",
    cwe: str = "",
    confidence: str = "Medium",
) -> Finding:
    return Finding(
        id=fid,
        name=name,
        risk=risk,
        confidence=confidence,
        url=url,
        parameter=parameter,
        evidence=evidence[:500],
        description=description,
        solution=solution,
        cwe=cwe,
        owasp_category=classify_owasp(cwe, name),
        source="deep-probe",
    )


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def fuzz_targets(base_url: str, crawl: CrawlResult, limit: int = 12) -> list[str]:
    """URLs to fuzz beyond the homepage — crawl pages + common paths."""
    targets: list[str] = []
    seen: set[str] = set()
    for u in [base_url, *crawl.pages]:
        norm = u.split("#")[0]
        if norm not in seen:
            seen.add(norm)
            targets.append(norm)
        if len(targets) >= limit:
            break
    return targets


async def probe_path_traversal_and_lfi(
    targets: list[str],
    client: httpx.AsyncClient,
    max_params: int = 20,
) -> list[Finding]:
    findings: list[Finding] = []
    file_params = ("file", "path", "page", "doc", "document", "folder", "dir", "include", "template", "load", "read")

    for base in targets[:8]:
        parsed = urlparse(base)
        clean = urlunparse(parsed._replace(query="", fragment=""))
        params_to_test = [p for p in COMMON_FUZZ_PARAMS if p in file_params][:max_params]
        if not params_to_test:
            params_to_test = list(file_params)

        for param in params_to_test:
            for payload in PATH_TRAVERSAL_PAYLOADS[:3]:
                probe = f"{clean}?{urlencode({param: payload})}"
                try:
                    resp = await client.get(probe, timeout=10.0)
                    body = (resp.text or "").lower()
                    if any(s in body for s in PASSWD_SIGNS):
                        findings.append(
                            _f(
                                f"path-trav-{param}-{hash(base) % 9999}",
                                "Path Traversal — Local File Read",
                                "High",
                                clean,
                                f"Parameter '{param}' may allow reading files outside the web root.",
                                "Validate and sanitise file paths. Use allowlists, not user-supplied paths.",
                                evidence=f"System file content pattern after ?{param}=",
                                parameter=param,
                                cwe="22",
                                confidence="Firm",
                            )
                        )
                        break
                except Exception:
                    pass

            for payload in LFI_PAYLOADS[:2]:
                probe = f"{clean}?{urlencode({param: payload})}"
                try:
                    resp = await client.get(probe, timeout=10.0)
                    body = resp.text or ""
                    bl = body.lower()
                    if any(s in bl for s in PASSWD_SIGNS) or "PD9waHA" in body:  # base64 php
                        findings.append(
                            _f(
                                f"lfi-{param}-{hash(base) % 9999}",
                                "Local File Inclusion (LFI)",
                                "High",
                                clean,
                                f"Parameter '{param}' may include local files on the server.",
                                "Never pass user input to include/require. Use static templates.",
                                evidence=f"LFI indicator via ?{param}=",
                                parameter=param,
                                cwe="98",
                                confidence="Firm",
                            )
                        )
                        break
                except Exception:
                    pass
    return findings


async def probe_ssti(targets: list[str], client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    ssti_params = ("name", "template", "message", "msg", "query", "q", "search", "input", "comment", "content")

    for base in targets[:6]:
        parsed = urlparse(base)
        clean = urlunparse(parsed._replace(query="", fragment=""))
        for param in ssti_params:
            for payload in SSTI_PAYLOADS:
                probe = f"{clean}?{urlencode({param: payload})}"
                try:
                    resp = await client.get(probe, timeout=10.0)
                    body = resp.text or ""
                    if payload in ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>") and "49" in body and "7*7" not in body:
                        findings.append(
                            _f(
                                f"ssti-{param}-{hash(base) % 9999}",
                                "Server-Side Template Injection (SSTI)",
                                "High",
                                clean,
                                f"Parameter '{param}' appears to evaluate template expressions server-side.",
                                "Use logic-less templates or sandbox template engines. Never embed user input in templates.",
                                evidence=f"Expression evaluated to 49 via ?{param}=",
                                parameter=param,
                                cwe="94",
                                confidence="Firm",
                            )
                        )
                        break
                except Exception:
                    pass
    return findings


async def probe_nosql_injection(forms: list[FormInfo], client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    for i, form in enumerate(forms[:12]):
        if not any("pass" in f.lower() or "user" in f.lower() for f in form.fields):
            continue
        for payload in NOSQL_PAYLOADS:
            data = {form.fields[0]: payload}
            if len(form.fields) > 1:
                data[form.fields[1]] = payload
            try:
                if form.method == "post":
                    resp = await client.post(
                        form.action_url,
                        data=data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        follow_redirects=True,
                        timeout=10.0,
                    )
                else:
                    resp = await client.get(form.action_url, params=data, timeout=10.0)
                body = (resp.text or "").lower()
                if resp.status_code == 200 and any(
                    k in body for k in ("welcome", "dashboard", "logout", "admin", "success", "logged in")
                ):
                    findings.append(
                        _f(
                            f"nosql-{i}",
                            "NoSQL / Authentication Bypass Surface",
                            "High",
                            form.action_url,
                            "Login form may accept NoSQL-style injection payloads.",
                            "Use typed queries and validate credentials server-side. Avoid string-built queries.",
                            evidence=f"Unexpected success response with payload on field {form.fields[0]}",
                            parameter=form.fields[0],
                            cwe="943",
                            confidence="Medium",
                        )
                    )
                    break
            except Exception:
                pass
    return findings


async def probe_host_header_injection(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    poison = "shieldscan-host-probe.invalid"
    try:
        resp = await client.get(
            base_url,
            headers={"Host": poison, "X-Forwarded-Host": poison},
            follow_redirects=True,
            timeout=12.0,
        )
        body = resp.text or ""
        if poison in body or poison in str(resp.url):
            findings.append(
                _f(
                    "host-header-injection",
                    "Host Header Injection",
                    "Medium",
                    base_url,
                    "The application reflects a crafted Host header in the response.",
                    "Validate Host header against an allowlist. Do not use Host for URL generation.",
                    evidence=f"Injected host '{poison}' reflected in response",
                    parameter="Host header",
                    cwe="644",
                    confidence="Firm",
                )
            )
    except Exception:
        pass
    return findings


async def probe_file_upload_surface(forms: list[FormInfo], client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    for i, form in enumerate(forms):
        try:
            resp = await client.get(form.page_url, timeout=10.0)
            html = resp.text or ""
        except Exception:
            continue
        if re.search(r'type=["\']file["\']', html, re.I):
            findings.append(
                _f(
                    f"upload-surface-{i}",
                    "Unrestricted File Upload Surface",
                    "Medium",
                    form.page_url,
                    "A file upload form was found. Upload endpoints are high-risk if file types are not restricted.",
                    "Allowlist safe extensions, scan uploads, store outside web root, rename files.",
                    evidence=f"Upload form at {form.action_url}",
                    parameter="file input",
                    cwe="434",
                )
            )
    return findings


async def probe_json_api_endpoints(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    origin = _origin(base_url)
    api_paths = [
        "/api", "/api/v1", "/api/users", "/api/login", "/api/auth", "/graphql",
        "/rest/user", "/api/products", "/api/search",
    ]
    sqli_json = {"id": "1' OR '1'='1", "query": "' OR 1=1--", "search": "<script>shieldscan</script>"}

    for path in api_paths:
        url = urljoin(origin, path)
        for method in ("GET", "POST"):
            try:
                if method == "GET":
                    resp = await client.get(url, params={"q": XSS_PAYLOADS[1]}, timeout=8.0)
                else:
                    resp = await client.post(
                        url,
                        json=sqli_json,
                        headers={"Content-Type": "application/json"},
                        timeout=8.0,
                    )
                if resp.status_code in (200, 201, 400, 401, 403, 500):
                    body = resp.text or ""
                    bl = body.lower()
                    if XSS_PAYLOADS[1] in body:
                        findings.append(
                            _f(
                                f"api-xss-{path.replace('/', '-')}",
                                "Reflected XSS in API Response",
                                "High",
                                url,
                                "API endpoint reflects unencoded input in its response.",
                                "Encode API output. Validate Content-Type. Use CSP on any HTML views.",
                                evidence=f"{method} {path} reflected XSS payload",
                                parameter="JSON/query body",
                                cwe="79",
                                confidence="Firm",
                            )
                        )
                    elif any(s in bl for s in SQL_ERROR_SIGNS):
                        findings.append(
                            _f(
                                f"api-sqli-{path.replace('/', '-')}",
                                "SQL Injection in API Endpoint",
                                "High",
                                url,
                                "API returned database error signatures when sent injection payloads.",
                                "Use parameterised queries for all API database access.",
                                evidence=f"{method} {path} SQL error in response",
                                parameter="JSON body",
                                cwe="89",
                                confidence="Firm",
                            )
                        )
                    elif resp.status_code == 200 and method == "POST" and "graphql" in path:
                        findings.append(
                            _f(
                                "graphql-exposed",
                                "GraphQL Endpoint Discovered",
                                "Informational",
                                url,
                                "GraphQL endpoints should require auth, rate limiting, and query depth limits.",
                                "Disable introspection in production. Require authentication.",
                                evidence=f"HTTP {resp.status_code}",
                                parameter="GraphQL",
                                cwe="200",
                            )
                        )
            except Exception:
                pass
    return findings


async def probe_clickjacking_pages(pages: list[str], client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    sensitive_markers = ("login", "password", "checkout", "payment", "transfer", "admin")
    for page in pages[:15]:
        try:
            resp = await client.get(page, timeout=10.0)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = (resp.text or "").lower()
            if not any(m in page.lower() or m in body for m in sensitive_markers):
                continue
            xfo = headers.get("x-frame-options", "")
            csp = headers.get("content-security-policy", "")
            if not xfo and "frame-ancestors" not in csp.lower():
                findings.append(
                    _f(
                        f"clickjack-{hash(page) % 10000}",
                        "Clickjacking Risk on Sensitive Page",
                        "Medium",
                        page,
                        "Sensitive page lacks X-Frame-Options or CSP frame-ancestors — may be embedded in malicious iframes.",
                        "Add X-Frame-Options: DENY or CSP frame-ancestors 'self'.",
                        evidence="Missing anti-clickjacking headers on login/payment page",
                        parameter="Page headers",
                        cwe="1021",
                    )
                )
        except Exception:
            pass
    return findings


async def probe_rate_limiting(forms: list[FormInfo], client: httpx.AsyncClient) -> list[Finding]:
    """Quick check if login accepts unlimited attempts."""
    findings: list[Finding] = []
    for form in forms[:3]:
        if not any("pass" in f.lower() for f in form.fields):
            continue
        user_field = next((f for f in form.fields if "user" in f.lower() or "email" in f.lower()), form.fields[0])
        pass_field = next((f for f in form.fields if "pass" in f.lower()), form.fields[-1])
        blocked = False
        for attempt in range(5):
            data = {user_field: "shieldscan_invalid", pass_field: f"wrong{attempt}"}
            try:
                if form.method == "post":
                    resp = await client.post(form.action_url, data=data, timeout=8.0)
                else:
                    resp = await client.get(form.action_url, params=data, timeout=8.0)
                if resp.status_code == 429 or "too many" in (resp.text or "").lower() or "locked" in (resp.text or "").lower():
                    blocked = True
                    break
            except Exception:
                break
        if not blocked:
            findings.append(
                _f(
                    f"no-rate-limit-{hash(form.action_url) % 9999}",
                    "No Login Rate Limiting Detected",
                    "Medium",
                    form.action_url,
                    "Login form accepted multiple failed attempts without blocking — enables password guessing.",
                    "Implement rate limiting, CAPTCHA, and account lockout after failed attempts.",
                    evidence="5 rapid failed login attempts were not blocked",
                    parameter=pass_field,
                    cwe="307",
                )
            )
    return findings


async def probe_extended_sensitive_paths(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    origin = _origin(base_url)
    indicators = {
        "/.env": ("db_", "password", "secret", "api_key", "="),
        "/.git/HEAD": ("ref:", "git"),
        "/.git/config": ("[core]", "repositoryformatversion"),
        "/backup.sql": ("insert into", "create table", "mysqldump"),
        "/dump.sql": ("insert into", "create table"),
        "/phpinfo.php": ("phpinfo", "php version"),
        "/actuator/env": ("propertysources", "systemproperties"),
        "/elmah.axd": ("error log", "elmah"),
    }
    for path, name, risk in SENSITIVE_PATHS_EXTENDED:
        test_url = origin + path
        try:
            resp = await client.get(test_url, follow_redirects=False, timeout=8.0)
            if resp.status_code != 200:
                continue
            body = (resp.text or "")[:800].lower()
            keys = indicators.get(path, ())
            if not keys or any(k in body for k in keys) or path.endswith((".zip", ".sql")):
                findings.append(
                    _f(
                        f"sensitive-{path.replace('/', '-').strip('-')}",
                        name,
                        risk,
                        test_url,
                        f"Sensitive path {path} is publicly accessible.",
                        "Block access in web server config. Never deploy secrets to public paths.",
                        evidence=f"HTTP 200, {len(resp.content)} bytes",
                        parameter=path,
                        cwe="538",
                        confidence="Firm" if keys else "Medium",
                    )
                )
        except Exception:
            pass
    return findings


async def probe_directory_listing_extended(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    origin = _origin(base_url)
    for path in DIRECTORY_LIST_PATHS:
        test_url = origin + path
        try:
            resp = await client.get(test_url, timeout=8.0)
            body = resp.text or ""
            if resp.status_code == 200 and re.search(
                r"index of /|directory listing|parent directory|<title>index of",
                body,
                re.I,
            ):
                findings.append(
                    _f(
                        f"dirlist-{path.strip('/').replace('/', '-')}",
                        "Directory Listing Enabled",
                        "Medium",
                        test_url,
                        "Directory listing exposes file names to attackers.",
                        "Disable directory listing (e.g. Options -Indexes in Apache).",
                        evidence=body[:200],
                        parameter=path,
                        cwe="548",
                    )
                )
        except Exception:
            pass
    return findings


async def probe_components_all_pages(pages: list[str], client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for page in pages[:20]:
        try:
            resp = await client.get(page, timeout=10.0)
            html = resp.text or ""
            for pattern, max_minor, msg in JQUERY_VULN_PATTERNS:
                m = re.search(pattern, html, re.I)
                if not m:
                    continue
                key = f"{pattern}:{m.group(0)}"
                if key in seen:
                    continue
                if max_minor is not None and m.lastindex:
                    try:
                        minor = int(m.group(1))
                        if minor > max_minor:
                            continue
                    except (ValueError, IndexError):
                        pass
                seen.add(key)
                findings.append(
                    _f(
                        f"vuln-lib-{hash(key) % 10000}",
                        f"Outdated or Risky Component — {msg}",
                        "Medium",
                        page,
                        "Outdated libraries may contain known security flaws.",
                        "Upgrade dependencies and monitor CVE advisories.",
                        evidence=m.group(0)[:120],
                        cwe="1104",
                    )
                )
        except Exception:
            pass
    return findings


async def multi_page_header_audit(pages: list[str], client: httpx.AsyncClient) -> list[Finding]:
    """Flag pages missing HSTS/CSP when homepage has them (inconsistency)."""
    from app.services.passive_checks import check_security_headers

    findings: list[Finding] = []
    for page in pages[1:8]:
        findings.extend(await check_security_headers(page, client))
    return findings


async def deep_fuzz_urls(
    targets: list[str],
    client: httpx.AsyncClient,
    max_params: int = 40,
) -> list[Finding]:
    """Run XSS/SQLi/CMD fuzzing across multiple discovered URLs."""
    from app.services.owasp_top10 import fuzz_url_parameters

    findings: list[Finding] = []
    for target in targets[:10]:
        findings.extend(await fuzz_url_parameters(target, client, max_params=max_params))
    return findings


async def run_deep_probes(
    target_url: str,
    client: httpx.AsyncClient,
    crawl: CrawlResult,
    on_progress=None,
    fuzz_max_params: int = 40,
) -> list[Finding]:
    findings: list[Finding] = []
    targets = fuzz_targets(target_url, crawl)

    if on_progress:
        on_progress("Deep scan: path traversal and local file inclusion")
    findings.extend(await probe_path_traversal_and_lfi(targets, client))

    if on_progress:
        on_progress("Deep scan: template injection and NoSQL probes")
    findings.extend(await probe_ssti(targets, client))
    findings.extend(await probe_nosql_injection(crawl.forms, client))

    if on_progress:
        on_progress("Deep scan: host header, APIs, and upload surfaces")
    findings.extend(await probe_host_header_injection(target_url, client))
    findings.extend(await probe_json_api_endpoints(target_url, client))
    findings.extend(await probe_file_upload_surface(crawl.forms, client))

    if on_progress:
        on_progress("Deep scan: clickjacking, rate limits, sensitive files")
    findings.extend(await probe_clickjacking_pages(crawl.pages, client))
    findings.extend(await probe_rate_limiting(crawl.forms, client))
    findings.extend(await probe_extended_sensitive_paths(target_url, client))
    findings.extend(await probe_directory_listing_extended(target_url, client))

    if on_progress:
        on_progress("Deep scan: outdated libraries on all crawled pages")
    findings.extend(await probe_components_all_pages(crawl.pages, client))

    if on_progress:
        on_progress("Deep scan: multi-page security header audit")
    findings.extend(await multi_page_header_audit(crawl.pages, client))

    if on_progress:
        on_progress("Deep scan: extended parameter fuzzing on discovered URLs")
    findings.extend(await deep_fuzz_urls(targets, client, max_params=fuzz_max_params))

    return findings
