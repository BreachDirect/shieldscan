"""Extended defensive security checks beyond HTTP headers."""

import logging
import re
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from app.schemas import Finding
from app.services.crawler import CrawlResult, FormInfo
from app.services.owasp import classify_owasp

logger = logging.getLogger(__name__)

XSS_PAYLOAD = "shieldscan_xss_probe"
SQLI_PAYLOAD = "' OR '1'='1"
SQL_ERROR_SIGNS = (
    "sql syntax", "mysql", "sqlite", "postgresql", "ora-", "syntax error",
    "unclosed quotation", "quoted string not properly terminated", "odbc",
    "sqlstate", "database error", "pg_query", "mysqli",
)

SENSITIVE_PATHS = [
    ("/.env", "Environment File Exposed", "High", ".env files often contain database credentials and API keys."),
    ("/.git/HEAD", "Git Repository Exposed", "High", "Exposed .git directory may allow source code download."),
    ("/backup.zip", "Backup Archive Exposed", "High", "Public backup files may contain source code and credentials."),
    ("/wp-config.php.bak", "WordPress Config Backup Exposed", "High", "Backup config files may expose database credentials."),
    ("/phpinfo.php", "PHP Info Page Exposed", "Medium", "phpinfo() pages disclose server configuration to attackers."),
    ("/server-status", "Server Status Page Exposed", "Medium", "Apache server-status can reveal internal traffic data."),
    ("/.DS_Store", "DS_Store File Exposed", "Low", "May leak directory structure information."),
]

REDIRECT_PARAMS = ("redirect", "url", "next", "return", "returnurl", "goto", "dest", "destination", "redir", "continue")

DISCLOSURE_HEADERS = {
    "server": ("Server Version Disclosure", "Medium", "Remove or genericise the Server response header."),
    "x-powered-by": ("Technology Stack Disclosure (X-Powered-By)", "Low", "Remove X-Powered-By to reduce fingerprinting."),
    "x-aspnet-version": ("ASP.NET Version Disclosure", "Low", "Disable X-AspNet-Version header in web.config."),
    "x-aspnetmvc-version": ("ASP.NET MVC Version Disclosure", "Low", "Disable MVC version header exposure."),
}


def _finding(
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
        source="builtin",
    )


async def check_https_enforcement(target_url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(target_url)
    if parsed.scheme == "https":
        return findings
    http_url = target_url if parsed.scheme == "http" else f"http://{parsed.netloc}{parsed.path or '/'}"
    try:
        resp = await client.get(http_url, follow_redirects=False, timeout=10.0)
        if resp.status_code not in (301, 302, 303, 307, 308):
            findings.append(
                _finding(
                    "https-no-redirect",
                    "HTTP Not Redirecting to HTTPS",
                    "Medium",
                    http_url,
                    "The site accepts plain HTTP without redirecting users to HTTPS.",
                    "Configure automatic HTTP-to-HTTPS redirect on the web server or load balancer.",
                    f"HTTP returned status {resp.status_code} without redirect.",
                    cwe="319",
                )
            )
        elif not str(resp.headers.get("location", "")).startswith("https://"):
            findings.append(
                _finding(
                    "https-weak-redirect",
                    "HTTP Redirect Does Not Use HTTPS",
                    "Medium",
                    http_url,
                    "HTTP requests redirect but not to a secure HTTPS destination.",
                    "Ensure all HTTP traffic redirects to https:// URLs.",
                    f"Location: {resp.headers.get('location', '')[:200]}",
                    cwe="319",
                )
            )
    except Exception as exc:
        logger.debug("HTTPS check failed: %s", exc)
    return findings


async def check_header_disclosure(url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = await client.get(url, follow_redirects=True, timeout=12.0)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for header, (name, risk, solution) in DISCLOSURE_HEADERS.items():
            if header in headers and headers[header].strip():
                findings.append(
                    _finding(
                        f"disclosure-{header}",
                        name,
                        risk,
                        url,
                        f"The {header} header reveals server technology: {headers[header][:100]}",
                        solution,
                        evidence=f"{header}: {headers[header][:150]}",
                        cwe="200",
                        confidence="High",
                    )
                )
    except Exception:
        pass
    return findings


async def check_cookie_security(url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = await client.get(url, follow_redirects=True, timeout=12.0)
        raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not raw_cookies and resp.headers.get("set-cookie"):
            raw_cookies = [resp.headers.get("set-cookie", "")]
        for i, cookie in enumerate(raw_cookies):
            lower = cookie.lower()
            if "secure" not in lower and url.startswith("https://"):
                findings.append(
                    _finding(
                        f"cookie-secure-{i}",
                        "Cookie Missing Secure Flag",
                        "Medium",
                        url,
                        "Cookies without the Secure flag may be transmitted over unencrypted HTTP.",
                        "Add the Secure attribute to all session cookies on HTTPS sites.",
                        evidence=cookie[:200],
                        cwe="614",
                    )
                )
            if "samesite" not in lower:
                findings.append(
                    _finding(
                        f"cookie-samesite-{i}",
                        "Cookie Missing SameSite Attribute",
                        "Low",
                        url,
                        "Without SameSite, cookies are more vulnerable to cross-site request attacks.",
                        "Set SameSite=Lax or SameSite=Strict on session cookies.",
                        evidence=cookie[:200],
                        cwe="1275",
                    )
                )
    except Exception:
        pass
    return findings


async def check_cors(url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = await client.get(
            url,
            headers={"Origin": "https://shieldscan-probe.example"},
            timeout=10.0,
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        if acao == "*":
            findings.append(
                _finding(
                    "cors-wildcard",
                    "Permissive CORS Policy (Allow-Origin: *)",
                    "Low",
                    url,
                    "A wildcard CORS policy may allow any website to read API responses.",
                    "Restrict Access-Control-Allow-Origin to trusted domains only.",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    cwe="942",
                )
            )
        elif acao == "https://shieldscan-probe.example":
            findings.append(
                _finding(
                    "cors-reflects-origin",
                    "CORS Reflects Arbitrary Origin",
                    "High",
                    url,
                    "The server reflects any Origin header, allowing malicious sites to read responses.",
                    "Maintain an allowlist of trusted origins; never echo arbitrary Origin values.",
                    evidence=f"Access-Control-Allow-Origin: {acao}, Allow-Credentials: {acac}",
                    cwe="942",
                    confidence="Firm",
                )
            )
    except Exception:
        pass
    return findings


async def check_sensitive_paths(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path, name, risk, description in SENSITIVE_PATHS:
        test_url = origin + path
        try:
            resp = await client.get(test_url, follow_redirects=False, timeout=8.0)
            body = (resp.text or "")[:500].lower()
            if resp.status_code == 200 and len(body) > 0:
                indicators = {
                    "/.env": ("=", "db_", "password", "secret", "api_key"),
                    "/.git/HEAD": ("ref:", "git"),
                    "/backup.zip": (),  # binary - status 200 on zip is enough
                    "/wp-config.php.bak": ("db_", "define"),
                    "/phpinfo.php": ("phpinfo", "php version"),
                    "/server-status": ("apache status", "server status"),
                    "/.DS_Store": (),
                }
                keys = indicators.get(path, ())
                if not keys or any(k in body for k in keys) or path in ("/backup.zip", "/.DS_Store"):
                    findings.append(
                        _finding(
                            f"sensitive-{path.replace('/', '-')}",
                            name,
                            risk,
                            test_url,
                            description,
                            "Remove public access to sensitive files. Block these paths in web server config.",
                            evidence=f"HTTP {resp.status_code}, {len(resp.content)} bytes",
                            cwe="538",
                            confidence="Firm" if keys else "Medium",
                        )
                    )
        except Exception:
            pass
    return findings


async def check_http_methods(url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    for method, name in (("TRACE", "HTTP TRACE Method Enabled"), ("OPTIONS", "HTTP OPTIONS Method Exposed")):
        try:
            resp = await client.request(method, url, timeout=8.0)
            if method == "TRACE" and resp.status_code == 200:
                findings.append(
                    _finding(
                        "http-trace",
                        name,
                        "Medium",
                        url,
                        "TRACE can be abused for cross-site tracing (XST) attacks.",
                        "Disable TRACE method in web server configuration.",
                        evidence=f"TRACE returned HTTP {resp.status_code}",
                        cwe="693",
                    )
                )
            if method == "OPTIONS" and "allow" in {k.lower() for k in resp.headers}:
                allow = resp.headers.get("allow", resp.headers.get("Allow", ""))
                if "TRACE" in allow.upper():
                    findings.append(
                        _finding(
                            "http-trace-allowed",
                            "TRACE Listed in Allowed HTTP Methods",
                            "Medium",
                            url,
                            "Server advertises TRACE as an allowed method.",
                            "Remove TRACE from allowed methods.",
                            evidence=f"Allow: {allow}",
                            cwe="693",
                        )
                    )
        except Exception:
            pass
    return findings


async def check_directory_listing(url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    test_paths = ["/images/", "/uploads/", "/files/", "/assets/", "/backup/", "/tmp/"]
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in test_paths:
        test_url = origin + path
        try:
            resp = await client.get(test_url, timeout=8.0)
            body = resp.text or ""
            if resp.status_code == 200 and re.search(r"index of /|directory listing", body, re.I):
                findings.append(
                    _finding(
                        f"dirlist-{path.strip('/')}",
                        "Directory Listing Enabled",
                        "Medium",
                        test_url,
                        "Directory listing exposes file names and structure to attackers.",
                        "Disable directory listing in web server configuration (e.g. Options -Indexes).",
                        evidence=body[:200],
                        cwe="548",
                    )
                )
        except Exception:
            pass
    return findings


async def check_mixed_content(url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    if not url.startswith("https://"):
        return findings
    try:
        resp = await client.get(url, timeout=12.0)
        insecure = re.findall(r"""(?:src|href)=["']http://[^"']+["']""", resp.text or "", re.I)
        if insecure:
            findings.append(
                _finding(
                    "mixed-content",
                    "Mixed Content (HTTP Resources on HTTPS Page)",
                    "Medium",
                    url,
                    "Loading HTTP resources on HTTPS pages can be intercepted or modified by attackers.",
                    "Change all resource URLs to HTTPS or use protocol-relative paths.",
                    evidence=f"{len(insecure)} insecure reference(s): {insecure[0][:120]}",
                    cwe="311",
                )
            )
    except Exception:
        pass
    return findings


async def check_csrf_on_forms(forms: list[FormInfo]) -> list[Finding]:
    findings: list[Finding] = []
    for i, form in enumerate(forms):
        if form.method == "post" and not form.has_csrf_token and len(form.fields) > 0:
            sensitive = any(
                k in f.lower() for f in form.fields for k in ("password", "pass", "email", "user", "login")
            )
            if sensitive or len(form.fields) >= 2:
                findings.append(
                    _finding(
                        f"csrf-{i}-{form.action_url}",
                        "Form Missing CSRF Protection",
                        "Medium",
                        form.page_url,
                        "POST forms without CSRF tokens may be vulnerable to cross-site request forgery.",
                        "Add a unique CSRF token to every state-changing form and validate it server-side.",
                        evidence=f"POST form action={form.action_url}, fields={form.fields[:5]}",
                        parameter=form.action_url,
                        cwe="352",
                    )
                )
    return findings


async def probe_url_parameters(
    param_urls: list[tuple[str, str, str]],
    client: httpx.AsyncClient,
    max_probes: int = 40,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    count = 0

    for page_url, param, _value in param_urls:
        if count >= max_probes:
            break
        key = f"{page_url}:{param}"
        if key in seen:
            continue
        seen.add(key)
        count += 1

        parsed = urlparse(page_url)
        base_params = parse_qs(parsed.query)
        flat = {k: v[0] if isinstance(v, list) else v for k, v in base_params.items()}

        # XSS probe
        flat_xss = dict(flat)
        flat_xss[param] = XSS_PAYLOAD
        xss_url = urlunparse(parsed._replace(query=urlencode(flat_xss)))
        try:
            resp = await client.get(xss_url, timeout=10.0)
            if XSS_PAYLOAD in (resp.text or ""):
                findings.append(
                    _finding(
                        f"xss-get-{param}",
                        "Reflected Cross-Site Scripting (XSS) in URL Parameter",
                        "High",
                        page_url,
                        "User-supplied URL parameter is reflected without encoding.",
                        "Encode all output contextually. Implement Content-Security-Policy.",
                        evidence=f"Parameter '{param}' reflected payload on {xss_url[:200]}",
                        parameter=param,
                        cwe="79",
                        confidence="Firm",
                    )
                )
        except Exception:
            pass

        # SQLi probe
        flat_sqli = dict(flat)
        flat_sqli[param] = SQLI_PAYLOAD
        sqli_url = urlunparse(parsed._replace(query=urlencode(flat_sqli)))
        try:
            resp = await client.get(sqli_url, timeout=10.0)
            body_lower = (resp.text or "").lower()
            if any(sig in body_lower for sig in SQL_ERROR_SIGNS):
                findings.append(
                    _finding(
                        f"sqli-get-{param}",
                        "SQL Injection in URL Parameter",
                        "High",
                        page_url,
                        "Database error triggered by modified URL parameter.",
                        "Use parameterised queries. Never concatenate user input into SQL.",
                        evidence=f"Parameter '{param}' caused database error signature",
                        parameter=param,
                        cwe="89",
                        confidence="Firm",
                    )
                )
        except Exception:
            pass

        # Open redirect probe
        if param.lower() in REDIRECT_PARAMS:
            flat_redir = dict(flat)
            flat_redir[param] = "https://shieldscan-probe.example/redirect-test"
            redir_url = urlunparse(parsed._replace(query=urlencode(flat_redir)))
            try:
                resp = await client.get(redir_url, follow_redirects=False, timeout=10.0)
                loc = resp.headers.get("location", "")
                if "shieldscan-probe.example" in loc:
                    findings.append(
                        _finding(
                            f"open-redirect-{param}",
                            "Open Redirect Vulnerability",
                            "Medium",
                            page_url,
                            "Application redirects users to externally controlled URLs.",
                            "Validate redirect targets against an allowlist of trusted domains.",
                            evidence=f"Location: {loc[:200]}",
                            parameter=param,
                            cwe="601",
                        )
                    )
            except Exception:
                pass

    return findings


async def probe_forms_extended(forms: list[FormInfo], client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    for i, form in enumerate(forms[:25]):
        for field in form.fields[:6]:
            fl = field.lower()
            if not any(k in fl for k in ("id", "user", "search", "q", "name", "email", "pass", "query", "msg")):
                continue
            data = {field: XSS_PAYLOAD}
            try:
                if form.method == "post":
                    resp = await client.post(form.action_url, data=data, follow_redirects=True, timeout=10.0)
                else:
                    resp = await client.get(form.action_url, params=data, follow_redirects=True, timeout=10.0)
                if XSS_PAYLOAD in (resp.text or ""):
                    findings.append(
                        _finding(
                            f"xss-form-{i}-{field}",
                            "Reflected Cross-Site Scripting (XSS) in Form Field",
                            "High",
                            form.action_url,
                            "Form input is reflected without proper encoding.",
                            "Encode all user output. Implement Content-Security-Policy.",
                            evidence=f"Field '{field}' reflected payload",
                            parameter=field,
                            cwe="79",
                            confidence="Firm",
                        )
                    )
            except Exception:
                pass

            data = {field: SQLI_PAYLOAD}
            try:
                if form.method == "post":
                    resp = await client.post(form.action_url, data=data, follow_redirects=True, timeout=10.0)
                else:
                    resp = await client.get(form.action_url, params=data, follow_redirects=True, timeout=10.0)
                body_lower = (resp.text or "").lower()
                if any(sig in body_lower for sig in SQL_ERROR_SIGNS):
                    findings.append(
                        _finding(
                            f"sqli-form-{i}-{field}",
                            "SQL Injection in Form Field",
                            "High",
                            form.action_url,
                            "Database error triggered by form input.",
                            "Use parameterised queries / prepared statements.",
                            evidence=f"Field '{field}' triggered SQL error signature",
                            parameter=field,
                            cwe="89",
                            confidence="Firm",
                        )
                    )
            except Exception:
                pass
    return findings


async def check_security_txt(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    parsed = urlparse(base_url)
    test_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/security.txt"
    try:
        resp = await client.get(test_url, timeout=8.0)
        if resp.status_code != 200:
            return [
                _finding(
                    "missing-security-txt",
                    "Missing security.txt Contact File",
                    "Informational",
                    base_url,
                    "security.txt helps researchers report vulnerabilities responsibly.",
                    "Publish /.well-known/security.txt with Contact and Expires fields per RFC 9116.",
                    evidence=f"GET {test_url} returned HTTP {resp.status_code}",
                    cwe="1059",
                )
            ]
    except Exception:
        pass
    return []


async def fingerprint_technology(url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Informational technology detection — helps SMB owners know their stack."""
    findings: list[Finding] = []
    try:
        resp = await client.get(url, timeout=12.0)
        html = (resp.text or "")[:50000].lower()
        headers = {k.lower(): v for k, v in resp.headers.items()}
        detected: list[str] = []

        patterns = [
            (r"wp-content|wordpress", "WordPress"),
            (r"drupal", "Drupal"),
            (r"joomla", "Joomla"),
            (r"react|__next", "React/Next.js"),
            (r"angular", "Angular"),
            (r"bootstrap", "Bootstrap"),
            (r"laravel", "Laravel"),
            (r"django", "Django"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, html):
                detected.append(name)
        if "x-powered-by" in headers:
            detected.append(headers["x-powered-by"][:50])
        if "server" in headers:
            detected.append(f"Server: {headers['server'][:50]}")

        if detected:
            findings.append(
                _finding(
                    "tech-fingerprint",
                    "Technology Stack Detected",
                    "Informational",
                    url,
                    "Identified technologies should be kept updated to patch known vulnerabilities.",
                    "Maintain an inventory of frameworks/plugins and apply security updates promptly.",
                    evidence=", ".join(dict.fromkeys(detected))[:300],
                    cwe="1104",
                    confidence="High",
                )
            )
    except Exception:
        pass
    return findings


async def run_extended_checks(
    target_url: str,
    client: httpx.AsyncClient,
    crawl: CrawlResult,
) -> list[Finding]:
    """Run all extended checks against target and crawl data."""
    findings: list[Finding] = []

    findings.extend(await check_https_enforcement(target_url, client))
    findings.extend(await check_header_disclosure(target_url, client))
    findings.extend(await check_cookie_security(target_url, client))
    findings.extend(await check_cors(target_url, client))
    findings.extend(await check_sensitive_paths(target_url, client))
    findings.extend(await check_http_methods(target_url, client))
    findings.extend(await check_directory_listing(target_url, client))
    findings.extend(await check_mixed_content(target_url, client))
    findings.extend(await check_security_txt(target_url, client))
    findings.extend(await fingerprint_technology(target_url, client))
    findings.extend(await check_csrf_on_forms(crawl.forms))
    findings.extend(await probe_url_parameters(crawl.param_urls, client))
    findings.extend(await probe_forms_extended(crawl.forms, client))

    # Header disclosure on more crawled pages
    for page in crawl.pages[1:10]:
        findings.extend(await check_header_disclosure(page, client))
        findings.extend(await check_cookie_security(page, client))
        findings.extend(await check_cors(page, client))

    return findings
