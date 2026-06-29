"""Shared scanner constants — paths, parameters, payloads."""

COMMON_PROBE_PATHS = [
    # Auth & admin
    "/login", "/signin", "/sign-in", "/auth/login", "/user/login", "/account/login",
    "/admin", "/administrator", "/dashboard", "/wp-admin", "/wp-login.php",
    "/register", "/signup", "/auth/register", "/api/login", "/api/auth",
    # API & modern apps
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/rest", "/swagger",
    "/swagger-ui", "/api-docs", "/openapi.json", "/swagger.json",
    # Common app pages
    "/search", "/contact", "/upload", "/profile", "/users", "/user/1", "/user/2",
    "/products", "/product/1", "/orders", "/cart", "/checkout", "/account",
    "/settings", "/config", "/debug", "/test", "/status", "/health",
    # DVWA / lab app paths (helps demos find vulnerable modules)
    "/login.php", "/setup.php", "/security.php", "/index.php",
    "/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/",
    "/vulnerabilities/xss_r/", "/vulnerabilities/xss_d/", "/vulnerabilities/xss_s/",
    "/vulnerabilities/csrf/", "/vulnerabilities/upload/", "/vulnerabilities/fi/",
    "/vulnerabilities/brute/", "/vulnerabilities/exec/", "/vulnerabilities/captcha/",
    "/vulnerabilities/weak_id/", "/vulnerabilities/open_redirect/",
    # Discovery
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
]

COMMON_FUZZ_PARAMS = [
    "id", "user", "user_id", "uid", "page", "p", "q", "search", "query", "s",
    "name", "file", "path", "cat", "category", "item", "product", "pid",
    "order", "sort", "filter", "email", "username", "login", "redirect", "url",
    "next", "return", "msg", "message", "error", "debug", "test", "cmd", "exec",
    "action", "type", "module", "view", "template", "lang", "locale", "country",
    "zip", "code", "token", "key", "secret", "api_key", "callback", "jsonp",
    "format", "output", "render", "include", "doc", "document", "folder", "dir",
    "download", "upload", "image", "img", "src", "href", "link", "ref", "target",
    "dest", "destination", "continue", "goto", "redir", "forward", "uri", "fetch",
    "load", "read", "write", "delete", "remove", "id_user", "account", "session",
]

XSS_PAYLOADS = [
    "shieldscan7",
    "<script>shieldscan7</script>",
    "\"><script>shieldscan7</script>",
    "'\"><img src=x onerror=alert(7)>",
    "<svg/onload=shieldscan7>",
    "javascript:shieldscan7",
    "'-shieldscan7-'",
    "<body onload=shieldscan7>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1' OR '1'='1' --",
    "1 AND 1=1",
    "' UNION SELECT NULL--",
    "1; WAITFOR DELAY '0:0:3'--",
    "admin'--",
    "' OR 1=1#",
    "1' AND '1'='1",
]

CMD_PAYLOADS = [";id", "|id", "`id`", "$(id)", "||id", "&id", ";whoami", "|whoami"]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
    "/etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
]

LFI_PAYLOADS = [
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
    "....//....//etc/passwd",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
]

NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    "' || '1'=='1",
    "admin' || '1'=='1",
]

SENSITIVE_PATHS_EXTENDED = [
    ("/.env", "Environment File Exposed", "High"),
    ("/.env.local", "Environment File Exposed", "High"),
    ("/.env.production", "Production Environment File Exposed", "High"),
    ("/.git/HEAD", "Git Repository Exposed", "High"),
    ("/.git/config", "Git Config Exposed", "High"),
    ("/.svn/entries", "SVN Repository Exposed", "High"),
    ("/backup.zip", "Backup Archive Exposed", "High"),
    ("/backup.sql", "Database Backup Exposed", "High"),
    ("/dump.sql", "Database Dump Exposed", "High"),
    ("/database.sql", "Database Dump Exposed", "High"),
    ("/wp-config.php.bak", "WordPress Config Backup", "High"),
    ("/config.php.bak", "Config Backup Exposed", "High"),
    ("/web.config.bak", "IIS Config Backup Exposed", "High"),
    ("/phpinfo.php", "PHP Info Page Exposed", "Medium"),
    ("/info.php", "PHP Info Page Exposed", "Medium"),
    ("/server-status", "Server Status Page Exposed", "Medium"),
    ("/server-info", "Server Info Page Exposed", "Medium"),
    ("/.DS_Store", "DS_Store File Exposed", "Low"),
    ("/crossdomain.xml", "Flash Cross-Domain Policy Exposed", "Low"),
    ("/clientaccesspolicy.xml", "Silverlight Policy Exposed", "Low"),
    ("/trace.axd", "ASP.NET Trace Exposed", "Medium"),
    ("/elmah.axd", "ELMAH Error Log Exposed", "High"),
    ("/actuator", "Spring Actuator Exposed", "High"),
    ("/actuator/env", "Spring Actuator Env Exposed", "High"),
    ("/console", "Admin Console Exposed", "High"),
    ("/admin/config", "Admin Config Exposed", "High"),
]

DIRECTORY_LIST_PATHS = [
    "/images/", "/uploads/", "/files/", "/assets/", "/backup/", "/tmp/",
    "/data/", "/media/", "/static/", "/public/", "/content/", "/storage/",
    "/vendor/", "/includes/", "/logs/",
]

JQUERY_VULN_PATTERNS = [
    (r"jquery[/-]1\.([0-9]+)", 12, "jQuery 1.x below 1.12 (multiple XSS CVEs)"),
    (r"jquery[/-]2\.([0-9]+)", 2, "jQuery 2.x end-of-life — upgrade to 3.x"),
    (r"jquery[/-]3\.([0-9]+)\.([0-9]+)", None, "jQuery version detected — verify against CVE database"),
    (r"bootstrap[/.-]3\.0", None, "Bootstrap 3.0.x has known XSS issues"),
    (r"bootstrap[/.-]2\.", None, "Bootstrap 2.x is outdated and unmaintained"),
    (r"angular\.js/1\.[0-5]", None, "AngularJS 1.0-1.5 has multiple XSS CVEs"),
    (r"lodash[/.-]4\.17\.([0-9]+)", 20, "Lodash below 4.17.21 has prototype pollution CVEs"),
    (r"moment[/.-]2\.([0-9]+)", 29, "Moment.js is deprecated — migrate to modern date library"),
    (r"vue[/.-]2\.", None, "Vue 2 reached end of life — upgrade to Vue 3"),
]
