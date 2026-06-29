"""Normalise findings for display — fill missing parameter labels."""

from urllib.parse import urlparse

from app.schemas import Finding


def enrich_finding_parameter(finding: Finding) -> Finding:
    """Assign a meaningful parameter label when scanners leave it blank."""
    if finding.parameter and finding.parameter.strip():
        return finding

    name = finding.name.lower()
    fid = finding.id.lower()

    if fid.startswith("header-") or "header" in name or "content-security-policy" in name:
        param = "Site security settings"
    elif "cookie" in name:
        param = "Login cookies"
    elif any(k in name for k in ("tls", "certificate", "ssl", "https")):
        param = "Secure connection (HTTPS)"
    elif "cors" in name:
        param = "Access-Control-Allow-Origin"
    elif "csrf" in name:
        param = "HTML form (no CSRF token)"
    elif "directory listing" in name:
        param = urlparse(finding.url).path or "URL path"
    elif any(k in name for k in ("exposed", "disclosure", "backup", "git", ".env")):
        param = urlparse(finding.url).path or "URL path"
    elif "redirect" in name:
        param = "redirect URL parameter"
    elif "authentication" in name or "login" in name:
        param = "Login endpoint"
    elif finding.source == "passive":
        param = "HTTP response"
    elif finding.evidence:
        param = "(see evidence)"
    else:
        param = "Whole site"

    return finding.model_copy(update={"parameter": param})


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    return [enrich_finding_parameter(f) for f in findings]
