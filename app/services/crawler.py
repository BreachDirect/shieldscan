"""Lightweight BFS crawler with path seeding and robots/sitemap discovery."""

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

import httpx

from app.services.constants import COMMON_PROBE_PATHS

LINK_RE = re.compile(r"""href=["']([^"'#>]+)["']""", re.I)
ACTION_RE = re.compile(r"""action=["']([^"']+)["']""", re.I)
FORM_RE = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
FORM_ACTION_RE = re.compile(r"""action=["']([^"']*)["']""", re.I)
FORM_METHOD_RE = re.compile(r"""method=["']([^"']*)["']""", re.I)
INPUT_RE = re.compile(r"""<(?:input|textarea|select)[^>]*name=["']([^"']+)["']""", re.I)
API_RE = re.compile(r"""["'](/api[^"']*)["']""", re.I)

CSRF_RE = re.compile(
    r"name=[\"'](csrf|_csrf|csrfmiddlewaretoken|token|_token|authenticity_token|"
    r"__requestverificationtoken|csrftoken)[\"']",
    re.I,
)


@dataclass
class FormInfo:
    page_url: str
    action_url: str
    method: str
    fields: list[str]
    has_csrf_token: bool


@dataclass
class CrawlResult:
    pages: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    param_urls: list[tuple[str, str, str]] = field(default_factory=list)


def _same_origin(base: str, candidate: str) -> bool:
    b, c = urlparse(base), urlparse(candidate)
    return b.netloc == c.netloc and c.scheme in ("http", "https")


def _normalize_url(base: str, link: str) -> str | None:
    full = urljoin(base, link.strip())
    parsed = urlparse(full)
    if parsed.scheme not in ("http", "https"):
        return None
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


async def _discover_robots_sitemap(start_url: str, client: httpx.AsyncClient) -> list[str]:
    urls: list[str] = []
    origin = _origin(start_url)
    for path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
        try:
            resp = await client.get(origin + path, timeout=8.0)
            if resp.status_code != 200:
                continue
            text = resp.text or ""
            if "robots" in path:
                for line in text.splitlines():
                    if line.lower().startswith(("allow:", "disallow:")):
                        part = line.split(":", 1)[1].strip()
                        if part and part not in ("/", "*") and "*" not in part:
                            urls.append(urljoin(origin, part))
            else:
                urls.extend(re.findall(r"<loc>([^<]+)</loc>", text, re.I))
        except Exception:
            pass
    return urls[:50]


def _parse_forms(page_url: str, html: str) -> list[FormInfo]:
    forms: list[FormInfo] = []
    for form_match in FORM_RE.finditer(html):
        block = form_match.group(0)
        action_m = FORM_ACTION_RE.search(block)
        method_m = FORM_METHOD_RE.search(block)
        action = urljoin(page_url, action_m.group(1)) if action_m else page_url
        method = (method_m.group(1) if method_m else "get").lower()
        fields = INPUT_RE.findall(block)
        csrf = bool(CSRF_RE.search(block))
        if fields:
            forms.append(FormInfo(page_url, action, method, fields, csrf))
    return forms


async def crawl_site(
    start_url: str,
    client: httpx.AsyncClient,
    max_pages: int = 40,
    max_depth: int = 3,
) -> CrawlResult:
    result = CrawlResult()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(start_url, 0)]

    # Seed queue with common paths and robots/sitemap URLs
    origin = _origin(start_url)
    for path in COMMON_PROBE_PATHS:
        queue.append((urljoin(origin, path), 1))
    for url in await _discover_robots_sitemap(start_url, client):
        queue.append((url, 1))

    while queue and len(result.pages) < max_pages:
        url, depth = queue.pop(0)
        norm = _normalize_url(url, url) or url
        if norm in visited:
            continue
        visited.add(norm)

        try:
            resp = await client.get(norm, follow_redirects=True, timeout=12.0)
        except Exception:
            continue

        final_url = str(resp.url)
        if final_url not in visited:
            visited.add(final_url)
        if final_url not in result.pages:
            result.pages.append(final_url)

        parsed = urlparse(final_url)
        if parsed.query:
            for param, values in parse_qs(parsed.query).items():
                if values:
                    result.param_urls.append((final_url, param, values[0]))

        html = resp.text or ""
        result.forms.extend(_parse_forms(final_url, html))

        # API paths embedded in HTML/JS
        for api_path in API_RE.findall(html)[:10]:
            api_url = urljoin(final_url, api_path)
            if _same_origin(start_url, api_url) and api_url not in visited:
                queue.append((api_url, depth + 1))

        if depth >= max_depth:
            continue

        for link in LINK_RE.findall(html)[:30]:
            nxt = _normalize_url(final_url, link)
            if nxt and _same_origin(start_url, nxt) and nxt not in visited:
                queue.append((nxt, depth + 1))

        for action in ACTION_RE.findall(html)[:20]:
            nxt = _normalize_url(final_url, action)
            if nxt and _same_origin(start_url, nxt) and nxt not in visited:
                queue.append((nxt, depth + 1))

    return result
