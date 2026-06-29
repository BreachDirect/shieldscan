import logging
from typing import Any, Callable

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)


class ZAPClient:
    """Client for OWASP ZAP REST API."""

    def __init__(self, settings: Settings):
        self.base_url = settings.zap_api_url.rstrip("/")
        self.api_key = settings.zap_api_key
        self.spider_timeout = settings.scan_spider_timeout
        self.active_timeout = settings.scan_active_timeout

    def _params(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        params = {"apikey": self.api_key}
        if extra:
            params.update(extra)
        return params

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/JSON/core/view/version/", params=self._params())
                return resp.status_code == 200 and "version" in resp.json()
        except Exception as exc:
            logger.warning("ZAP unavailable: %s", exc)
            return False

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.get(f"{self.base_url}{path}", params=self._params(params))
            resp.raise_for_status()
            return resp.json()

    async def new_session(self, name: str = "shieldscan") -> None:
        await self._get("/JSON/core/action/newSession/", {"name": name, "overwrite": "true"})

    async def access_url(self, url: str) -> None:
        await self._get("/JSON/core/action/accessUrl/", {"url": url, "followRedirects": "true"})

    async def spider(self, url: str, on_progress: Callable[[str], None] | None = None) -> str:
        data = await self._get(
            "/JSON/spider/action/scan/",
            {"url": url, "maxChildren": "100", "recurse": "true", "subtreeOnly": "false"},
        )
        scan_id = str(data["scan"])
        await self._wait_scan(
            "/JSON/spider/view/status/",
            scan_id,
            self.spider_timeout,
            on_progress,
            "Spidering",
        )
        return scan_id

    async def ajax_spider(self, url: str, on_progress: Callable[[str], None] | None = None) -> None:
        """Optional AJAX spider for JavaScript-heavy apps (Juice Shop, SPAs)."""
        try:
            await self._get("/JSON/ajaxSpider/action/setOptionMaxDuration/", {"Integer": "10"})
            await self._get("/JSON/ajaxSpider/action/scan/", {"url": url, "inScope": "true"})
            if on_progress:
                on_progress("AJAX spider started for JavaScript pages")
            import asyncio

            elapsed = 0
            while elapsed < 120:
                status = await self._get("/JSON/ajaxSpider/view/status/")
                if status.get("status") == "stopped":
                    return
                if on_progress and elapsed % 10 == 0:
                    on_progress("AJAX spider running...")
                await asyncio.sleep(3)
                elapsed += 3
        except Exception as exc:
            logger.debug("AJAX spider skipped: %s", exc)

    async def passive_scan_wait(self, on_progress: Callable[[str], None] | None = None) -> None:
        """Wait for passive scan to finish processing spider traffic."""
        import asyncio

        if on_progress:
            on_progress("Passive scan analysing discovered traffic")
        elapsed = 0
        while elapsed < 90:
            try:
                data = await self._get("/JSON/pscan/view/recordsToScan/")
                remaining = int(data.get("recordsToScan", 0))
                if on_progress and elapsed % 6 == 0:
                    on_progress(f"Passive scan: {remaining} records remaining")
                if remaining <= 0:
                    return
            except Exception:
                return
            await asyncio.sleep(3)
            elapsed += 3

    async def active_scan(self, url: str, on_progress: Callable[[str], None] | None = None) -> str:
        data = await self._get(
            "/JSON/ascan/action/scan/",
            {
                "url": url,
                "recurse": "true",
                "inScopeOnly": "false",
                "scanPolicyName": "",
                "method": "",
                "postData": "",
            },
        )
        scan_id = str(data["scan"])
        await self._wait_scan(
            "/JSON/ascan/view/status/",
            scan_id,
            self.active_timeout,
            on_progress,
            "Active scanning",
        )
        return scan_id

    async def _wait_scan(
        self,
        status_path: str,
        scan_id: str,
        timeout: int,
        on_progress: Callable[[str], None] | None,
        label: str,
    ) -> None:
        import asyncio

        elapsed = 0
        while elapsed < timeout:
            data = await self._get(status_path, {"scanId": scan_id})
            status = int(data.get("status", 100))
            if on_progress:
                on_progress(f"{label}: {status}%")
            if status >= 100:
                return
            await asyncio.sleep(2)
            elapsed += 2
        logger.warning("%s timed out after %ss", label, timeout)

    async def get_alerts(self, base_url: str) -> list[dict[str, Any]]:
        all_alerts: list[dict[str, Any]] = []
        start = 0
        page_size = 500
        while start < 2000:
            data = await self._get(
                "/JSON/alert/view/alerts/",
                {"baseurl": base_url, "start": str(start), "count": str(page_size)},
            )
            batch = data.get("alerts", [])
            if not batch:
                break
            all_alerts.extend(batch)
            if len(batch) < page_size:
                break
            start += page_size
        return all_alerts

    async def run_full_scan(
        self,
        target_url: str,
        on_progress: Callable[[str], None] | None = None,
    ) -> list[dict[str, Any]]:
        await self.new_session()
        if on_progress:
            on_progress("Initialising ZAP session")
        await self.access_url(target_url)
        if on_progress:
            on_progress("Starting spider (up to 100 children per node)")
        await self.spider(target_url, on_progress)
        await self.ajax_spider(target_url, on_progress)
        await self.passive_scan_wait(on_progress)
        if on_progress:
            on_progress("Starting active scan (full attack payload suite)")
        await self.active_scan(target_url, on_progress)
        if on_progress:
            on_progress("Collecting alerts")
        return await self.get_alerts(target_url)
