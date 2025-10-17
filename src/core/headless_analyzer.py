from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from ..models.exceptions import AnalysisException
from ..utils.logger import get_logger

logger = get_logger("headless_analyzer")

@dataclass
class HeadlessAnalysisResult:
    sw_registered: bool = False
    sw_scope: str = ""
    lifecycle_events: List[str] = field(default_factory=list)
    intercepted_routes: List[Dict[str, Any]] = field(default_factory=list)
    cache_operations: List[Dict[str, Any]] = field(default_factory=list)  
    network_requests: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class HeadlessAnalyzer:
    def __init__(self, headless: bool = True, timeout_ms: int = 30000):
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.playwright_available = self._check_playwright()

    def _check_playwright(self) -> bool:
        try:
            from playwright.async_api import async_playwright  # noqa: F401
            logger.info("Playwright detected — headless analysis enabled.")
            return True
        except Exception:
            logger.info("Playwright not available — headless analysis disabled.")
            return False

    async def analyze_service_worker(self, url: str, routes_to_test: Optional[List[str]] = None) -> HeadlessAnalysisResult:
        if not self.playwright_available:
            raise AnalysisException("Playwright not available for headless analysis")

        from playwright.async_api import async_playwright, Error as PWError

        result = HeadlessAnalysisResult()
        routes_to_test = routes_to_test or []

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context()  
                page = await context.new_page()
                page.on("request", lambda r: result.network_requests.append({
                    "url": r.url, "method": r.method, "headers": dict(r.headers), "ts": asyncio.get_event_loop().time()
                }))
                page.on("response", lambda rsp: result.intercepted_routes.append({
                    "url": rsp.url, "status": rsp.status, "served_by_sw": getattr(rsp, "from_service_worker", False)
                }))

                try:
                    logger.info("Headless: navigating to %s", url)
                    await page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
                    await self._wait_for_sw(context, result)
                    if result.sw_registered:
                        await self._trigger_sw_events(page, result)
                        if routes_to_test:
                            await self._test_routes(page, routes_to_test, result)
                except PWError as e:
                    result.errors.append(f"Navigation error: {e}")

                await browser.close()
        except Exception as e:
            logger.error("Headless analysis failed: %s", e)
            result.errors.append(f"Headless analysis failed: {e}")

        return result

    async def _wait_for_sw(self, context, result: HeadlessAnalysisResult) -> None:
        try:
            await context.wait_for_event("serviceworker", timeout=self.timeout_ms)
        except Exception:
            pass

        try:
            for w in context.service_workers:
                result.sw_registered = True
                result.sw_scope = w.url or result.sw_scope
        except Exception:
            result.warnings.append("Could not enumerate service workers")

    async def _trigger_sw_events(self, page, result: HeadlessAnalysisResult) -> None:
        try:
            await page.reload(wait_until="networkidle")
        except Exception as e:
            result.warnings.append(f"Reload failed: {e}")

        try:
            msg = await page.evaluate(
                """
                (async () => {
                  if (!('serviceWorker' in navigator)) return 'no sw api';
                  const reg = await navigator.serviceWorker.getRegistration().catch(() => null);
                  if (!reg) return 'no registration';
                  try {
                    // Touch the registration to ensure activation
                    return reg.scope || 'ok';
                  } catch (e) { return 'inspect failed'; }
                })()
                """
            )
            if isinstance(msg, str) and msg not in ("ok", "no sw api", "no registration", "inspect failed"):
                result.lifecycle_events.append(f"registration: {msg}")
        except Exception:
            pass

    async def _test_routes(self, page, routes: List[str], result: HeadlessAnalysisResult) -> None:
        parsed = urlparse(page.url or "")
        base = f"{parsed.scheme}://{parsed.netloc}"
        for r in routes[:10]:  # clamp
            url = f"{base}{r}" if r.startswith("/") else r
            try:
                rsp = await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                if rsp:
                    result.intercepted_routes.append({
                        "url": url,
                        "status": rsp.status,
                        "served_by_sw": getattr(rsp, "from_service_worker", False),
                    })
            except Exception as e:
                result.warnings.append(f"Route test failed for {url}: {e}")

    def analyze_sync(self, url: str, routes_to_test: Optional[List[str]] = None) -> HeadlessAnalysisResult:
        if not self.playwright_available:
            raise AnalysisException("Playwright not available")
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self.analyze_service_worker(url, routes_to_test or []))


class HeadlessAnalysisManager:
    def __init__(self, enable_headless: bool = False, headless: bool = True, timeout_ms: int = 30000):
        analyzer = HeadlessAnalyzer(headless=headless, timeout_ms=timeout_ms)
        self.enable_headless = enable_headless and analyzer.playwright_available
        self.analyzer = analyzer if self.enable_headless else None

    def validate_static_findings(self, static_results: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        if not self.enable_headless or not self.analyzer:
            static_results["headless_analysis"] = {
                "available": False,
                "reason": "Headless disabled or Playwright not available",
            }
            return static_results

        try:
            routes_to_test = list(static_results.get("routes_seen", []))[:10]
            h = self.analyzer.analyze_sync(target_url, routes_to_test)
            static_results["headless_analysis"] = {
                "available": True,
                "sw_registered": h.sw_registered,
                "sw_scope": h.sw_scope,
                "intercepted_routes_validated": [r for r in h.intercepted_routes if r.get("served_by_sw")],
                "network_requests_observed": len(h.network_requests),
                "errors": h.errors,
                "warnings": h.warnings,
            }
            static_results["validation_confidence"] = self._confidence(static_results, h)
        except Exception as e:
            logger.error("Headless validation failed: %s", e)
            static_results["headless_analysis"] = {"available": True, "errors": [f"Headless failed: {e}"]}
        return static_results

    def _confidence(self, static_results: Dict[str, Any], h: HeadlessAnalysisResult) -> float:
        score = 1.0
        if h.sw_registered:
            if static_results.get("sw_url"):
                score *= 1.2
            static_routes = set(static_results.get("routes_seen", []))
            validated = {
                r.get("url", "") for r in h.intercepted_routes if r.get("served_by_sw")
            }
            if validated and static_routes:
                overlap = {u for u in validated if any(u.endswith(sr) for sr in static_routes)}
                if overlap:
                    score *= 1.1 + (min(len(overlap), len(static_routes)) / max(1, len(static_routes))) * 0.5
        else:
            if static_results.get("sw_url"):
                score *= 0.7
        return min(score, 2.0)

headless_manager = HeadlessAnalysisManager()
