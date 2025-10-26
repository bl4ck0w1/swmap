# src/core/headless_analyzer.py
from __future__ import annotations
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple
from ..utils.logger import get_logger

logger = get_logger("headless")

try:
    from playwright.sync_api import sync_playwright, Response, Page
    _PW_OK = True
except Exception:
    _PW_OK = False

@dataclass
class HeadlessConfig:
    timeout_ms: int = 30000
    backoff_attempts: int = 4
    backoff_ms: int = 500
    max_routes: int = 25
    crawl_links: bool = True
    crawl_limit: int = 50
    prove_interception: bool = True
    prove_precache: bool = True
    prove_swr: bool = True
    login_script_path: Optional[str] = None
    login_wait_selector: Optional[str] = None
    route_seeds: List[str] = field(default_factory=list)
    extra_headers: Dict[str, str] = field(default_factory=dict)

class HeadlessAnalysisManager:

    def __init__(self, enable_headless: bool, config: Optional[HeadlessConfig] = None):
        self.enabled = bool(enable_headless and _PW_OK)
        self.cfg = config or HeadlessConfig()
        if not _PW_OK:
            logger.info("Playwright not available — headless analysis disabled.")

    def validate_static_findings(
        self,
        static_findings: Dict[str, Any],
        target_url: str,
        seed_routes: Optional[List[str]] = None,
        effective_scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.enabled:
            return {
                "headless_analysis": {
                    "enabled": False,
                    "reason": "Headless disabled or Playwright unavailable",
                }
            }

        seeds = list(self.cfg.route_seeds or [])
        if seed_routes:
            for r in seed_routes[: max(0, self.cfg.max_routes - len(seeds))]:
                if isinstance(r, str) and r.strip():
                    seeds.append(r)
        if "/" not in seeds:
            seeds.insert(0, "/")

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=self.cfg.extra_headers or {}
                )
                page = context.new_page()

                if self.cfg.login_script_path:
                    try:
                        with open(self.cfg.login_script_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        context.add_init_script(content)
                        logger.info("Injected login script.")
                    except Exception as e:
                        logger.warning(f"Unable to inject login script: {e}")

                evidence = self._run_observed_session(page, target_url, seeds)

                if self.cfg.login_wait_selector:
                    try:
                        page.wait_for_selector(self.cfg.login_wait_selector, timeout=self.cfg.timeout_ms)
                        logger.info("Login wait selector satisfied.")
                    except Exception:
                        pass

                if self.cfg.crawl_links:
                    self._crawl_same_origin(page, evidence, max_pages=self.cfg.crawl_limit)

                evidence["cache_audit"] = self._safe_cache_audit(page)

                labels, conf, reasons = self._label_strategies(evidence)
                evidence["labels"] = labels
                evidence["confidence"] = conf
                evidence["confidence_reasons"] = reasons

                context.close()
                browser.close()
                return {"headless_analysis": evidence}

        except Exception as e:
            logger.warning(f"Headless validation failed: {e}")
            return {
                "headless_analysis": {
                    "enabled": True,
                    "error": str(e),
                }
            }

    def _run_observed_session(self, page: Page, origin: str, seeds: List[str]) -> Dict[str, Any]:
        evidence: Dict[str, Any] = {
            "enabled": True,
            "origin": origin,
            "timeline": [],
            "service_worker": {
                "controller_ready": False,
                "versions": [],
                "registration": {},
            },
            "responses": [],   
            "interception_stats": {"total": 0, "from_sw": 0},
            "visited": [],
        }

        def record_resp(resp: Response):
            try:
                timing = resp.timing
            except Exception:
                timing = None

            from_sw = False
            try:
                from_sw = bool(resp.from_service_worker)
            except Exception:
                pass
            try:
                url = resp.url
                status = resp.status
            except Exception:
                return

            ttfb = None
            try:
                if timing and "startTime" in timing and "responseStart" in timing:
                    ttfb = max(0, int(timing["responseStart"] - timing["startTime"]))
            except Exception:
                pass

            evidence["responses"].append({
                "url": url,
                "status": status,
                "from_service_worker": from_sw,
                "ttfb_ms": ttfb,
            })
            evidence["interception_stats"]["total"] += 1
            if from_sw:
                evidence["interception_stats"]["from_sw"] += 1

        page.on("response", record_resp)

        page.add_init_script("""
            window.__swmap_route_log = [];
            (function(){
              const push = history.pushState;
              history.pushState = function(s, t, url){
                try { window.__swmap_route_log.push(String(url || '')); } catch(e){}
                return push.apply(this, arguments);
              };
              window.addEventListener('hashchange', function(){
                try { window.__swmap_route_log.push(String(location.href || '')); } catch(e){}
              });
            })();
        """)

        page.goto(origin, wait_until="load", timeout=self.cfg.timeout_ms)
        evidence["visited"].append(origin)

        sw_meta = self._wait_sw_ready_and_controller(page)
        evidence["service_worker"]["controller_ready"] = sw_meta["controller_ready"]
        evidence["service_worker"]["registration"] = sw_meta.get("registration") or {}
        evidence["timeline"].extend(sw_meta.get("timeline", []))

        for seed in seeds[: self.cfg.max_routes]:
            if seed.startswith("http"):
                url = seed
            else:
                url = origin.rstrip("/") + ("" if seed.startswith("/") else "/") + seed
            try:
                page.goto(url, wait_until="load", timeout=self.cfg.timeout_ms)
                evidence["visited"].append(url)
                self._harvest_spa_routes(page, evidence)
            except Exception:
                evidence["visited"].append(url + " (nav-error)")
                continue

        if self.cfg.prove_swr or self.cfg.prove_interception:
            for seed in seeds[: min(5, self.cfg.max_routes)]:
                url = origin.rstrip("/") + ("" if seed.startswith("/") else "/") + seed
                try:
                    page.goto(url, wait_until="load", timeout=self.cfg.timeout_ms)
                    self._harvest_spa_routes(page, evidence)
                except Exception:
                    pass

        return evidence

    def _wait_sw_ready_and_controller(self, page: Page) -> Dict[str, Any]:
        timeline: List[Dict[str, Any]] = []
        start = time.time()
        try:
            res = page.evaluate("""
                () => {
                  if (!('serviceWorker' in navigator)) return {ready:false};
                  return navigator.serviceWorker.ready.then(r => ({ready:true, scope: r.scope})).catch(()=>({ready:false}));
                }
            """)
            if res and res.get("ready"):
                timeline.append({"t": int((time.time()-start)*1000), "event": "sw.ready", "scope": res.get("scope")})
        except Exception:
            pass

        controller_ready = False
        for i in range(self.cfg.backoff_attempts):
            try:
                controller_ready = bool(page.evaluate("() => !!(navigator.serviceWorker && navigator.serviceWorker.controller)"))
            except Exception:
                controller_ready = False
            if controller_ready:
                timeline.append({"t": int((time.time()-start)*1000), "event": "sw.controller"})
                break
            time.sleep(self.cfg.backoff_ms / 1000.0)

        registration = {}
        try:
            registration = page.evaluate("""
                async () => {
                  if (!('serviceWorker' in navigator)) return {};
                  const regs = await navigator.serviceWorker.getRegistrations();
                  if (!regs || !regs.length) return {};
                  const r = regs[0];
                  const d = { scope: r.scope, active: !!r.active, installing: !!r.installing, waiting: !!r.waiting };
                  try { d.scriptURL = r.active?.scriptURL || r.installing?.scriptURL || r.waiting?.scriptURL || null; } catch(e){}
                  return d;
                }
            """)
            if registration:
                timeline.append({"t": int((time.time()-start)*1000), "event": "sw.registration", "details": registration})
        except Exception:
            pass

        return {"controller_ready": controller_ready, "registration": registration, "timeline": timeline}

    def _harvest_spa_routes(self, page: Page, evidence: Dict[str, Any]) -> None:
        try:
            pushes = page.evaluate("() => (Array.isArray(window.__swmap_route_log) ? window.__swmap_route_log.splice(0) : [])")
            origin = evidence.get("origin", "")
            for raw in (pushes or []):
                if not isinstance(raw, str):
                    continue
                url = raw if raw.startswith("http") else (origin.rstrip("/") + "/" + raw.lstrip("/"))
                if url not in evidence["visited"]:
                    evidence["visited"].append(url)
        except Exception:
            pass

    def _safe_cache_audit(self, page: Page) -> Dict[str, Any]:
        try:
            return page.evaluate("""
                async () => {
                  if (typeof caches === 'undefined') return {available:false, names:[], entries:{}};
                  const names = await caches.keys();
                  const entries = {};
                  for (const n of names) {
                    try {
                      const c = await caches.open(n);
                      const reqs = await c.keys();
                      entries[n] = reqs.map(r => r.url);
                    } catch(e) {
                      entries[n] = ["<error>"];
                    }
                  }
                  return {available:true, names, entries};
                }
            """)
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _crawl_same_origin(self, page: Page, evidence: Dict[str, Any], max_pages: int = 50) -> None:
        origin = evidence.get("origin", "")
        seen = set(evidence.get("visited", []) or [])
        q: List[str] = []

        try:
            anchors = page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))") or []
        except Exception:
            anchors = []

        for a in anchors:
            if not isinstance(a, str):
                continue
            url = a if a.startswith("http") else (origin.rstrip("/") + "/" + a.lstrip("/"))
            if url.startswith(origin) and url not in seen:
                q.append(url); seen.add(url)

        while q and len(evidence["visited"]) < max_pages:
            url = q.pop(0)
            try:
                page.goto(url, wait_until="load", timeout=self.cfg.timeout_ms)
                evidence["visited"].append(url)
                self._harvest_spa_routes(page, evidence)
                anchors = page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))") or []
                for a in anchors:
                    if not isinstance(a, str):
                        continue
                    new_url = a if a.startswith("http") else (origin.rstrip("/") + "/" + a.lstrip("/"))
                    if new_url.startswith(origin) and new_url not in seen:
                        q.append(new_url); seen.add(new_url)
            except Exception:
                evidence["visited"].append(url + " (nav-error)")

    def _label_strategies(self, ev: Dict[str, Any]) -> Tuple[List[str], float, List[str]]:
        labels: List[str] = []
        reasons: List[str] = []
        conf = 0.5

        # obvious precache
        cache_names = (ev.get("cache_audit") or {}).get("names") or []
        entries = (ev.get("cache_audit") or {}).get("entries") or {}
        if any("workbox-precache" in n or "flutter" in n or "precache" in n for n in cache_names):
            labels.append("precaching")
            reasons.append("Cache names hint at precache.")
            conf *= 1.15

        stats = ev.get("interception_stats") or {}
        from_sw = int(stats.get("from_sw") or 0)
        total = int(stats.get("total") or 0)
        if total >= 4 and from_sw / max(1, total) >= 0.5:
            labels.append("intercepts_majority")
            reasons.append(f"{from_sw}/{total} responses from SW.")
            conf *= 1.1

        if self._cfg_prove_swr(ev):
            labels.append("staleWhileRevalidate?")  
            reasons.append("Fast SW response followed by later network load observed.")
            conf *= 1.05

        return sorted(set(labels)), min(conf, 1.0), reasons

    def _cfg_prove_swr(self, ev: Dict[str, Any]) -> bool:
        if not self.cfg.prove_swr:
            return False
        seen = {}
        for r in ev.get("responses") or []:
            url = r.get("url")
            fsw = bool(r.get("from_service_worker"))
            if url not in seen:
                seen[url] = fsw
            else:
                if seen[url] and not fsw:
                    return True
        return False
