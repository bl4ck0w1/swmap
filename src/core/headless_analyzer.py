# src/core/headless_analyzer.py
from __future__ import annotations

import json
import time
import pathlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse
from ..utils.logger import get_logger

logger = get_logger("headless")

try:
    from playwright.sync_api import (
        sync_playwright,
        Response,
        Page,
        Browser,
        BrowserContext,
    )
    _PW_OK = True
except Exception:
    _PW_OK = False

@dataclass
class HeadlessConfig:
    timeout_ms: int = 30_000
    backoff_attempts: int = 4
    backoff_ms: int = 500
    max_routes: int = 25
    crawl_links: bool = True
    crawl_limit: int = 50
    sw_ready_timeout_ms: int = 5_000         
    seed_nav_timeout_ms: int = 12_000        
    prove_interception: bool = True
    prove_precache: bool = True
    prove_swr: bool = True
    login_script_path: Optional[str] = None
    login_wait_selector: Optional[str] = None
    route_seeds: List[str] = field(default_factory=list)
    extra_headers: Dict[str, str] = field(default_factory=dict)
    offline_replay: bool = False
    offline_wait_ms: int = 1500
    logout_url: Optional[str] = None
    logout_script: Optional[str] = None
    nav_delay_ms: int = 0
    proxy_url: Optional[str] = None
    locale: str = "en-US"
    timezone_id: str = "UTC"
    viewport_width: int = 1366
    viewport_height: int = 768
    device_scale_factor: float = 1.0
    cookies_netscape_file: Optional[str] = None
    chrome_profile_dir: Optional[str] = None

    use_system_chrome: bool = False
    cdp_url: str = "http://localhost:9222"

    headless: bool = True

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
        if not self.enabled or not _PW_OK:
            return {
                "headless_analysis": {
                    "enabled": False,
                    "error_code": "HEADLESS_UNAVAILABLE",
                    "reason": "Headless disabled or Playwright unavailable",
                    "hint": "Install Playwright browsers with: python -m playwright install chromium",
                },
                "validation_confidence": 0.5,
            }

        seeds = list(self.cfg.route_seeds or [])
        if seed_routes:
            for r in seed_routes[: max(0, self.cfg.max_routes - len(seeds))]:
                if isinstance(r, str) and r.strip():
                    seeds.append(r)
        if "/" not in seeds:
            seeds.insert(0, "/")

        logger.debug(f"[headless] starting headless validation for {target_url} with seeds={seeds}")

        try:
            with sync_playwright() as pw:
                browser, context_or_err, mode = self._open_runtime(pw, target_url)
                if isinstance(context_or_err, dict) and context_or_err.get("error_code"):
                    return {
                        "headless_analysis": context_or_err,
                        "validation_confidence": 0.5,
                    }

                context: BrowserContext = context_or_err 

                cookie_stats = self._maybe_import_cookies(context, target_url)

                page = context.new_page()
                self._apply_polite_stealth(page)

                logger.debug(f"[headless] navigating to origin {target_url}")
                try:
                    page.goto(target_url, wait_until="domcontentloaded", timeout=self.cfg.timeout_ms)
                    if self.cfg.nav_delay_ms:
                        page.wait_for_timeout(self.cfg.nav_delay_ms)
                except Exception as e:
                    logger.debug(f"Pre-nav to {target_url} skipped/failed: {e}")

                if self.cfg.login_script_path:
                    try:
                        with open(self.cfg.login_script_path, "r", encoding="utf-8") as f:
                            script_src = f.read()
                        page.evaluate(script_src)
                    except Exception as e:
                        logger.warning(f"Unable to run login script after nav: {e}")

                if self.cfg.login_wait_selector:
                    try:
                        page.wait_for_selector(self.cfg.login_wait_selector, timeout=self.cfg.timeout_ms)
                    except Exception as e:
                        logger.warning(f"login_wait_selector timed out: {e}")

                evidence = self._run_observed_session(page, target_url, seeds)

                if self.cfg.crawl_links and evidence.get("service_worker", {}).get("controller_ready", True):
                    logger.debug("[headless] starting same-origin crawl")
                    self._crawl_same_origin(page, evidence, max_pages=self.cfg.crawl_limit)

                evidence["cache_audit"] = self._safe_cache_audit(page)

                if self.cfg.offline_replay:
                    try:
                        self._run_logout_if_any(page, target_url)
                    except Exception as e:
                        logger.debug(f"logout step failed: {e}")
                    try:
                        evidence["offline_replay"] = self._perform_offline_replay(
                            context, page, target_url, seeds
                        )
                    except Exception as e:
                        evidence["offline_replay"] = {"enabled": True, "error": str(e)}

                evidence["auth_hints"] = self._collect_auth_hints(page, evidence, target_url)

                labels, conf, reasons = self._label_strategies(evidence)
                evidence["labels"] = labels
                evidence["confidence"] = conf
                evidence["confidence_reasons"] = reasons
                evidence["runtime_mode"] = mode
                if cookie_stats:
                    evidence["cookie_import"] = cookie_stats

                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass

                return {
                    "headless_analysis": evidence,
                    "validation_confidence": conf,
                }

        except Exception as e:
            msg = str(e)
            hint = None
            code = "HEADLESS_RUNTIME_ERROR"
            if "Executable doesn't exist" in msg or "browserType.launch" in msg:
                code = "HEADLESS_MISSING_BROWSER"
                hint = "Playwright browser is missing. Run: python -m playwright install chromium"
            return {
                "headless_analysis": {
                    "enabled": True,
                    "error_code": code,
                    "error": msg,
                    **({"hint": hint} if hint else {}),
                },
                "validation_confidence": 0.5,
            }

    def _open_runtime(
        self, pw, target_url: str
    ) -> Tuple[Optional[Browser], Union[BrowserContext, Dict[str, Any]], str]:
        extra_headers = dict(self.cfg.extra_headers or {})
        user_agent = extra_headers.pop("User-Agent", None)

        if self.cfg.use_system_chrome:
            try:
                browser = pw.chromium.connect_over_cdp(self.cfg.cdp_url)
                ctxs = browser.contexts
                if ctxs:
                    context = ctxs[0]
                    if extra_headers:
                        try:
                            context.set_extra_http_headers(extra_headers)
                        except Exception:
                            pass
                    return browser, context, "cdp-system-chrome"
                context = browser.new_context(
                    ignore_https_errors=True,
                    user_agent=user_agent,
                    locale=self.cfg.locale,
                    timezone_id=self.cfg.timezone_id,
                    extra_http_headers=extra_headers or None,
                    viewport={"width": self.cfg.viewport_width, "height": self.cfg.viewport_height},
                    device_scale_factor=self.cfg.device_scale_factor,
                )
                return browser, context, "cdp-system-chrome:new-context"
            except Exception as e:
                return None, {
                    "enabled": False,
                    "error_code": "HEADLESS_CDP_CONNECT_FAILED",
                    "error": f"Failed to connect to system Chrome at {self.cfg.cdp_url}: {e}",
                    "hint": "Start Chrome with: chrome --remote-debugging-port=9222",
                }, "cdp-error"

        if self.cfg.chrome_profile_dir:
            profile_path = pathlib.Path(self.cfg.chrome_profile_dir).expanduser()
            if not profile_path.exists():
                return None, {
                    "enabled": False,
                    "error_code": "HEADLESS_PROFILE_MISSING",
                    "error": f"Chrome profile directory not found: {profile_path}",
                }, "profile-error"
            try:
                launch_kwargs: Dict[str, Any] = {"headless": self.cfg.headless}
                if self.cfg.proxy_url:
                    launch_kwargs["proxy"] = {"server": self.cfg.proxy_url}

                context = pw.chromium.launch_persistent_context(
                    user_data_dir=str(profile_path),
                    ignore_https_errors=True,
                    user_agent=user_agent,
                    locale=self.cfg.locale,
                    timezone_id=self.cfg.timezone_id,
                    extra_http_headers=extra_headers or None,
                    viewport={"width": self.cfg.viewport_width, "height": self.cfg.viewport_height},
                    device_scale_factor=self.cfg.device_scale_factor,
                    **launch_kwargs,
                )
                browser = context.browser
                return browser, context, "persistent-profile"
            except Exception as e:
                if "Executable doesn't exist" in str(e):
                    return None, {
                        "enabled": False,
                        "error_code": "HEADLESS_MISSING_BROWSER",
                        "error": str(e),
                        "hint": "Playwright browser is missing. Run: python -m playwright install chromium",
                    }, "install-missing"
                return None, {
                    "enabled": False,
                    "error_code": "HEADLESS_LAUNCH_FAILED",
                    "error": str(e),
                }, "launch-failed"

        try:
            launch_kwargs: Dict[str, Any] = {"headless": self.cfg.headless}
            if self.cfg.proxy_url:
                launch_kwargs["proxy"] = {"server": self.cfg.proxy_url}

            browser = pw.chromium.launch(**launch_kwargs)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=user_agent,
                locale=self.cfg.locale,
                timezone_id=self.cfg.timezone_id,
                extra_http_headers=extra_headers or None,
                viewport={"width": self.cfg.viewport_width, "height": self.cfg.viewport_height},
                device_scale_factor=self.cfg.device_scale_factor,
            )
            return browser, context, "default-ephemeral"
        except Exception as e:
            if "Executable doesn't exist" in str(e):
                return None, {
                    "enabled": False,
                    "error_code": "HEADLESS_MISSING_BROWSER",
                    "error": str(e),
                    "hint": "Playwright browser is missing. Run: python -m playwright install chromium",
                }, "install-missing"
            return None, {
                "enabled": False,
                "error_code": "HEADLESS_LAUNCH_FAILED",
                "error": str(e),
            }, "launch-failed"

    def _maybe_import_cookies(self, context: BrowserContext, target_url: str) -> Optional[Dict[str, Any]]:
        stats: Dict[str, Any] = {}
        if self.cfg.cookies_netscape_file:
            try:
                added = self._import_netscape_cookies(context, self.cfg.cookies_netscape_file, target_url)
                stats["netscape_file"] = {
                    "path": self.cfg.cookies_netscape_file,
                    "added": added,
                }
            except Exception as e:
                stats["netscape_file_error"] = str(e)

        if self.cfg.chrome_profile_dir:
            stats["chrome_profile"] = self.cfg.chrome_profile_dir

        return stats if stats else None

    def _import_netscape_cookies(
        self, context: BrowserContext, file_path: str, target_url: str
    ) -> int:
        fp = pathlib.Path(file_path).expanduser()
        if not fp.exists():
            raise FileNotFoundError(f"cookies file not found: {fp}")

        host = urlparse(target_url).hostname or ""
        if not host:
            return 0

        def domain_matches(cookie_domain: str, host: str) -> bool:
            cd = cookie_domain.lstrip(".").lower()
            h = host.lower()
            return h == cd or h.endswith("." + cd)

        jar: List[Dict[str, Any]] = []
        with open(fp, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) != 7:
                    continue
                domain, flag, path, secure, expires, name, value = parts
                if domain.startswith("#HttpOnly_"):
                    domain = domain.replace("#HttpOnly_", "", 1)
                    http_only = True
                else:
                    http_only = False
                if not domain_matches(domain, host):
                    continue
                try:
                    exp = int(expires)
                except Exception:
                    exp = -1
                jar.append(
                    {
                        "name": name,
                        "value": value,
                        "domain": domain,
                        "path": path or "/",
                        "expires": exp if exp > 0 else None,
                        "httpOnly": http_only,
                        "secure": (secure.upper() == "TRUE"),
                        "sameSite": "Lax",
                    }
                )

        if jar:
            context.add_cookies(jar)
        return len(jar)

    def _apply_polite_stealth(self, page: Page) -> None:
        try:
            page.add_init_script(
                """
                try {
                  Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                  });
                } catch(e){}
                """
            )
        except Exception:
            pass

    def _run_observed_session(self, page: Page, origin: str, seeds: List[str]) -> Dict[str, Any]:
        evidence: Dict[str, Any] = {
            "enabled": True,
            "origin": origin,
            "timeline": [],
            "service_worker": {
                "controller_ready": False,
                "registration": {},
            },
            "responses": [],
            "interception_stats": {"total": 0, "from_service_worker": 0},
            "visited": [],
        }

        def record_resp(resp: Response):
            try:
                from_sw = bool(resp.from_service_worker)
            except Exception:
                from_sw = False

            try:
                url = resp.url
                status = resp.status
            except Exception:
                return

            ttfb = None
            try:
                timing = resp.timing
                if timing and "startTime" in timing and "responseStart" in timing:
                    ttfb = max(0, int(timing["responseStart"] - timing["startTime"]))
            except Exception:
                pass

            evidence["responses"].append(
                {
                    "url": url,
                    "status": status,
                    "from_service_worker": from_sw,
                    "ttfb_ms": ttfb,
                }
            )
            evidence["interception_stats"]["total"] += 1
            if from_sw:
                evidence["interception_stats"]["from_service_worker"] += 1

        page.on("response", record_resp)
        page.add_init_script(
            """
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
            """
        )

        evidence["visited"].append(origin)
        sw_meta = self._wait_sw_ready_and_controller(page)
        evidence["service_worker"]["controller_ready"] = sw_meta["controller_ready"]
        evidence["service_worker"]["registration"] = sw_meta.get("registration") or {}
        evidence["timeline"].extend(sw_meta.get("timeline", []))

        controller_ready = bool(sw_meta.get("controller_ready"))

        if not controller_ready and not (
            self.cfg.prove_swr or self.cfg.prove_interception or self.cfg.prove_precache
        ):
            return evidence

        max_routes = max(0, int(self.cfg.max_routes))
        seed_timeout = getattr(self.cfg, "seed_nav_timeout_ms", self.cfg.timeout_ms)

        if max_routes > 0:
            budget = max_routes
            for seed in seeds:
                if budget <= 0:
                    break
                url = seed if seed.startswith("http") else origin.rstrip("/") + ("" if seed.startswith("/") else "/") + seed
                if url == origin:
                    continue
                logger.debug(f"[headless] visiting seed {url}")
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=seed_timeout)
                    if self.cfg.nav_delay_ms:
                        page.wait_for_timeout(self.cfg.nav_delay_ms)
                    evidence["visited"].append(url)
                    self._harvest_spa_routes(page, evidence)
                except Exception:
                    evidence["visited"].append(url + " (nav-error)")
                budget -= 1

        if (self.cfg.prove_swr or self.cfg.prove_interception) and max_routes > 0:
            for seed in seeds[: min(5, max_routes)]:
                url = seed if seed.startswith("http") else origin.rstrip("/") + ("" if seed.startswith("/") else "/") + seed
                if url == origin:
                    continue
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=seed_timeout)
                    if self.cfg.nav_delay_ms:
                        page.wait_for_timeout(self.cfg.nav_delay_ms)
                    self._harvest_spa_routes(page, evidence)
                except Exception:
                    pass

        return evidence

    def _wait_sw_ready_and_controller(self, page: Page) -> Dict[str, Any]:
        timeline: List[Dict[str, Any]] = []
        start = time.time()

        try:
            res = page.evaluate(
                f"""
                () => {{
                  if (!('serviceWorker' in navigator)) {{
                    return {{ready: false, timedOut: false}};
                  }}
                  const readyPromise = navigator.serviceWorker.ready
                    .then(r => ({{ready: true, scope: r.scope, timedOut: false}}))
                    .catch(() => ({{ready: false, timedOut: false}}));

                  const timeoutPromise = new Promise(resolve => {{
                    setTimeout(() => resolve({{ready: false, timedOut: true}}), {self.cfg.sw_ready_timeout_ms});
                  }});

                  return Promise.race([readyPromise, timeoutPromise]);
                }}
                """
            )
            if res and res.get("ready"):
                timeline.append(
                    {
                        "t": int((time.time() - start) * 1000),
                        "event": "sw.ready",
                        "scope": res.get("scope"),
                    }
                )
            elif res and res.get("timedOut"):
                timeline.append(
                    {
                        "t": int((time.time() - start) * 1000),
                        "event": "sw.ready.timeout",
                    }
                )
        except Exception:
            pass

        controller_ready = False
        for _ in range(self.cfg.backoff_attempts):
            try:
                controller_ready = bool(
                    page.evaluate("() => !!(navigator.serviceWorker && navigator.serviceWorker.controller)")
                )
            except Exception:
                controller_ready = False
            if controller_ready:
                timeline.append(
                    {
                        "t": int((time.time() - start) * 1000),
                        "event": "sw.controller",
                    }
                )
                break
            time.sleep(self.cfg.backoff_ms / 1000.0)

        registration = {}
        try:
            registration = page.evaluate(
                """
                async () => {
                  if (!('serviceWorker' in navigator)) return {};
                  const regs = await navigator.serviceWorker.getRegistrations();
                  if (!regs || !regs.length) return {};
                  const r = regs[0];
                  const d = {
                    scope: r.scope,
                    active: !!r.active,
                    installing: !!r.installing,
                    waiting: !!r.waiting
                  };
                  try {
                    d.scriptURL = r.active?.scriptURL || r.installing?.scriptURL || r.waiting?.scriptURL || null;
                  } catch(e){}
                  try { d.updateViaCache = r.updateViaCache || null; } catch(e){}
                  return d;
                }
                """
            )
            if registration:
                timeline.append(
                    {
                        "t": int((time.time() - start) * 1000),
                        "event": "sw.registration",
                        "details": registration,
                    }
                )
        except Exception:
            pass

        return {"controller_ready": controller_ready, "registration": registration, "timeline": timeline}

    def _harvest_spa_routes(self, page: Page, evidence: Dict[str, Any]) -> None:
        try:
            pushes = page.evaluate(
                "() => (Array.isArray(window.__swmap_route_log) ? window.__swmap_route_log.splice(0) : [])"
            )
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
            return page.evaluate(
                """
                async () => {
                  if (typeof caches === 'undefined')
                    return {available:false, names:[], entries:{}};
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
                """
            )
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _crawl_same_origin(self, page: Page, evidence: Dict[str, Any], max_pages: int = 50) -> None:
        origin = evidence.get("origin", "")
        seen = set(evidence.get("visited", []) or [])
        q: List[str] = []
        seed_timeout = getattr(self.cfg, "seed_nav_timeout_ms", self.cfg.timeout_ms)

        try:
            anchors = page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))") or []
        except Exception:
            anchors = []

        for a in anchors:
            if not isinstance(a, str):
                continue
            url = a if a.startswith("http") else (origin.rstrip("/") + "/" + a.lstrip("/"))
            if url.startswith(origin) and url not in seen:
                q.append(url)
                seen.add(url)

        while q and len(evidence["visited"]) < max_pages:
            url = q.pop(0)
            try:
                page.goto(url, wait_until="load", timeout=seed_timeout)
                if self.cfg.nav_delay_ms:
                    page.wait_for_timeout(self.cfg.nav_delay_ms)
                evidence["visited"].append(url)
                self._harvest_spa_routes(page, evidence)

                anchors = page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))") or []
                for a in anchors:
                    if not isinstance(a, str):
                        continue
                    new_url = a if a.startswith("http") else (origin.rstrip("/") + "/" + a.lstrip("/"))
                    if new_url.startswith(origin) and new_url not in seen:
                        q.append(new_url)
                        seen.add(new_url)
            except Exception:
                evidence["visited"].append(url + " (nav-error)")

    def _run_logout_if_any(self, page: Page, origin: str) -> None:
        if self.cfg.logout_url:
            try:
                page.goto(self.cfg.logout_url, wait_until="load", timeout=self.cfg.timeout_ms)
                if self.cfg.nav_delay_ms:
                    page.wait_for_timeout(self.cfg.nav_delay_ms)
            except Exception as e:
                logger.debug(f"logout_url failed: {e}")
        if self.cfg.logout_script:
            try:
                page.evaluate(self.cfg.logout_script)
                if self.cfg.nav_delay_ms:
                    page.wait_for_timeout(self.cfg.nav_delay_ms)
            except Exception as e:
                logger.debug(f"logout_script failed: {e}")

    def _perform_offline_replay(
        self, context: BrowserContext, page: Page, origin: str, seeds: List[str]
    ) -> Dict[str, Any]:
        out = {"enabled": True, "visited": [], "ok_count": 0}
        try:
            context.set_offline(True)
        except Exception as e:
            out["error"] = f"set_offline failed: {e}"
            return out

        try:
            page.wait_for_timeout(max(0, int(self.cfg.offline_wait_ms)))
        except Exception:
            pass

        seed_timeout = getattr(self.cfg, "seed_nav_timeout_ms", self.cfg.timeout_ms)
        replay = seeds[: min(5, self.cfg.max_routes)]
        for seed in replay:
            url = seed if seed.startswith("http") else (origin.rstrip("/") + ("" if seed.startswith("/") else "/") + seed)
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=seed_timeout)
                if self.cfg.nav_delay_ms:
                    page.wait_for_timeout(self.cfg.nav_delay_ms)
                out["visited"].append({"url": url, "status": "ok"})
                out["ok_count"] += 1
            except Exception:
                out["visited"].append({"url": url, "status": "nav-error"})

        try:
            context.set_offline(False)
        except Exception:
            pass

        return out

    def _collect_auth_hints(
        self, page: Page, evidence: Dict[str, Any], target_url: str
    ) -> Dict[str, Any]:
        hints: Dict[str, Any] = {
            "saw_401_403": False,
            "saw_login_words": False,
            "saw_password_field": False,
            "login_like_url": False,
        }

        origin_host = urlparse(target_url).hostname or ""

        try:
            for r in evidence.get("responses", []):
                status = int(r.get("status") or 0)
                url = r.get("url") or ""
                host = urlparse(url).hostname or ""
                same_origin = (origin_host and host == origin_host)
                if same_origin and status in (401, 403):
                    hints["saw_401_403"] = True
                    break
        except Exception:
            pass

        try:
            txt = page.inner_text("body", timeout=1000)
            low = (txt or "")[:5000].lower()
            for w in ("sign in", "signin", "log in", "login", "authenticate", "single sign-on", "sso"):
                if w in low:
                    hints["saw_login_words"] = True
                    break
        except Exception:
            pass

        try:
            pwd = page.query_selector("input[type='password']")
            if pwd is not None:
                hints["saw_password_field"] = True
        except Exception:
            pass

        try:
            cur = page.url.lower()
            if any(k in cur for k in ("login", "signin", "account", "auth")):
                hints["login_like_url"] = True
        except Exception:
            pass

        return hints

    def _label_strategies(self, ev: Dict[str, Any]) -> Tuple[List[str], float, List[str]]:
        labels: List[str] = []
        reasons: List[str] = []
        conf = 0.5

        cache_names = (ev.get("cache_audit") or {}).get("names") or []
        if any("workbox-precache" in n or "flutter" in n or "precache" in n for n in cache_names):
            labels.append("precaching")
            reasons.append("Cache names hint at precache.")
            conf *= 1.15

        stats = ev.get("interception_stats") or {}
        from_sw = int(stats.get("from_service_worker") or 0)
        total = int(stats.get("total") or 0)
        if total >= 4 and from_sw / max(1, total) >= 0.5:
            labels.append("intercepts_majority")
            reasons.append(f"{from_sw}/{total} responses from SW.")
            conf *= 1.10
        elif from_sw > 0:
            labels.append("intercepts_some")
            reasons.append(f"{from_sw}/{total} responses from SW.")
            conf *= 1.05

        if self._cfg_prove_swr(ev):
            labels.append("stale_while_revalidate_suspected")
            reasons.append("Fast SW response followed by later network load observed.")
            conf *= 1.05

        off = ev.get("offline_replay") or {}
        if off.get("enabled") and int(off.get("ok_count") or 0) >= 1:
            labels.append("offline_capable")
            reasons.append("At least one route rendered offline.")
            conf *= 1.07

        ah = ev.get("auth_hints") or {}
        if (
            ah.get("saw_401_403")
            or ah.get("saw_login_words")
            or ah.get("saw_password_field")
            or ah.get("login_like_url")
        ):
            labels.append("auth_gate")
            reasons.append("Auth/login indicators detected in headless session.")

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
