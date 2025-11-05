# src/core/scanner.py
from __future__ import annotations

import concurrent.futures
import logging
import time
import threading
import random
from contextlib import contextmanager
from typing import List, Dict, Any, Optional, Generator, Tuple
from urllib.parse import urlparse, urljoin
from .fetcher import AdvancedFetcher
from .parser import SWParser
from .analyzer import SWAnalyzer
from .security_analyzer import SecurityAnalyzer
from .risk_assessor import RiskAssessor
from .normalizer import URLNormalizer
from .enhanced_analyzer import EnhancedAnalyzer, EnhancedAnalysisConfig
from ..models.target import ScanTarget
from ..models.result import SWResult

try:
    from ..models.exceptions import NetworkException, SecurityException 
except Exception:  
    NetworkException = Exception  
    SecurityException = Exception  

logger = logging.getLogger(__name__)


class SWScanner:
    def __init__(
        self,
        parallel: int = 6,
        timeout: int = 15,
        max_sw_bytes: int = 512 * 1024,
        max_routes: int = 50,
        user_agent: str | None = None,
        headers: Dict[str, str] | None = None,
        cookies: str | None = None,
        no_risk_assessment: bool = False,
        enable_ast_analysis: bool = True,
        ast_max_depth: int = 0,
        ast_request_timeout: int = 10,
        enable_headless_analysis: bool = False,
        headless_timeout_ms: int = 30_000,
        headless_max_routes: int = 25,
        headless_crawl: bool = True,
        headless_crawl_limit: int = 50,
        headless_backoff_attempts: int = 4,
        headless_backoff_ms: int = 500,
        headless_prove_interception: bool = True,
        headless_prove_precache: bool = True,
        headless_prove_swr: bool = True,
        headless_login_script: Optional[str] = None,
        headless_login_wait_selector: Optional[str] = None,
        headless_route_seeds: Optional[List[str]] = None,
        headless_offline_replay: bool = False,
        headless_offline_wait_ms: int = 1500,
        headless_logout_url: Optional[str] = None,
        headless_logout_script: Optional[str] = None,
        headless_nav_delay_ms: int = 0,
        proxy_url: Optional[str] = None,
        headless_cookies_netscape_file: Optional[str] = None,
        per_host_limit: int = 3,
        jitter_min_ms: int = 20,
        jitter_max_ms: int = 80,
        vendor_probe_limit: int = 8,
    ):
        self.parallel = parallel
        self.timeout = timeout
        self.max_sw_bytes = max_sw_bytes
        self.max_routes = max_routes
        self.user_agent = user_agent
        self.headers = headers or {}
        self.cookies = cookies
        self.no_risk_assessment = no_risk_assessment
        self.proxy_url = proxy_url
        self.headless_nav_delay_ms = headless_nav_delay_ms
        self.vendor_probe_limit = max(1, int(vendor_probe_limit))
        self.headless_cookies_netscape_file = headless_cookies_netscape_file
        self.per_host_limit = max(1, per_host_limit)
        self._host_sems: Dict[str, threading.Semaphore] = {}
        self._host_sem_lock = threading.Lock()
        self.jitter_min = max(0, int(jitter_min_ms))
        self.jitter_max = max(self.jitter_min, int(jitter_max_ms))

        try:
            self.fetcher = AdvancedFetcher(timeout=timeout, user_agent=user_agent, proxy=proxy_url)
        except TypeError:
            logger.debug("AdvancedFetcher has no 'proxy' parameter; update fetcher to honor --proxy.")
            self.fetcher = AdvancedFetcher(timeout=timeout, user_agent=user_agent)

        self.parser = SWParser()
        self.analyzer = SWAnalyzer()
        self.security_analyzer = SecurityAnalyzer()
        self.risk_assessor = RiskAssessor()
        self.normalizer = URLNormalizer()
        self.enable_ast_analysis = enable_ast_analysis
        self.enable_headless_analysis = enable_headless_analysis

        ea_kwargs = dict(
            enable_ast=enable_ast_analysis,
            enable_headless=enable_headless_analysis,
            ast_max_depth=ast_max_depth,
            ast_request_timeout=ast_request_timeout,
            headless_timeout_ms=headless_timeout_ms,
            headless_max_routes=headless_max_routes,
            headless_crawl=headless_crawl,
            headless_crawl_limit=headless_crawl_limit,
            headless_backoff_attempts=headless_backoff_attempts,
            headless_backoff_ms=headless_backoff_ms,
            headless_prove_interception=headless_prove_interception,
            headless_prove_precache=headless_prove_precache,
            headless_prove_swr=headless_prove_swr,
            headless_login_script=headless_login_script,
            headless_login_wait_selector=headless_login_wait_selector,
            headless_route_seeds=headless_route_seeds or [],
            headless_offline_replay=headless_offline_replay,
            headless_offline_wait_ms=headless_offline_wait_ms,
            headless_logout_url=headless_logout_url,
            headless_logout_script=headless_logout_script,
            headless_nav_delay_ms=headless_nav_delay_ms,
            proxy_url=proxy_url,
            headless_extra_headers=self.headers,
        )

        try:
            ea_config = EnhancedAnalysisConfig(**ea_kwargs)
        except TypeError:
            ea_kwargs.pop("headless_extra_headers", None)
            ea_config = EnhancedAnalysisConfig(**ea_kwargs)

        self.enhanced_analyzer = EnhancedAnalyzer(ea_config)

        if self.enable_headless_analysis and self.headless_cookies_netscape_file:
            try:
                hm = getattr(self.enhanced_analyzer, "headless_manager", None)
                if hm and getattr(hm, "cfg", None):
                    hm.cfg.cookies_netscape_file = self.headless_cookies_netscape_file
            except Exception:
                pass

        self.stats = {
            "targets_processed": 0,
            "sw_found": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
        }


    def _ensure_labels_hints(self, res: SWResult) -> None:
        if not getattr(res, "labels", None):
            res.labels = []
        if not getattr(res, "discovery_hints", None):
            res.discovery_hints = {}

    def _is_infra_sw(self, sw_url: str, headers: Dict[str, str], body: Optional[str] = None) -> Optional[str]:
        u = (sw_url or "").lower()
        h = {k.lower(): v for k, v in (headers or {}).items()}
        if u.endswith("/akam-sw.js") or u.endswith("akam-sw.js"):
            return "akamai"
        if "x-akam-sw-version" in h or "stored-attribute-sw-version" in h:
            return "akamai"
        return None

    def _host_key(self, url: str) -> str:
        try:
            return (urlparse(url).netloc or "").lower()
        except Exception:
            return ""

    @contextmanager
    def _host_gate(self, host: str):
        if not host:
            yield
            return
        with self._host_sem_lock:
            sem = self._host_sems.get(host)
            if sem is None:
                sem = threading.Semaphore(self.per_host_limit)
                self._host_sems[host] = sem
        sem.acquire()
        try:
            yield
        finally:
            try:
                sem.release()
            except Exception:
                pass

    def _detect_waf_label(self, headers: Dict[str, str]) -> Optional[str]:
        if not headers:
            return None
        h = {k.lower(): v for k, v in headers.items()}
        server = h.get("server", "").lower()
        via = h.get("via", "").lower()
        if "akamai" in server or "akamai" in via or "akamai-ghost" in h:
            return "WAF_AKAMAI"
        if "cloudflare" in server or "cf-ray" in h or "cf-cache-status" in h:
            return "WAF_CLOUDFLARE"
        if "sucuri" in server or "x-sucuri" in h:
            return "WAF_SUCURI"
        return None

    def _classify_block_reason(
        self,
        url: str,
        status: int,
        headers: Dict[str, str],
        error: Optional[BaseException],
        phase: str,
    ) -> Tuple[str, str]:
        h = {k.lower(): v for k, v in (headers or {}).items()}
        server = h.get("server", "")
        via = h.get("via", "")
        cf = ("cf-ray" in h) or ("cf-cache-status" in h) or ("cloudflare" in server.lower())
        ak = ("akamai" in server.lower()) or ("akamai" in via.lower()) or ("akamai-ghost" in h)
        sucuri = ("x-sucuri" in h) or ("sucuri" in server.lower())

        if status == 403:
            if cf:
                return f"{phase}: HTTP_403_FORBIDDEN_CLOUDFLARE", "WAF_CLOUDFLARE_403"
            if ak:
                return f"{phase}: HTTP_403_FORBIDDEN_AKAMAI", "WAF_AKAMAI_403"
            if sucuri:
                return f"{phase}: HTTP_403_FORBIDDEN_SUCURI", "WAF_SUCURI_403"
            return f"{phase}: HTTP_403_FORBIDDEN", "HTTP_403_FORBIDDEN"
        if status == 429:
            return f"{phase}: HTTP_429_RATE_LIMIT", "HTTP_429_RATE_LIMIT"
        if status in (406, 451):
            return f"{phase}: HTTP_{status}_POLICY", f"HTTP_{status}_POLICY"

        if error:
            msg = str(error)
            if isinstance(error, SecurityException):
                if "Response exceeded size limit" in msg:
                    return f"{phase}: HTML_TOO_LARGE", "HTML_TOO_LARGE"
                return f"{phase}: SECURITY_GUARD", "SECURITY_GUARD"
            if isinstance(error, NetworkException):
                if "Timeout" in msg:
                    return f"{phase}: TIMEOUT", "NETWORK_TIMEOUT"
                return f"{phase}: NETWORK_ERROR", "NETWORK_ERROR"

            m = msg.lower()
            if "dns" in m or "getaddrinfo" in m:
                return f"{phase}: DNS_FAILURE", "NETWORK_DNS_ERROR"
            if "ssl" in m or "tls" in m or "handshake" in m:
                return f"{phase}: TLS_FAILURE", "NETWORK_TLS_ERROR"
            if "proxy" in m and ("refused" in m or "failed to establish" in m):
                return f"{phase}: PROXY_REFUSED", "PROXY_REFUSED"
            if "read timed out" in m:
                return f"{phase}: READ_TIMEOUT", "NETWORK_TIMEOUT"
            return f"{phase}: {error.__class__.__name__}", error.__class__.__name__

        if status == 0:
            return f"{phase}: NO_RESPONSE", "NO_RESPONSE"
        return "", ""

    def _safe_fetch(
        self,
        url: str,
        phase: str,
        max_bytes: Optional[int] = None,
    ) -> Tuple[Optional[str], Dict[str, str], int, str, str]:
        try:
            text, headers, status = self.fetcher.fetch_url(
                url,
                headers=self.headers,
                cookies=self.cookies,
                max_bytes=(max_bytes if max_bytes is not None else self.max_sw_bytes),
                user_agent=self.user_agent,
            )
            if (not text) and status and status >= 400:
                br, ec = self._classify_block_reason(url, status, headers, None, phase)
                return text, headers, status, br, ec
            return text, headers, status, "", ""
        except (SecurityException, NetworkException) as e:
            br, ec = self._classify_block_reason(url, 0, {}, e, phase)
            return None, {}, 0, br, ec
        except Exception as e:
            br, ec = self._classify_block_reason(url, 0, {}, e, phase)
            return None, {}, 0, br, ec

    def scan_targets(self, targets: List[ScanTarget], probe: bool = True) -> Generator[SWResult, None, None]:
        self.stats.update({"start_time": time.time(), "targets_processed": 0, "sw_found": 0, "errors": 0})
        logger.debug(f"Starting scan of {len(targets)} targets with concurrency {self.parallel}")

        if self.enable_headless_analysis:
            logger.debug("Headless enabled — running scans serially to avoid Playwright thread issues.")
            for t in targets:
                try:
                    result = self._scan_single_target(t, probe)
                    self.stats["targets_processed"] += 1
                    if result and getattr(result, "sw_url", ""):
                        self.stats["sw_found"] += 1
                        logger.debug(f"Found SW for {t.url} - outcome: {getattr(result, 'outcome', '')}")
                    yield result
                except Exception as e:
                    self.stats["errors"] += 1
                    logger.error(f"Scan failed for {t.url}: {e}")
                    yield self._create_error_result(t.url, str(e))

            self.stats["end_time"] = time.time()
            logger.debug(
                f"Scan completed: {self.stats['targets_processed']} processed, "
                f"{self.stats['sw_found']} with SW, {self.stats['errors']} errors"
            )
            return

        def _submit(executor, fn, *args, **kwargs):
            time.sleep(random.uniform(0.02, 0.08))
            return executor.submit(fn, *args, **kwargs)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel) as executor:
            fut_to_t = {_submit(executor, self._scan_single_target, t, probe): t for t in targets}

            for future in concurrent.futures.as_completed(fut_to_t):
                target = fut_to_t[future]
                try:
                    result = future.result()
                    self.stats["targets_processed"] += 1
                    if result and getattr(result, "sw_url", ""):
                        self.stats["sw_found"] += 1
                        logger.debug(f"Found SW for {target.url} - outcome: {getattr(result, 'outcome', '')}")
                    yield result
                except Exception as e:
                    self.stats["errors"] += 1
                    logger.error(f"Scan failed for {target.url}: {e}")
                    yield self._create_error_result(target.url, str(e))

        self.stats["end_time"] = time.time()
        logger.debug(
            f"Scan completed: {self.stats['targets_processed']} processed, "
            f"{self.stats['sw_found']} with SW, {self.stats['errors']} errors"
        )

    def _scan_single_target(self, target: ScanTarget, probe: bool = True) -> SWResult:
        if self.jitter_max > 0:
            time.sleep(random.uniform(self.jitter_min / 1000.0, self.jitter_max / 1000.0))

        host = self._host_key(target.url)
        with self._host_gate(host):
            html, headers, status, block_reason, error_class = self._safe_fetch(
                target.url, phase="html_fetch"
            )

        if not html:
            res = self._rescue_or_empty(
                target.url,
                status,
                block_reason,
                response_headers=headers,
                error_class=error_class,
            )

            waf_label = self._detect_waf_label(headers)
            if waf_label:
                self._ensure_labels_hints(res)
                res.labels = list(set((res.labels or []) + [waf_label, "WAF_BLOCKED"]))
                if waf_label == "WAF_AKAMAI":
                    res.discovery_hints["vendor"] = "akamai"
                    res.discovery_hints["policy_endpoint"] = "/akam-sw-policy.json"
                    if not res.error_class or res.error_class == "HTTP_403_FORBIDDEN":
                        res.error_class = "WAF_AKAMAI_403"

            return res

        sw_urls = self.parser.find_sw_registrations(html, target.url)

        ngsw_meta: Optional[Dict[str, Any]] = None
        if probe and not sw_urls:
            try:
                vendor_candidates = self.parser.get_vendor_sw_candidates(target.url)
            except AttributeError:
                vendor_candidates = self.parser.get_common_sw_paths(target.url)

            for idx, path in enumerate(vendor_candidates):
                if idx >= self.vendor_probe_limit:
                    break
                ok, probe_status, probe_headers = self.fetcher.probe_exists(
                    path, headers=self.headers, cookies=self.cookies
                )
                if ok and 200 <= probe_status < 400:
                    if path.endswith(".js") or "worker" in path:
                        sw_urls.append(path)
                        break

        if probe:
            ngsw_json_url = urljoin(target.url, "/ngsw.json")
            ok, probe_status, _ = self.fetcher.probe_exists(
                ngsw_json_url, headers=self.headers, cookies=self.cookies
            )
            if ok and probe_status == 200:
                ngsw_meta = self._fetch_and_parse_ngsw_json(ngsw_json_url)

        if not sw_urls:
            if ngsw_meta:
                for candidate in ("/ngsw-worker.js", "/ngsw-worker-es2015.js"):
                    absu = urljoin(target.url, candidate)
                    ok, probe_status, _ = self.fetcher.probe_exists(
                        absu, headers=self.headers, cookies=self.cookies
                    )
                    if ok and 200 <= probe_status < 400:
                        r = self._analyze_service_worker(
                            origin=target.url,
                            sw_url=absu,
                            discovery_path="vendor_probe(angular)",
                        )
                        if r:
                            r.framework_artifacts = {"angular_ngsw_json": ngsw_meta}
                            r.outcome = "FOUND_SW"
                            return r

                empty = self._create_empty_result(target.url, status)
                empty.discovery_path = "vendor_metadata_only(angular)"
                empty.framework_artifacts = {"angular_ngsw_json": ngsw_meta}
                empty.outcome = "NO_SW_EVIDENCE"
                if block_reason:
                    empty.block_reason = block_reason
                if error_class:
                    empty.error_class = error_class
                empty.response_headers = headers or {}
                return empty

            res = self._rescue_or_empty(
                target.url,
                status,
                block_reason,
                response_headers=headers,
                error_class=error_class,
            )
            waf_label = self._detect_waf_label(headers)
            if waf_label:
                self._ensure_labels_hints(res)
                res.labels = list(set((res.labels or []) + [waf_label, "WAF_BLOCKED"]))
                if waf_label == "WAF_AKAMAI":
                    res.discovery_hints["vendor"] = "akamai"
                    res.discovery_hints["policy_endpoint"] = "/akam-sw-policy.json"
                    if not res.error_class or res.error_class == "HTTP_403_FORBIDDEN":
                        res.error_class = "WAF_AKAMAI_403"
            return res

        results: List[SWResult] = []
        for sw_url in sw_urls:
            r = self._analyze_service_worker(
                origin=target.url,
                sw_url=sw_url,
                discovery_path="html_script" if sw_url in sw_urls else "probed_path",
            )
            if r:
                if ngsw_meta and "ngsw-worker" in sw_url:
                    r.framework_artifacts = {"angular_ngsw_json": ngsw_meta}
                r.outcome = "FOUND_SW"
                results.append(r)

        if not results:
            return self._rescue_or_empty(
                target.url,
                status,
                block_reason,
                response_headers=headers,
                error_class=error_class,
            )

        prioritized = self.risk_assessor.prioritize_findings(results)
        best = prioritized[0]
        best.outcome = "FOUND_SW"
        if block_reason and not getattr(best, "block_reason", None):
            best.block_reason = block_reason
        if error_class and not getattr(best, "error_class", None):
            best.error_class = error_class
        if not best.response_headers:
            best.response_headers = headers or {}
        return best

    def _rescue_or_empty(
        self,
        origin: str,
        status_code: int,
        block_reason: str = "",
        response_headers: Optional[Dict[str, str]] = None,
        error_class: str = "",
    ) -> SWResult:
        if not self.enable_headless_analysis:
            r = self._create_empty_result(origin, status_code)
            if block_reason:
                r.block_reason = block_reason
            if error_class:
                r.error_class = error_class
            if response_headers:
                r.response_headers = response_headers
            return r

        try:
            enhanced = self.enhanced_analyzer.analyze_service_worker(
                javascript_code="",
                target_url=origin,
                static_findings={},
                base_url_for_ast=None,
                effective_scope=None,
                seed_routes=[],
                request_headers=self.headers,
                cookies=self.cookies,
                user_agent=self.user_agent,
            )
            hv = enhanced.get("headless_validation") or enhanced.get("headless_analysis") or {}
            sw_reg = (hv.get("service_worker") or {}).get("registration") or {}
            swu = sw_reg.get("scriptURL")

            if swu:
                r = self._analyze_service_worker(
                    origin=origin,
                    sw_url=swu,
                    discovery_path="auth_headless" if self.cookies else "runtime",
                )
                if r:
                    r.outcome = "FOUND_SW"
                    if response_headers and not r.response_headers:
                        r.response_headers = response_headers
                    if block_reason and not getattr(r, "block_reason", None):
                        r.block_reason = block_reason
                    if error_class and not getattr(r, "error_class", None):
                        r.error_class = error_class
                    return r

            auth_hints = hv.get("auth_hints") or {}
            if any(auth_hints.get(k) for k in ("saw_login_redirect", "saw_auth_words", "saw_401_403")):
                e = self._create_empty_result(origin, status_code)
                e.outcome = "AUTH_NEEDED"
                e.discovery_path = "headless_hints"
                if block_reason:
                    e.block_reason = block_reason
                if error_class:
                    e.error_class = error_class
                if response_headers:
                    e.response_headers = response_headers
                e.enhanced_analysis = enhanced
                return e

            responses = hv.get("responses") or []
            code_set = {int(r.get("status") or 0) for r in responses}
            if 403 in code_set:
                e = self._create_empty_result(origin, status_code)
                e.outcome = "WAF_OR_BLOCK_403"
                e.discovery_path = "headless_runtime"
                e.block_reason = "headless_runtime: HTTP_403_FORBIDDEN"
                e.error_class = "HTTP_403_FORBIDDEN"
                if response_headers:
                    e.response_headers = response_headers

                waf_label = self._detect_waf_label(response_headers or {})
                if waf_label:
                    self._ensure_labels_hints(e)
                    e.labels = list(set((e.labels or []) + [waf_label, "WAF_BLOCKED"]))

                    if waf_label == "WAF_AKAMAI":
                        e.discovery_hints["vendor"] = "akamai"
                        e.discovery_hints["policy_endpoint"] = "/akam-sw-policy.json"
                        e.error_class = "WAF_AKAMAI_403"

                e.enhanced_analysis = enhanced
                return e
            if 429 in code_set:
                e = self._create_empty_result(origin, status_code)
                e.outcome = "WAF_OR_BLOCK_429"
                e.discovery_path = "headless_runtime"
                e.block_reason = "headless_runtime: HTTP_429_RATE_LIMIT"
                e.error_class = "HTTP_429_RATE_LIMIT"
                if response_headers:
                    e.response_headers = response_headers
                e.enhanced_analysis = enhanced
                return e

            e = self._create_empty_result(origin, status_code)
            e.outcome = "NO_SW_EVIDENCE"
            e.discovery_path = "headless_runtime"
            if block_reason:
                e.block_reason = block_reason
            if error_class:
                e.error_class = error_class
            if response_headers:
                e.response_headers = response_headers
            e.enhanced_analysis = enhanced
            return e

        except Exception as ex:
            logger.debug(f"Headless rescue failed for {origin}: {ex}")
            e = self._create_empty_result(origin, status_code)
            if block_reason:
                e.block_reason = block_reason
            if error_class:
                e.error_class = error_class
            if response_headers:
                e.response_headers = response_headers
            return e

    def _analyze_service_worker(
        self,
        origin: str,
        sw_url: str,
        discovery_path: str = "",
    ) -> Optional[SWResult]:
        with self._host_gate(self._host_key(sw_url)):
            sw_content, sw_headers, sw_status, sw_block, sw_err_class = self._safe_fetch(
                sw_url, phase="sw_fetch", max_bytes=self.max_sw_bytes
            )

        if not sw_content:
            r = self._create_empty_result(origin, sw_status)
            r.sw_url = sw_url
            r.discovery_path = discovery_path or "unknown"
            if sw_block:
                r.block_reason = sw_block
            if sw_err_class:
                r.error_class = sw_err_class
            r.response_headers = sw_headers or {}
            r.outcome = "NO_SW_EVIDENCE"

            waf_label = self._detect_waf_label(sw_headers or {})
            if waf_label:
                self._ensure_labels_hints(r)
                res_labels = set((r.labels or []) + [waf_label, "WAF_BLOCKED"])
                r.labels = list(res_labels)
                if waf_label == "WAF_AKAMAI":
                    r.discovery_hints["vendor"] = "akamai"
                    r.discovery_hints["policy_endpoint"] = "/akam-sw-policy.json"
                    if not r.error_class or r.error_class == "HTTP_403_FORBIDDEN":
                        r.error_class = "WAF_AKAMAI_403"

            return r

        has_swa = "Service-Worker-Allowed" in (sw_headers or {})
        effective_scope = self.normalizer.calculate_scope(
            sw_url, (sw_headers or {}).get("Service-Worker-Allowed")
        )

        infra_vendor = self._is_infra_sw(sw_url, sw_headers or {}, sw_content)
        skip_headless_for_this = bool(infra_vendor)
        workbox_detected, workbox_modules = self.analyzer.detect_workbox(sw_content)
        cache_names = self.analyzer.extract_cache_names(sw_content)
        routes = self.analyzer.extract_routes(sw_content, self.max_routes)
        security_findings = self.security_analyzer.analyze_security_patterns(sw_content, routes)

        if self.no_risk_assessment:
            risk_assessment = {
                "risk_score": 0,
                "security_flags": security_findings.get("security_flags", []),
                "risk_indicators": security_findings.get("risk_indicators", []),
            }
        else:
            ra = self.risk_assessor.calculate_risk_score(
                has_swa=has_swa,
                effective_scope=effective_scope,
                security_findings=security_findings,
                cache_names=cache_names,
                routes=routes,
                workbox_detected=workbox_detected,
            )
            risk_assessment = {
                "risk_score": ra.get("risk_score", 0),
                "security_flags": ra.get("security_flags", []),
                "risk_indicators": ra.get("risk_indicators", []),
            }

        enhanced_results: Dict[str, Any] = {}
        try:
            if self.enable_ast_analysis or self.enable_headless_analysis:
                target_for_headless = None if skip_headless_for_this else (origin if self.enable_headless_analysis else None)

                enhanced_results = self.enhanced_analyzer.analyze_service_worker(
                    javascript_code=sw_content,
                    target_url=target_for_headless,
                    static_findings={
                        "sw_url": sw_url,
                        "routes_seen": routes,
                        "workbox_detected": workbox_detected,
                        "cache_names": cache_names,
                    },
                    base_url_for_ast=sw_url,
                    effective_scope=effective_scope,
                    seed_routes=routes[:10],
                    request_headers=self.headers,
                    cookies=self.cookies,
                    user_agent=self.user_agent,
                )

                if not self.no_risk_assessment:
                    conf = float(enhanced_results.get("confidence_score") or 1.0)
                    risk_assessment["risk_score"] = min(
                        int(risk_assessment["risk_score"] * conf), 100
                    )

                    dyn = (
                        enhanced_results.get("headless_analysis")
                        or enhanced_results.get("headless_validation")
                        or {}
                    )
                    labels = set(dyn.get("labels") or [])
                    dyn_conf = float(dyn.get("confidence") or 0.5)
                    if "precaching" in labels:
                        risk_assessment["risk_score"] = min(
                            int(risk_assessment["risk_score"] * max(1.05, dyn_conf)), 100
                        )
                    if "intercepts_majority" in labels:
                        risk_assessment["risk_score"] = min(
                            int(risk_assessment["risk_score"] * max(1.10, dyn_conf)), 100
                        )
        except Exception as e:
            logger.debug(f"Enhanced analysis failed for {sw_url}: {e}")
            enhanced_results = {"enhanced_error": str(e)}

        result = SWResult(
            origin=origin,
            sw_url=sw_url,
            effective_scope=effective_scope,
            http_status=sw_status,
            response_headers=sw_headers or {},
            has_swa=has_swa,
            workbox=workbox_detected,
            cache_names=cache_names,
            routes_seen=routes,
            risk_score=risk_assessment["risk_score"],
            risk_level="-",
            security_flags=risk_assessment["security_flags"],
            workbox_modules=workbox_modules,
            detected_patterns=security_findings.get("patterns_detected", {}),
            security_findings=security_findings,
            enhanced_analysis=enhanced_results,
        )
        result.discovery_path = discovery_path or "unknown"
        if sw_block:
            result.block_reason = sw_block
        if sw_err_class:
            result.error_class = sw_err_class

        if infra_vendor == "akamai":
            self._ensure_labels_hints(result)
            if "AKAMAI_SW" not in result.labels:
                result.labels.append("AKAMAI_SW")
            result.discovery_hints.setdefault("vendor", "akamai")
            result.discovery_hints.setdefault("policy_endpoint", "/akam-sw-policy.json")

        return result

    def _fetch_and_parse_ngsw_json(self, ngsw_json_url: str) -> Optional[Dict[str, Any]]:
        try:
            text, hdrs, code = self.fetcher.fetch_url(
                ngsw_json_url,
                headers=self.headers,
                cookies=self.cookies,
                max_bytes=min(self.max_sw_bytes, 1_000_000),
                user_agent=self.user_agent,
            )
            if code != 200 or not text:
                return None
            import json

            data = json.loads(text)
            out: Dict[str, Any] = {"assetGroups": [], "dataGroups": [], "urls": []}

            for ag in (data.get("assetGroups") or []):
                entry = {
                    "name": ag.get("name"),
                    "installMode": ag.get("installMode"),
                    "resources": {
                        "files": (ag.get("resources") or {}).get("files") or [],
                        "urls": (ag.get("resources") or {}).get("urls") or [],
                    },
                }
                out["assetGroups"].append(entry)
                out["urls"].extend(entry["resources"]["urls"])

            for dg in (data.get("dataGroups") or []):
                entry = {
                    "name": dg.get("name"),
                    "urls": dg.get("urls") or [],
                    "cacheConfig": dg.get("cacheConfig") or {},
                }
                out["dataGroups"].append(entry)
                out["urls"].extend(entry["urls"])

            out["urls"] = sorted(set(out["urls"]))

            return out
        except Exception as e:
            logger.debug(f"Failed to parse ngsw.json {ngsw_json_url}: {e}")
            return None

    def _create_empty_result(self, origin: str, status_code: int) -> SWResult:
        r = SWResult(
            origin=origin,
            sw_url="",
            effective_scope="",
            http_status=status_code,
            response_headers={},
            has_swa=False,
            workbox=False,
            cache_names=[],
            routes_seen=[],
            risk_level="-",
            security_flags=[],
            risk_score=0,
            workbox_modules=[],
            detected_patterns={},
        )
        r.outcome = "NO_SW_EVIDENCE"
        r.discovery_path = "none"
        return r

    def _create_error_result(self, origin: str, error: str) -> SWResult:
        r = self._create_empty_result(origin, 0)
        r.outcome = "ERROR"
        r.block_reason = error
        r.error = error 
        r.error_class = "CLIENT_EXCEPTION"
        return r
    
    def get_stats(self) -> Dict[str, Any]:
        start, end = self.stats.get("start_time"), self.stats.get("end_time")
        if start and end:
            duration = end - start
        elif start:
            duration = time.time() - start
        else:
            duration = 0.0

        stats = dict(self.stats)
        stats["duration_seconds"] = round(duration, 2)
        stats["targets_per_second"] = (
            round(stats["targets_processed"] / duration, 2) if duration > 0 else 0
        )
        return stats

    def close(self):
        self.fetcher.close()
