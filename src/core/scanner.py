# src/core/scanner.py
from __future__ import annotations

import concurrent.futures
import logging
import time
from typing import List, Dict, Any, Optional, Generator
from .fetcher import AdvancedFetcher
from .parser import SWParser
from .analyzer import SWAnalyzer
from .security_analyzer import SecurityAnalyzer
from .risk_assessor import RiskAssessor
from .normalizer import URLNormalizer
from .enhanced_analyzer import EnhancedAnalyzer, EnhancedAnalysisConfig
from ..models.target import ScanTarget
from ..models.result import SWResult

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
        headless_timeout_ms: int = 30000,
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
    ):
        self.parallel = parallel
        self.timeout = timeout
        self.max_sw_bytes = max_sw_bytes
        self.max_routes = max_routes
        self.user_agent = user_agent 
        self.fetcher = AdvancedFetcher(timeout=timeout, user_agent=user_agent)
        self.parser = SWParser()
        self.analyzer = SWAnalyzer()
        self.security_analyzer = SecurityAnalyzer()
        self.risk_assessor = RiskAssessor()
        self.normalizer = URLNormalizer()
        self.headers = headers or {}
        self.cookies = cookies
        self.no_risk_assessment = no_risk_assessment
        self.enable_ast_analysis = enable_ast_analysis
        self.enable_headless_analysis = enable_headless_analysis
        self.enhanced_analyzer = EnhancedAnalyzer(
            EnhancedAnalysisConfig(
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
            )
        )

        self.stats = {
            "targets_processed": 0,
            "sw_found": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
        }

    def scan_targets(self, targets: List[ScanTarget], probe: bool = True) -> Generator[SWResult, None, None]:
        self.stats.update({"start_time": time.time(), "targets_processed": 0, "sw_found": 0, "errors": 0})
        logger.info(f"Starting scan of {len(targets)} targets with concurrency {self.parallel}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel) as executor:
            fut_to_t = {executor.submit(self._scan_single_target, t, probe): t for t in targets}

            for future in concurrent.futures.as_completed(fut_to_t):
                target = fut_to_t[future]
                try:
                    result = future.result()
                    self.stats["targets_processed"] += 1
                    if result and getattr(result, "sw_url", ""):
                        self.stats["sw_found"] += 1
                        logger.info(f"Found SW for {target.url} - Risk: {result.risk_level}")
                    yield result
                except Exception as e:
                    self.stats["errors"] += 1
                    logger.error(f"Scan failed for {target.url}: {e}")
                    yield self._create_error_result(target.url, str(e))

        self.stats["end_time"] = time.time()
        logger.info(
            f"Scan completed: {self.stats['targets_processed']} processed, "
            f"{self.stats['sw_found']} with SW, {self.stats['errors']} errors"
        )

    def _scan_single_target(self, target: ScanTarget, probe: bool = True) -> SWResult:
        try:
            html, headers, status = self.fetcher.fetch_url(
                target.url, headers=self.headers, cookies=self.cookies, max_bytes=self.max_sw_bytes
            )
            if not html:
                logger.warning(f"No content fetched from {target.url}")
                return self._create_empty_result(target.url, status)

            sw_urls = self.parser.find_sw_registrations(html, target.url)

            if not sw_urls and probe:
                for path in self.parser.get_common_sw_paths(target.url):
                    _, _, probe_status = self.fetcher.fetch_url(path, max_bytes=1024)
                    if probe_status == 200:
                        sw_urls.append(path)
                        break

            if not sw_urls:
                return self._create_empty_result(target.url, status)

            results: List[SWResult] = []
            for sw_url in sw_urls:
                r = self._analyze_service_worker(target.url, sw_url)
                if r:
                    results.append(r)

            if not results:
                return self._create_empty_result(target.url, status)

            prioritized = self.risk_assessor.prioritize_findings(results)
            return prioritized[0]
        except Exception as e:
            logger.error(f"Error scanning {target.url}: {e}")
            return self._create_error_result(target.url, str(e))

    def _analyze_service_worker(self, origin: str, sw_url: str) -> Optional[SWResult]:
        try:
            sw_content, sw_headers, sw_status = self.fetcher.fetch_url(
                sw_url, headers=self.headers, cookies=self.cookies, max_bytes=self.max_sw_bytes
            )
            if not sw_content:
                logger.warning(f"No content from SW: {sw_url}")
                return None

            has_swa = "Service-Worker-Allowed" in sw_headers
            effective_scope = self.normalizer.calculate_scope(sw_url, sw_headers.get("Service-Worker-Allowed"))

            workbox_detected, workbox_modules = self.analyzer.detect_workbox(sw_content)
            cache_names = self.analyzer.extract_cache_names(sw_content)
            routes = self.analyzer.extract_routes(sw_content, self.max_routes)

            security_findings = self.security_analyzer.analyze_security_patterns(sw_content, routes)

            if self.no_risk_assessment:
                risk_assessment = {
                    "risk_score": 0,
                    "risk_level": "INFO",
                    "security_flags": [],
                    "risk_indicators": [],
                }
            else:
                risk_assessment = self.risk_assessor.calculate_risk_score(
                    has_swa=has_swa,
                    effective_scope=effective_scope,
                    security_findings=security_findings,
                    cache_names=cache_names,
                    routes=routes,
                    workbox_detected=workbox_detected,
                )

            enhanced_results: Dict[str, Any] = {}
            if self.enable_ast_analysis or self.enable_headless_analysis:
                try:
                    enhanced_results = self.enhanced_analyzer.analyze_service_worker(
                        javascript_code=sw_content,
                        target_url=origin if self.enable_headless_analysis else None,
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

                    if not self.no_risk_assessment and enhanced_results.get("confidence_score"):
                        rs = int(risk_assessment["risk_score"] * enhanced_results["confidence_score"])
                        risk_assessment["risk_score"] = min(rs, 100)
                        
                    dyn = enhanced_results.get("headless_analysis") or {}
                    labels = set(dyn.get("labels") or [])
                    confidence = float(dyn.get("confidence") or 0.5)

                    if not self.no_risk_assessment and labels:
                        if "precaching" in labels:
                            risk_assessment["risk_score"] = min(
                                100, int(risk_assessment["risk_score"] * max(1.05, confidence))
                            )
                            
                        if "intercepts_majority" in labels:
                            risk_assessment["risk_score"] = min(
                                100, int(risk_assessment["risk_score"] * max(1.10, confidence))
                            )
                            
                except Exception as e:
                    logger.warning(f"Enhanced analysis failed: {e}")

            return SWResult(
                origin=origin,
                sw_url=sw_url,
                effective_scope=effective_scope,
                http_status=sw_status,
                has_swa=has_swa,
                workbox=workbox_detected,
                cache_names=cache_names,
                routes_seen=routes,
                risk_level=risk_assessment["risk_level"],
                security_flags=risk_assessment["security_flags"],
                risk_score=risk_assessment["risk_score"],
                workbox_modules=workbox_modules,
                detected_patterns=security_findings.get("patterns_detected", {}),
                security_findings=security_findings,
                enhanced_analysis=enhanced_results,
            )
        except Exception as e:
            logger.error(f"Error analyzing SW {sw_url}: {e}")
            return None

    def _create_empty_result(self, origin: str, status_code: int) -> SWResult:
        return SWResult(
            origin=origin,
            sw_url="",
            effective_scope="",
            http_status=status_code,
            has_swa=False,
            workbox=False,
            cache_names=[],
            routes_seen=[],
            risk_level="INFO",
            security_flags=[],
            risk_score=0,
            workbox_modules=[],
            detected_patterns={},
        )

    def _create_error_result(self, origin: str, error: str) -> SWResult:
        r = self._create_empty_result(origin, 0)
        try:
            setattr(r, "error", error)
        except Exception:
            pass
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
        stats["targets_per_second"] = round(stats["targets_processed"] / duration, 2) if duration > 0 else 0
        return stats

    def close(self):
        self.fetcher.close()
