from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional, List
from .ast_analyzer import ASTAnalyzer, ASTAnalyzerConfig
from .headless_analyzer import HeadlessAnalysisManager, HeadlessConfig
from ..utils.logger import get_logger

logger = get_logger("enhanced_analyzer")

@dataclass
class EnhancedAnalysisConfig:
    enable_ast: bool = True
    enable_headless: bool = False
    ast_max_depth: int = 2
    ast_same_origin_only: bool = True
    ast_request_timeout: int = 10
    headless_timeout_ms: int = 30000
    headless_max_routes: int = 25
    headless_crawl: bool = True
    headless_crawl_limit: int = 50
    headless_backoff_attempts: int = 4
    headless_backoff_ms: int = 500

class EnhancedAnalyzer:
    def __init__(self, config: Optional[EnhancedAnalysisConfig] = None):
        self.cfg = config or EnhancedAnalysisConfig()

        self.ast_analyzer: Optional[ASTAnalyzer] = None
        if self.cfg.enable_ast:
            self.ast_analyzer = ASTAnalyzer(
                ASTAnalyzerConfig(
                    max_depth=self.cfg.ast_max_depth,
                    same_origin_only=self.cfg.ast_same_origin_only,
                    request_timeout=self.cfg.ast_request_timeout,
                )
            )

        self.headless_manager: Optional[HeadlessAnalysisManager] = None
        if self.cfg.enable_headless:
            self.headless_manager = HeadlessAnalysisManager(
                enable_headless=True,
                config=HeadlessConfig(
                    timeout_ms=self.cfg.headless_timeout_ms,
                    max_routes_to_test=self.cfg.headless_max_routes,
                    crawl_links=self.cfg.headless_crawl,
                    crawl_limit=self.cfg.headless_crawl_limit,
                    backoff_attempts=self.cfg.headless_backoff_attempts,
                    backoff_ms=self.cfg.headless_backoff_ms,
                ),
            )

    def analyze_service_worker(
        self,
        javascript_code: str,
        target_url: Optional[str] = None,
        static_findings: Optional[Dict[str, Any]] = None,
        base_url_for_ast: Optional[str] = None,
        effective_scope: Optional[str] = None,
        seed_routes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Returns:
          {
            analysis_methods: [...],
            ast_analysis: {...},
            headless_validation: {...},
            enhanced_findings: {...},
            confidence_score: float,
            warnings: [...]
          }
        """
        out = {
            "analysis_methods": [],
            "ast_analysis": {},
            "headless_validation": {},
            "enhanced_findings": {},
            "confidence_score": 0.5,
            "warnings": [],
        }

        if self.cfg.enable_ast and self.ast_analyzer:
            try:
                ast = self.ast_analyzer.analyze_with_ast(javascript_code, base_url=base_url_for_ast)
                out["ast_analysis"] = ast
                out["analysis_methods"].append("ast")
                if not ast.get("errors"):
                    out["confidence_score"] *= 1.3
                out["enhanced_findings"].update(self._from_ast(ast))
            except Exception as e:
                logger.warning(f"AST analysis failed: {e}")
                out["warnings"].append(f"AST analysis failed: {e}")

        if (
            self.cfg.enable_headless
            and self.headless_manager
            and target_url
            and static_findings is not None
        ):
            try:
                validated = self.headless_manager.validate_static_findings(
                    static_findings,
                    target_url,
                    seed_routes=seed_routes,
                    effective_scope=effective_scope,
                )
                out["headless_validation"] = validated.get("headless_analysis", {})
                out["analysis_methods"].append("headless")
                if "validation_confidence" in validated:
                    out["confidence_score"] *= validated["validation_confidence"]
            except Exception as e:
                logger.warning(f"Headless validation failed: {e}")
                out["warnings"].append(f"Headless validation failed: {e}")

        out["confidence_score"] = min(out["confidence_score"], 1.0)
        return out
    @staticmethod
    def _from_ast(ast: Dict[str, Any]) -> Dict[str, Any]:
        findings = {
            "precise_imports": [],
            "event_handlers": [],
            "cache_precache": [],
            "route_handlers": [],
            "dangerous_operations": [],
            "strategies": [],
        }

        for imp in ast.get("imports", []):
            if imp.get("source"):
                findings["precise_imports"].append(
                    {"type": imp.get("type"), "source": imp.get("source")}
                )

        for ev in ast.get("eventListeners", []):
            findings["event_handlers"].append(
                {"event": ev.get("event"), "location": ev.get("location", "unknown")}
            )

        for op in ast.get("cacheOperations", []):
            if op.get("type") == "cacheAddAll":
                urls = op.get("urls") or []
                findings["cache_precache"].append({"urls": urls})

        for r in ast.get("routes", []):
            findings["route_handlers"].append(
                {
                    "type": r.get("type"),
                    "expression": r.get("expression", ""),
                    "location": r.get("location", "unknown"),
                }
            )

        for d in ast.get("dangerousPatterns", []):
            findings["dangerous_operations"].append(
                {
                    "type": d.get("type"),
                    "code": d.get("code", ""),
                    "location": d.get("location", "unknown"),
                    "risk_level": EnhancedAnalyzer._risk_of_danger(d.get("type")),
                }
            )

        for s in ast.get("strategies", []):
            findings["strategies"].append(
                {
                    "handler": s.get("handler", "fetch"),
                    "strategy": s.get("strategy", "unknown"),
                    "location": s.get("location", "unknown"),
                }
            )

        return findings

    @staticmethod
    def _risk_of_danger(typ: Optional[str]) -> str:
        m = {
            "eval": "HIGH",
            "functionConstructor": "HIGH",
            "setTimeoutString": "MEDIUM",
            "setIntervalString": "MEDIUM",
        }
        return m.get(typ or "", "LOW")

enhanced_analyzer = EnhancedAnalyzer()
