import logging
from typing import Dict, List, Any
from enum import Enum
from urllib.parse import urlparse
logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskAssessor:
    def __init__(self):
        self.risk_weights = {
            "WIDENED_SCOPE": 40,
            "SENSITIVE_CACHING": 35,
            "CACHE_POISONING_RISK": 30,
            "AGGRESSIVE_ACTIVATION": 25,
            "CLIENT_SIDE_AUTH": 25,
            "THIRD_PARTY_IMPORTS": 20,
            "EVAL_USAGE": 20,
            "BACKGROUND_SYNC": 15,
            "MIXED_ORIGIN_ISSUES": 10,
            "AUTH_BYPASS_RISK": 35,
            "AGGRESSIVE_CACHING": 30,
        }
        self.base_scores = {
            "has_swa_header": 20,
            "workbox_detected": 10,
            "has_sensitive_routes": 15,
            "multiple_cache_names": 5,
        }

    def calculate_risk_score(
        self,
        has_swa: bool,
        effective_scope: str,
        security_findings: Dict[str, Any],
        cache_names: List[str],
        routes: List[str],
        workbox_detected: bool = False,
    ) -> Dict[str, Any]:
        try:
            score = 0
            breakdown: Dict[str, int] = {}

            if has_swa:
                score += self.base_scores["has_swa_header"]
                breakdown["swa_header"] = self.base_scores["has_swa_header"]

            if workbox_detected:
                score += self.base_scores["workbox_detected"]
                breakdown["workbox"] = self.base_scores["workbox_detected"]

            scope_risk = self._assess_scope_risk(has_swa, effective_scope)
            score += scope_risk
            breakdown["scope_risk"] = scope_risk
            security_flags = security_findings.get("security_flags", [])
            risk_indicators = security_findings.get("risk_indicators", [])
            for flag in security_flags + risk_indicators:
                if flag in self.risk_weights:
                    score += self.risk_weights[flag]
                    breakdown[flag] = self.risk_weights[flag]

            if security_findings.get("sensitive_routes"):
                score += self.base_scores["has_sensitive_routes"]
                breakdown["sensitive_routes"] = self.base_scores["has_sensitive_routes"]

            if len(cache_names) > 1:
                score += self.base_scores["multiple_cache_names"]
                breakdown["multiple_caches"] = self.base_scores["multiple_cache_names"]

            score = min(score, 100)
            risk_level = self._score_to_level(score)

            return {
                "risk_score": score,
                "risk_level": risk_level.value,
                "breakdown": breakdown,
                "security_flags": security_flags,
                "risk_indicators": risk_indicators,
            }
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return self._default_risk_assessment()

    def _assess_scope_risk(self, has_swa: bool, effective_scope: str) -> int:
        try:
            path = urlparse(effective_scope).path or "/"
        except Exception:
            path = "/"

        if has_swa and path == "/":
            return 40 
        if path == "/":
            return 25

        depth = len([s for s in path.split("/") if s])
        if depth <= 1:
            return 20
        elif depth <= 3:
            return 10
        else:
            return 5

    def _score_to_level(self, score: int) -> RiskLevel:
        if score >= 90:
            return RiskLevel.CRITICAL
        elif score >= 70:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    def _default_risk_assessment(self) -> Dict[str, Any]:
        return {
            "risk_score": 0,
            "risk_level": RiskLevel.INFO.value,
            "breakdown": {},
            "security_flags": [],
            "risk_indicators": [],
        }

    def prioritize_findings(self, results: List[Any]) -> List[Any]:
        try:
            def score_of(r: Any) -> int:
                if isinstance(r, dict):
                    return int(r.get("risk_score", 0))
                return int(getattr(r, "risk_score", 0) or 0)

            return sorted(results, key=score_of, reverse=True)
        except Exception as e:
            logger.error(f"Error prioritizing findings: {e}")
            return results

    def generate_risk_summary(self, results: List[Any]) -> Dict[str, Any]:
        try:
            if not results:
                return self._empty_summary()

            def score_of(r: Any) -> int:
                if isinstance(r, dict):
                    return int(r.get("risk_score", 0))
                return int(getattr(r, "risk_score", 0) or 0)

            def level_of(r: Any) -> str:
                if isinstance(r, dict):
                    return str(r.get("risk_level", "INFO"))
                return str(getattr(r, "risk_level", "INFO"))

            scores = [score_of(r) for r in results]
            levels = [level_of(r) for r in results]

            return {
                "total_targets": len(results),
                "average_risk_score": (sum(scores) / len(scores)) if scores else 0,
                "max_risk_score": max(scores) if scores else 0,
                "high_risk_count": sum(1 for lv in levels if lv in ("HIGH", "CRITICAL")),
                "risk_distribution": {
                    "CRITICAL": levels.count("CRITICAL"),
                    "HIGH": levels.count("HIGH"),
                    "MEDIUM": levels.count("MEDIUM"),
                    "LOW": levels.count("LOW"),
                    "INFO": levels.count("INFO"),
                },
            }
        except Exception as e:
            logger.error(f"Error generating risk summary: {e}")
            return self._empty_summary()

    def _empty_summary(self) -> Dict[str, Any]:
        return {
            "total_targets": 0,
            "average_risk_score": 0,
            "max_risk_score": 0,
            "high_risk_count": 0,
            "risk_distribution": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
        }
