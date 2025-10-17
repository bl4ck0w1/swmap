from dataclasses import dataclass, field
from typing import List, Dict, Any
from enum import Enum
import json
import time

class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_score(cls, score: int) -> "RiskLevel":
        if score >= 90:
            return cls.CRITICAL
        elif score >= 70:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        elif score >= 20:
            return cls.LOW
        else:
            return cls.INFO


class SecurityFlag(Enum):
    WIDENED_SCOPE = "WIDENED_SCOPE"
    OVERLY_BROAD_SCOPE = "OVERLY_BROAD_SCOPE"
    SENSITIVE_CACHING = "SENSITIVE_CACHING"
    CACHE_POISONING_RISK = "CACHE_POISONING_RISK"
    AGGRESSIVE_CACHING = "AGGRESSIVE_CACHING"
    EVAL_USAGE = "EVAL_USAGE"
    THIRD_PARTY_IMPORTS = "THIRD_PARTY_IMPORTS"
    DYNAMIC_CODE_EXECUTION = "DYNAMIC_CODE_EXECUTION"
    CLIENT_SIDE_AUTH = "CLIENT_SIDE_AUTH"
    AUTH_BYPASS_RISK = "AUTH_BYPASS_RISK"
    AGGRESSIVE_ACTIVATION = "AGGRESSIVE_ACTIVATION"
    MIXED_ORIGIN_ISSUES = "MIXED_ORIGIN_ISSUES"
    BACKGROUND_SYNC = "BACKGROUND_SYNC"
    WORKBOX_PRECACHING = "WORKBOX_PRECACHING"
    WORKBOX_RUNTIME_CACHING = "WORKBOX_RUNTIME_CACHING"


@dataclass
class PatternDetection:
    eval_usage: bool = False
    third_party_imports: bool = False
    cache_poisoning_risk: bool = False
    background_sync: bool = False
    aggressive_activation: bool = False
    mixed_origin_issues: bool = False
    client_side_auth: bool = False
    workbox_precaching: bool = False
    workbox_routing: bool = False
    workbox_strategies: bool = False
    custom_patterns: Dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, bool]:
        base = {
            "eval_usage": self.eval_usage,
            "third_party_imports": self.third_party_imports,
            "cache_poisoning_risk": self.cache_poisoning_risk,
            "background_sync": self.background_sync,
            "aggressive_activation": self.aggressive_activation,
            "mixed_origin_issues": self.mixed_origin_issues,
            "client_side_auth": self.client_side_auth,
            "workbox_precaching": self.workbox_precaching,
            "workbox_routing": self.workbox_routing,
            "workbox_strategies": self.workbox_strategies,
        }
        base.update(self.custom_patterns)
        return base

    @property
    def detected_patterns(self) -> List[str]:
        return [k for k, v in self.to_dict().items() if v]


@dataclass
class SecurityFindings:
    security_flags: List[Any] = field(default_factory=list)
    risk_indicators: List[str] = field(default_factory=list)
    sensitive_routes: List[str] = field(default_factory=list)
    pattern_detection: PatternDetection = field(default_factory=PatternDetection)
    third_party_imports: List[str] = field(default_factory=list)
    dangerous_functions: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    analysis_timestamp: float = field(default_factory=lambda: time.time())
    analyzer_version: str = "1.0.0"

    def add_security_flag(self, flag: Any):
        if flag not in self.security_flags:
            self.security_flags.append(flag)

    def add_risk_indicator(self, indicator: str):
        if indicator not in self.risk_indicators:
            self.risk_indicators.append(indicator)

    def add_sensitive_route(self, route: str):
        if route not in self.sensitive_routes:
            self.sensitive_routes.append(route)

    @property
    def has_critical_findings(self) -> bool:
        critical = {
            SecurityFlag.WIDENED_SCOPE.value,
            SecurityFlag.SENSITIVE_CACHING.value,
            SecurityFlag.CACHE_POISONING_RISK.value,
            SecurityFlag.AUTH_BYPASS_RISK.value,
            SecurityFlag.WIDENED_SCOPE,
            SecurityFlag.SENSITIVE_CACHING,
            SecurityFlag.CACHE_POISONING_RISK,
            SecurityFlag.AUTH_BYPASS_RISK,
        }
        return any(f in critical for f in self.security_flags)

    @property
    def flag_count(self) -> int:
        return len(self.security_flags)

    @property
    def sensitive_route_count(self) -> int:
        return len(self.sensitive_routes)

    def to_dict(self) -> Dict[str, Any]:
        def flag_to_str(f: Any) -> str:
            try:
                return f.value if isinstance(f, SecurityFlag) else str(f)
            except Exception:
                return str(f)

        return {
            "security_flags": [flag_to_str(f) for f in self.security_flags],
            "risk_indicators": self.risk_indicators,
            "sensitive_routes": self.sensitive_routes,
            "pattern_detection": self.pattern_detection.to_dict(),
            "third_party_imports": self.third_party_imports,
            "dangerous_functions": self.dangerous_functions,
            "security_headers": self.security_headers,
            "analysis_timestamp": self.analysis_timestamp,
            "analyzer_version": self.analyzer_version,
            "has_critical_findings": self.has_critical_findings,
            "flag_count": self.flag_count,
            "sensitive_route_count": self.sensitive_route_count,
        }


@dataclass
class RiskBreakdown:
    scope_risk: int = 0
    caching_risk: int = 0
    code_quality_risk: int = 0
    authentication_risk: int = 0
    activation_risk: int = 0
    network_risk: int = 0
    workbox_risk: int = 0
    configuration_risk: int = 0
    calculation_method: str = "weighted_sum"
    version: str = "1.0.0"

    @property
    def total_score(self) -> int:
        return sum(
            [
                self.scope_risk,
                self.caching_risk,
                self.code_quality_risk,
                self.authentication_risk,
                self.activation_risk,
                self.network_risk,
                self.workbox_risk,
                self.configuration_risk,
            ]
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope_risk": self.scope_risk,
            "caching_risk": self.caching_risk,
            "code_quality_risk": self.code_quality_risk,
            "authentication_risk": self.authentication_risk,
            "activation_risk": self.activation_risk,
            "network_risk": self.network_risk,
            "workbox_risk": self.workbox_risk,
            "configuration_risk": self.configuration_risk,
            "total_score": self.total_score,
            "calculation_method": self.calculation_method,
            "version": self.version,
        }


@dataclass
class RiskAssessment:
    risk_score: int
    risk_level: RiskLevel
    breakdown: RiskBreakdown = field(default_factory=RiskBreakdown)
    security_findings: SecurityFindings = field(default_factory=SecurityFindings)
    assessment_timestamp: float = field(default_factory=lambda: time.time())
    assessor_version: str = "1.0.0"
    recommendations: List[str] = field(default_factory=list)
    priority: str = "medium" 

    def __post_init__(self):
        expected = RiskLevel.from_score(self.risk_score)
        if self.risk_level != expected:
            self.risk_level = expected
        if not self.recommendations:
            self._generate_recommendations()
        self.priority = self._calculate_priority()

    def _generate_recommendations(self):
        recs: List[str] = []
        flags = {str(f) for f in self.security_findings.security_flags}
        if "WIDENED_SCOPE" in flags:
            recs.append("Restrict Service-Worker-Allowed scope; prefer the SW script directory.")
        if "SENSITIVE_CACHING" in flags:
            recs.append("Avoid caching sensitive user data; require revalidation on auth-bound routes.")
        if "CACHE_POISONING_RISK" in flags:
            recs.append("Validate cache keys and inputs; prefer safe strategies for dynamic content.")
        if self.security_findings.pattern_detection.eval_usage:
            recs.append("Remove eval/new Function usage; replace with safer patterns.")
        if "THIRD_PARTY_IMPORTS" in flags:
            recs.append("Pin and integrity-check third-party scripts or serve first-party.")
        if "CLIENT_SIDE_AUTH" in flags:
            recs.append("Move authentication/authorization checks server-side.")
        self.recommendations = recs

    def _calculate_priority(self) -> str:
        if self.risk_level == RiskLevel.CRITICAL:
            return "critical"
        if self.risk_level == RiskLevel.HIGH:
            return "high"
        if self.risk_level == RiskLevel.MEDIUM:
            return "medium"
        return "low"

    @property
    def is_high_priority(self) -> bool:
        return self.priority in ("high", "critical")

    @property
    def has_security_flags(self) -> bool:
        return len(self.security_findings.security_flags) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "breakdown": self.breakdown.to_dict(),
            "security_findings": self.security_findings.to_dict(),
            "assessment_timestamp": self.assessment_timestamp,
            "assessor_version": self.assessor_version,
            "recommendations": self.recommendations,
            "priority": self.priority,
            "is_high_priority": self.is_high_priority,
            "has_security_flags": self.has_security_flags,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
