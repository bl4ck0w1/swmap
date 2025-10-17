from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
import time
import json
from .risk_models import RiskAssessment, SecurityFindings, RiskLevel

@dataclass
class SWResult:
    origin: str
    sw_url: str
    effective_scope: str
    http_status: int
    response_headers: Dict[str, str] = field(default_factory=dict)

    has_swa: bool = False 
    workbox: bool = False
    workbox_modules: List[str] = field(default_factory=list)
    cache_names: List[str] = field(default_factory=list)
    routes_seen: List[str] = field(default_factory=list)
    import_scripts: List[str] = field(default_factory=list)

    risk_score: int = 0
    risk_level: Union[RiskLevel, str] = RiskLevel.INFO
    security_flags: List[str] = field(default_factory=list)
    detected_patterns: Dict[str, bool] = field(default_factory=dict)

    risk_assessment: Optional[RiskAssessment] = None
    security_findings: Optional[Union[SecurityFindings, Dict[str, Any]]] = None

    scan_timestamp: float = field(default_factory=time.time)
    scan_duration: float = 0.0
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self):
        if isinstance(self.risk_level, str):
            try:
                self.risk_level = RiskLevel(self.risk_level)
            except Exception:
                self.risk_level = RiskLevel.INFO

        self.workbox_modules = sorted(set(self.workbox_modules))
        self.cache_names = sorted(set(self.cache_names))
        self.routes_seen = sorted(set(self.routes_seen))
        self.security_flags = sorted(set(self.security_flags))

    @property
    def has_service_worker(self) -> bool:
        return bool(self.sw_url and self.http_status == 200)

    @property
    def has_errors(self) -> bool:
        return self.error is not None

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0

    @property
    def is_high_risk(self) -> bool:
        return self.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    @property
    def cache_count(self) -> int:
        return len(self.cache_names)

    @property
    def route_count(self) -> int:
        return len(self.routes_seen)

    def add_warning(self, warning: str):
        if warning and warning not in self.warnings:
            self.warnings.append(warning)

    def to_tsv(self) -> str:
        fields = [
            self.origin,
            self.sw_url or "-",
            self.effective_scope or "-",
            str(self.http_status),
            "1" if self.has_swa else "0",
            "1" if self.workbox else "0",
            ",".join(self.cache_names) if self.cache_names else "-",
            ",".join(self.routes_seen) if self.routes_seen else "-",
            self.risk_level.value,
            ",".join(self.security_flags) if self.security_flags else "-",
            str(self.risk_score),
        ]
        safe = []
        for f in fields:
            s = str(f)
            s = s.replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")
            safe.append(s)
        return "\t".join(safe)

    def to_dict(self, include_details: bool = False) -> Dict[str, Any]:
        base = {
            "origin": self.origin,
            "sw_url": self.sw_url,
            "effective_scope": self.effective_scope,
            "http_status": self.http_status,
            "response_headers": self.response_headers,
            "has_swa": self.has_swa,
            "workbox": self.workbox,
            "workbox_modules": self.workbox_modules,
            "cache_names": self.cache_names,
            "routes_seen": self.routes_seen,
            "import_scripts": self.import_scripts,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "security_flags": self.security_flags,
            "detected_patterns": self.detected_patterns,
            "scan_timestamp": self.scan_timestamp,
            "scan_duration": self.scan_duration,
            "error": self.error,
            "warnings": self.warnings,
            "has_service_worker": self.has_service_worker,
            "has_errors": self.has_errors,
            "has_warnings": self.has_warnings,
            "is_high_risk": self.is_high_risk,
            "cache_count": self.cache_count,
            "route_count": self.route_count,
        }

        if include_details and self.risk_assessment:
            base["risk_assessment"] = self.risk_assessment.to_dict()

        if include_details and self.security_findings:
            if isinstance(self.security_findings, SecurityFindings):
                base["security_findings"] = self.security_findings.to_dict()
            elif isinstance(self.security_findings, dict):
                base["security_findings"] = self.security_findings

        return base

    def to_json(self, include_details: bool = False) -> str:
        return json.dumps(self.to_dict(include_details=include_details), indent=2)

    @classmethod
    def get_tsv_header(cls) -> str:
        return "\t".join(
            [
                "origin",
                "sw_url",
                "effective_scope",
                "http_status",
                "has_swa",
                "workbox",
                "cache_names",
                "routes_seen",
                "risk_level",
                "security_flags",
                "risk_score",
            ]
        )


@dataclass
class ScanSummary:
    scan_id: str
    start_time: float
    end_time: float
    config: Dict[str, Any] = field(default_factory=dict)
    total_targets: int = 0
    targets_processed: int = 0
    targets_with_sw: int = 0
    targets_with_errors: int = 0
    risk_distribution: Dict[str, int] = field(default_factory=dict)
    average_risk_score: float = 0.0
    max_risk_score: int = 0
    total_security_flags: int = 0
    high_risk_findings: int = 0
    sensitive_routes_found: int = 0
    total_duration: float = 0.0
    targets_per_second: float = 0.0
    results: List[SWResult] = field(default_factory=list)

    def __post_init__(self):
        self.total_duration = max(0.0, (self.end_time - self.start_time))
        self.targets_per_second = (
            (self.targets_processed / self.total_duration) if self.total_duration > 0 else 0.0
        )
        self._calculate_statistics()

    def _calculate_statistics(self):
        if not self.results:
            self.risk_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            return

        self.risk_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        scores: List[int] = []
        flag_total = 0
        sensitive_total = 0

        for r in self.results:
            self.risk_distribution[r.risk_level.value] += 1
            scores.append(int(r.risk_score))
            flag_total += len(r.security_flags)
            sensitive_total += sum(
                1
                for route in r.routes_seen
                if any(k in route.lower() for k in ("/api/", "/auth", "/user", "/admin"))
            )
            if r.is_high_risk:
                self.high_risk_findings += 1

        if scores:
            self.average_risk_score = sum(scores) / len(scores)
            self.max_risk_score = max(scores)

        self.total_security_flags = flag_total
        self.sensitive_routes_found = sensitive_total

    @property
    def success_rate(self) -> float:
        if self.total_targets == 0:
            return 0.0
        return (self.targets_processed - self.targets_with_errors) / self.total_targets

    @property
    def sw_detection_rate(self) -> float:
        if self.targets_processed == 0:
            return 0.0
        return self.targets_with_sw / self.targets_processed

    @property
    def high_risk_rate(self) -> float:
        if self.targets_with_sw == 0:
            return 0.0
        return self.high_risk_findings / self.targets_with_sw

    def get_high_risk_results(self) -> List[SWResult]:
        return [r for r in self.results if r.is_high_risk]

    def get_results_with_errors(self) -> List[SWResult]:
        return [r for r in self.results if r.has_errors]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_duration": self.total_duration,
            "config": self.config,
            "total_targets": self.total_targets,
            "targets_processed": self.targets_processed,
            "targets_with_sw": self.targets_with_sw,
            "targets_with_errors": self.targets_with_errors,
            "risk_distribution": self.risk_distribution,
            "average_risk_score": round(self.average_risk_score, 2),
            "max_risk_score": self.max_risk_score,
            "total_security_flags": self.total_security_flags,
            "high_risk_findings": self.high_risk_findings,
            "sensitive_routes_found": self.sensitive_routes_found,
            "targets_per_second": round(self.targets_per_second, 2),
            "success_rate": round(self.success_rate, 3),
            "sw_detection_rate": round(self.sw_detection_rate, 3),
            "high_risk_rate": round(self.high_risk_rate, 3),
            "high_risk_count": len(self.get_high_risk_results()),
            "error_count": len(self.get_results_with_errors()),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def print_summary(self):
        print("\n=== SWMap Scan Summary ===")
        print(f"Scan ID: {self.scan_id}")
        print(f"Duration: {self.total_duration:.2f}s")
        print(f"Targets: {self.targets_processed}/{self.total_targets} processed")
        print(f"Service Workers: {self.targets_with_sw} found")
        print(f"Success Rate: {self.success_rate:.1%}")
        print("\nRisk Distribution:")
        for level, count in self.risk_distribution.items():
            if count > 0:
                print(f"  {level}: {count}")
        print("\nSecurity Findings:")
        print(f"  High Risk: {self.high_risk_findings}")
        print(f"  Security Flags: {self.total_security_flags}")
        print(f"  Sensitive Routes: {self.sensitive_routes_found}")
        print(f"\nPerformance: {self.targets_per_second:.1f} targets/second")
