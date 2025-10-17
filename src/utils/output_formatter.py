import json
import csv
from typing import List, Dict, Any, TextIO
from ..models.result import SWResult, ScanSummary

class OutputFormatter:
    def __init__(self):
        self.supported_formats = ["tsv", "json", "jsonl", "csv"]

    def format_result(self, result: SWResult, format_type: str = "tsv") -> str:
        format_type = format_type.lower()
        if format_type == "tsv":
            return self._format_tsv(result)
        if format_type == "json":
            return self._format_json(result, pretty=True)
        if format_type == "jsonl":
            return self._format_json(result, pretty=False)
        if format_type == "csv":
            return self._format_csv(result)
        raise ValueError(f"Unsupported format: {format_type}")

    def format_results(self, results: List[SWResult], format_type: str = "tsv") -> List[str]:
        format_type = format_type.lower()
        if format_type == "json":
            data = [r.to_dict(include_details=True) for r in results]
            return [json.dumps(data, indent=2, ensure_ascii=False)]
        return [self.format_result(r, format_type) for r in results]

    def _format_tsv(self, result: SWResult) -> str:
        return result.to_tsv()

    def _format_json(self, result: SWResult, pretty: bool = False) -> str:
        data = result.to_dict(include_details=True)
        return json.dumps(data, indent=2 if pretty else None, ensure_ascii=False)

    def _format_csv(self, result: SWResult) -> str:
        import io

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        row = [
            result.origin,
            result.sw_url or "",
            result.effective_scope or "",
            result.http_status,
            "YES" if result.has_swa else "NO",
            "YES" if result.workbox else "NO",
            ";".join(result.cache_names),
            ";".join(result.routes_seen),
            result.risk_level.value,
            ";".join(result.security_flags),
            result.risk_score,
        ]
        writer.writerow(row)
        return output.getvalue().strip()

    def get_header(self, format_type: str = "tsv") -> str:
        format_type = format_type.lower()
        if format_type == "tsv":
            return SWResult.get_tsv_header()
        if format_type == "csv":
            return "origin,sw_url,effective_scope,http_status,has_swa,workbox,cache_names,routes_seen,risk_level,security_flags,risk_score"
        return ""


class ResultSerializer:
    def __init__(self):
        self.formatter = OutputFormatter()

    def serialize_to_file(
        self,
        results: List[SWResult],
        output_file: TextIO,
        format_type: str = "tsv",
        include_header: bool = True,
        risk_threshold: int = 0,
        only_high_risk: bool = False,
    ):
        filtered = self._filter_results(results, risk_threshold, only_high_risk)
        filtered.sort(key=lambda x: x.risk_score, reverse=True)

        ft = format_type.lower()
        if ft == "json":
            data = [r.to_dict(include_details=True) for r in filtered]
            json.dump(data, output_file, indent=2, ensure_ascii=False)
            output_file.write("\n")
            return

        if include_header and ft in ("tsv", "csv"):
            output_file.write(self.formatter.get_header(ft) + "\n")

        for r in filtered:
            output_file.write(self.formatter.format_result(r, ft) + "\n")

    def _filter_results(self, results: List[SWResult], risk_threshold: int, only_high_risk: bool) -> List[SWResult]:
        out: List[SWResult] = []
        for r in results:
            if r.risk_score < risk_threshold:
                continue
            if only_high_risk and not r.is_high_risk:
                continue
            out.append(r)
        return out

    def create_summary_report(self, summary: ScanSummary, format_type: str = "text") -> str:
        return summary.to_json() if format_type.lower() == "json" else self._create_text_summary(summary)

    def _create_text_summary(self, summary: ScanSummary) -> str:
        lines: List[str] = []
        lines.append("=" * 60)
        lines.append("SWMap Security Scan Summary")
        lines.append("=" * 60)
        lines.append(f"Scan ID: {summary.scan_id}")
        lines.append(f"Duration: {summary.total_duration:.2f} seconds")
        lines.append(f"Targets Processed: {summary.targets_processed}/{summary.total_targets}")
        lines.append(f"Service Workers Found: {summary.targets_with_sw}")
        lines.append(f"Success Rate: {summary.success_rate:.1%}")

        lines.append("\nRisk Distribution:")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = summary.risk_distribution.get(level, 0)
            if count > 0:
                lines.append(f"  {level}: {count}")

        lines.append("\nSecurity Findings:")
        lines.append(f"  High Risk Findings: {summary.high_risk_findings}")
        lines.append(f"  Total Security Flags: {summary.total_security_flags}")
        lines.append(f"  Sensitive Routes: {summary.sensitive_routes_found}")
        lines.append(f"\nPerformance: {summary.targets_per_second:.1f} targets/second")
        lines.append("=" * 60)
        return "\n".join(lines)


output_formatter = OutputFormatter()
result_serializer = ResultSerializer()
