#!/usr/bin/env python3
import time
import statistics
import psutil
import sys
import os
from collections import deque
from typing import List, Dict, Any
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.core.scanner import SWScanner
from src.models.target import ScanTarget, ScanConfig
from src.utils.logger import setup_logging, get_logger


class Benchmark:
    def __init__(self):
        self.logger = get_logger("benchmark")
        self.results: Dict[str, Any] = {}
        self.memory_usage: deque[float] = deque(maxlen=10000)  
        self._monitoring = False

    def _memory_monitor(self, interval: float = 0.1):
        process = psutil.Process()
        try:
            while self._monitoring:
                rss_mb = process.memory_info().rss / (1024 * 1024)
                self.memory_usage.append(rss_mb)
                time.sleep(interval)
        except Exception as e:
            self.logger.debug(f"Memory monitor stopped: {e}")

    def start_memory_monitor(self, interval: float = 0.1):
        import threading

        self._monitoring = True
        self.memory_usage.clear()
        self._monitor_thread = threading.Thread(target=self._memory_monitor, args=(interval,), daemon=True)
        self._monitor_thread.start()

    def stop_memory_monitor(self):
        self._monitoring = False
        t = getattr(self, "_monitor_thread", None)
        if t and t.is_alive():
            t.join(timeout=1.5)

    def measure_memory_mb(self) -> float:
        try:
            return psutil.Process().memory_info().rss / (1024 * 1024)
        except Exception:
            return 0.0

    def run_single_target_benchmark(self, target_url: str, iterations: int = 10) -> Dict[str, Any]:
        self.logger.info(f"Running single target benchmark: {target_url}")

        timings: List[float] = []
        memory_peaks: List[float] = []

        target = ScanTarget(target_url)
        config = ScanConfig(parallel=1, timeout=10, quiet_mode=True)

        for i in range(iterations):
            self.logger.debug(f"Iteration {i + 1}/{iterations}")
            self.start_memory_monitor()

            start_time = time.time()
            scan_success = False
            scanner = None
            try:
                scanner = SWScanner(
                    parallel=config.parallel,
                    timeout=config.timeout,
                    quiet_mode=config.quiet_mode,
                )
                results = list(scanner.scan_targets([target]))
                scan_success = len(results) > 0
            except Exception as e:
                self.logger.warning(f"Scan failed in iteration {i + 1}: {e}")
            finally:
                end_time = time.time()
                self.stop_memory_monitor()
                if scanner is not None:
                    try:
                        scanner.close()
                    except Exception:
                        pass

            duration = end_time - start_time
            if scan_success:
                timings.append(duration)
                if self.memory_usage:
                    memory_peaks.append(max(self.memory_usage))

        stats = {
            "target": target_url,
            "iterations": iterations,
            "successful_iterations": len(timings),
            "timings": {
                "min": min(timings) if timings else 0.0,
                "max": max(timings) if timings else 0.0,
                "mean": statistics.mean(timings) if timings else 0.0,
                "median": statistics.median(timings) if timings else 0.0,
                "stdev": statistics.stdev(timings) if len(timings) > 1 else 0.0,
            },
            "memory_mb": {
                "min": min(memory_peaks) if memory_peaks else 0.0,
                "max": max(memory_peaks) if memory_peaks else 0.0,
                "mean": statistics.mean(memory_peaks) if memory_peaks else 0.0,
            },
            "throughput": (1.0 / statistics.mean(timings)) if timings and statistics.mean(timings) > 0 else 0.0,
        }

        self.results["single_target"] = stats
        return stats

    def run_concurrency_benchmark(self, target_urls: List[str], max_workers: int = 10) -> Dict[str, Any]:
        self.logger.info(f"Running concurrency benchmark with {len(target_urls)} targets")

        concurrency_results: Dict[int, Dict[str, Any]] = {}
        targets = [ScanTarget(url) for url in target_urls]

        for workers in range(1, max_workers + 1):
            self.logger.info(f"Testing with {workers} workers...")
            config = ScanConfig(parallel=workers, timeout=10, quiet_mode=True)

            self.start_memory_monitor()
            start = time.time()
            success_count = 0
            scanner = None

            try:
                scanner = SWScanner(parallel=config.parallel, timeout=config.timeout, quiet_mode=config.quiet_mode)
                results = list(scanner.scan_targets(targets))
                success_count = sum(1 for r in results if getattr(r, "has_service_worker", False))
            except Exception as e:
                self.logger.warning(f"Concurrent scan failed with {workers} workers: {e}")
            finally:
                end = time.time()
                self.stop_memory_monitor()
                if scanner is not None:
                    try:
                        scanner.close()
                    except Exception:
                        pass

            duration = max(0.0, end - start)
            total = len(targets)
            tps = (total / duration) if duration > 0 and total > 0 else 0.0
            concurrency_results[workers] = {
                "targets_processed": total,
                "successful_scans": success_count,
                "total_duration": duration,
                "targets_per_second": tps,
                "avg_time_per_target": (duration / total) if total > 0 else 0.0,
                "max_memory_mb": max(self.memory_usage) if self.memory_usage else 0.0,
            }

        optimal_workers = max(concurrency_results.keys(), key=lambda w: concurrency_results[w]["targets_per_second"])
        results = {
            "concurrency_results": concurrency_results,
            "optimal_workers": optimal_workers,
            "max_throughput": concurrency_results[optimal_workers]["targets_per_second"],
        }

        self.results["concurrency"] = results
        return results

    def run_memory_benchmark(self, target_urls: List[str]) -> Dict[str, Any]:
        self.logger.info("Running memory usage benchmark")
        memory_samples: List[Dict[str, float]] = []
        targets = [ScanTarget(url) for url in target_urls]
        initial_memory = self.measure_memory_mb()

        self.start_memory_monitor()

        scanner = None
        try:
            scanner = SWScanner(parallel=6, timeout=10, quiet_mode=True)
            for i, _ in enumerate(scanner.scan_targets(targets), start=1):
                current = self.measure_memory_mb()
                memory_samples.append(
                    {"targets_processed": float(i), "memory_mb": current, "memory_increase": current - initial_memory}
                )
                if i % 10 == 0:
                    self.logger.debug(f"Processed {i}/{len(targets)} targets")
        except Exception as e:
            self.logger.warning(f"Memory benchmark failed: {e}")
        finally:
            self.stop_memory_monitor()
            if scanner is not None:
                try:
                    scanner.close()
                except Exception:
                    pass

        if memory_samples:
            mem_vals = [s["memory_mb"] for s in memory_samples]
            inc_vals = [s["memory_increase"] for s in memory_samples]
            stats = {
                "initial_memory_mb": initial_memory,
                "peak_memory_mb": max(mem_vals),
                "avg_memory_mb": statistics.mean(mem_vals),
                "max_increase_mb": max(inc_vals),
                "avg_increase_per_target": (statistics.mean(inc_vals) / len(targets)) if targets else 0.0,
                "memory_samples": memory_samples,
            }
        else:
            stats = {"error": "No memory data collected"}

        self.results["memory"] = stats
        return stats

    def run_pattern_matching_benchmark(self, test_files: List[str]) -> Dict[str, Any]:
        self.logger.info("Running pattern matching benchmark")
        from src.utils.pattern_matcher import security_patterns  
        from src.core.analyzer import SWAnalyzer
        from src.core.security_analyzer import SecurityAnalyzer

        analyzer = SWAnalyzer()
        security_analyzer = SecurityAnalyzer()
        pattern_results: Dict[str, Any] = {}

        for test_file in test_files:
            if not os.path.exists(test_file):
                self.logger.warning(f"Test file not found: {test_file}")
                continue

            self.logger.debug(f"Testing pattern matching on: {test_file}")
            with open(test_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            components = {
                "workbox_detection": lambda: analyzer.detect_workbox(content),
                "cache_extraction": lambda: analyzer.extract_cache_names(content),
                "route_extraction": lambda: analyzer.extract_routes(content),
                "security_analysis": lambda: security_analyzer.analyze_security_patterns(content),
            }

            file_results: Dict[str, Any] = {}
            for name, fn in components.items():
                times: List[float] = []
                for _ in range(5):
                    start = time.time()
                    try:
                        fn()
                        times.append(time.time() - start)
                    except Exception as e:
                        self.logger.warning(f"Component {name} failed: {e}")
                        times.append(0)
                        break

                file_results[name] = {
                    "min_time": min(times) if times else 0.0,
                    "max_time": max(times) if times else 0.0,
                    "avg_time": statistics.mean(times) if times else 0.0,
                    "success": bool(times),
                }

            pattern_results[test_file] = file_results

        self.results["pattern_matching"] = pattern_results
        return pattern_results

    def generate_report(self, output_file: str | None = None) -> Dict[str, Any]:
        report = {
            "timestamp": time.time(),
            "swmap_version": "1.0.0",
            "system_info": self.get_system_info(),
            "benchmark_results": self.results,
            "summary": self.generate_summary(),
        }
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Benchmark report saved to: {output_file}")
        return report

    def get_system_info(self) -> Dict[str, Any]:
        import platform

        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "memory_gb": psutil.virtual_memory().total / (1024**3),
        }

    def generate_summary(self) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}

        if "single_target" in self.results:
            single = self.results["single_target"]
            summary["single_target_performance"] = {
                "avg_scan_time_seconds": single["timings"]["mean"],
                "scans_per_second": single["throughput"],
                "memory_usage_mb": single["memory_mb"]["mean"],
            }

        if "concurrency" in self.results:
            concurrency = self.results["concurrency"]
            summary["concurrency_recommendations"] = {
                "optimal_workers": concurrency["optimal_workers"],
                "max_throughput_targets_second": concurrency["max_throughput"],
                "scaling_efficiency": self.calculate_scaling_efficiency(concurrency["concurrency_results"]),
            }

        if "memory" in self.results:
            memory = self.results["memory"]
            summary["memory_efficiency"] = {
                "peak_usage_mb": memory.get("peak_memory_mb", 0.0),
                "memory_per_target_mb": memory.get("avg_increase_per_target", 0.0),
            }

        if "pattern_matching" in self.results:
            summary["pattern_matching"] = self.summarize_pattern_performance(self.results["pattern_matching"])

        return summary

    def calculate_scaling_efficiency(self, concurrency_results: Dict[int, Dict[str, Any]]) -> float:
        if not concurrency_results:
            return 0.0
        base = concurrency_results.get(1, {}).get("targets_per_second", 0.0)
        if base <= 0:
            return 0.0
        max_tps = max(r["targets_per_second"] for r in concurrency_results.values())
        max_workers = max(concurrency_results.keys())
        ideal = base * max_workers
        return (max_tps / ideal) if ideal > 0 else 0.0

    def summarize_pattern_performance(self, pattern_results: Dict[str, Any]) -> Dict[str, Any]:
        times = []
        for file_results in pattern_results.values():
            for comp in file_results.values():
                if comp.get("success"):
                    times.append(comp.get("avg_time", 0.0))
        if times:
            return {
                "avg_analysis_time_ms": statistics.mean(times) * 1000,
                "max_analysis_time_ms": max(times) * 1000,
                "total_components_tested": len(times),
            }
        return {"error": "No successful pattern matching tests"}

    def run_comprehensive_benchmark(self, test_targets: List[str], output_file: str | None = None) -> Dict[str, Any]:
        self.logger.info("Starting comprehensive SWMap benchmark")
        try:
            if test_targets:
                self.run_single_target_benchmark(test_targets[0])
                self.run_concurrency_benchmark(test_targets[:10])
                self.run_memory_benchmark(test_targets[:50])

            fixtures = self.find_test_fixtures()
            if fixtures:
                self.run_pattern_matching_benchmark(fixtures)

            report = self.generate_report(output_file)
            self.logger.info("Benchmark completed successfully")
            return report
        except Exception as e:
            self.logger.error(f"Benchmark failed: {e}")
            raise

    def find_test_fixtures(self) -> List[str]:
        fixture_dirs = ["tests/fixtures/sw_scripts", "tests/fixtures/html", "fixtures"]
        fixtures: List[str] = []
        for d in fixture_dirs:
            if os.path.exists(d):
                for root, _, files in os.walk(d):
                    for file in files:
                        if file.endswith((".js", ".html", ".txt")):
                            fixtures.append(os.path.join(root, file))
        return fixtures[:10]


def main():
    import argparse

    parser = argparse.ArgumentParser(description="SWMap Performance Benchmark")
    parser.add_argument("--targets", "-t", nargs="+", help="Target URLs to test")
    parser.add_argument("--output", "-o", help="Output report file")
    parser.add_argument("--single", action="store_true", help="Run only single target benchmark")
    parser.add_argument("--concurrency", action="store_true", help="Run only concurrency benchmark")
    parser.add_argument("--memory", action="store_true", help="Run only memory benchmark")
    parser.add_argument("--patterns", action="store_true", help="Run only pattern matching benchmark")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(level=log_level, enable_console=True)

    benchmark = Benchmark()
    test_targets = args.targets or [
        "https://httpbin.org/html",
        "https://httpbin.org/json",
        "https://example.com",
    ]

    try:
        if args.single:
            benchmark.run_single_target_benchmark(test_targets[0])
        elif args.concurrency:
            benchmark.run_concurrency_benchmark(test_targets[:5])
        elif args.memory:
            benchmark.run_memory_benchmark(test_targets[:10])
        elif args.patterns:
            benchmark.run_pattern_matching_benchmark(benchmark.find_test_fixtures())
        else:
            benchmark.run_comprehensive_benchmark(test_targets, args.output)

        if benchmark.results:
            print("\n" + "=" * 60)
            print("SWMap Benchmark Summary")
            print("=" * 60)
            summary = benchmark.generate_summary()
            for category, data in summary.items():
                print(f"\n{category.upper().replace('_', ' ')}:")
                for key, value in data.items():
                    print(f"  {key}: {value}")

    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
        return 1
    except Exception as e:
        print(f"Benchmark failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
