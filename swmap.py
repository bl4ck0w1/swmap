#!/usr/bin/env python3
from __future__ import annotations
import os
import sys
import argparse
from typing import List
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from src.models.target import ScanTarget, ScanConfig
from src.models.result import SWResult, ScanSummary
from src.utils.logger import setup_logging, get_logger
from config.constants import DEFAULT_CONFIG, SCAN_LIMITS, EXIT_CODES, get_version

logger = get_logger("cli")

BANNER = r"""                                                            
                                                            
  █████  █████ ███ █████ █████████████    ██████   ████████ 
 ███░░  ░░███ ░███░░███ ░░███░░███░░███  ░░░░░███ ░░███░░███
░░█████  ░███ ░███ ░███  ░███ ░███ ░███   ███████  ░███ ░███
 ░░░░███ ░░███████████   ░███ ░███ ░███  ███░░███  ░███ ░███
 ██████   ░░████░████    █████░███ █████░░████████ ░███████ 
░░░░░░     ░░░░ ░░░░    ░░░░░ ░░░ ░░░░░  ░░░░░░░░  ░███░░░  
                                                   ░███     
                                                   █████    
                                                  ░░░░░     
"""
TITLE = "Service Worker Security Mapper - Advanced SW reconn tool"

class SWMapCLI:
    def __init__(self):
        self.parser = self._create_parser()
        self.config: ScanConfig | None = None
        self.scanner = None  

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description=TITLE,
            epilog="For more information: https://github.com/bl4ck0w1/swmap",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            add_help=False,
            usage=argparse.SUPPRESS, 
        )

        info = parser.add_argument_group("Information Options")
        info.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
        info.add_argument("-V", "--version", action="store_true", help="Show version information and exit")

        inp = parser.add_argument_group("Input Options")
        inp.add_argument("target", nargs="?", help="Single URL to scan (e.g., https://target.com)")
        inp.add_argument("-i", "--input", dest="input_file", help="Read targets from file (one URL per line)")
        inp.add_argument("--no-probe", action="store_true", help="Skip common SW filename probing")

        scan = parser.add_argument_group("Scan Options")
        scan.add_argument("-P", "--parallel", type=int, default=DEFAULT_CONFIG["parallel_workers"], help=f'Concurrent scans (default: {DEFAULT_CONFIG["parallel_workers"]}, max: {SCAN_LIMITS["max_concurrent_connections"]})',)
        scan.add_argument("-t", "--timeout", type=int, default=DEFAULT_CONFIG["request_timeout"], help=f'Request timeout in seconds (default: {DEFAULT_CONFIG["request_timeout"]})',)
        scan.add_argument("--max-sw-bytes", type=int, default=DEFAULT_CONFIG["max_sw_bytes"], help=f'Maximum SW script size in bytes (default: {DEFAULT_CONFIG["max_sw_bytes"]})',)
        scan.add_argument("--max-routes", type=int,default=DEFAULT_CONFIG["max_routes_per_sw"], help=f'Maximum routes to extract per SW (default: {DEFAULT_CONFIG["max_routes_per_sw"]})',)
        scan.add_argument("--deep", action="store_true", help="Legacy deep static parse hint (will set --ast-depth=2 if not provided)",)

        enh = parser.add_argument_group("Enhanced Analysis (optional)")
        enh.add_argument("--ast", dest="ast", action="store_true", default=True, help="Enable AST analysis (default)")
        enh.add_argument("--no-ast", dest="ast", action="store_false", help="Disable AST analysis")
        enh.add_argument("--ast-depth", type=int, default=None, help="Recurse importScripts/ESM to this depth (default: 0; or 2 if --deep)", )
        enh.add_argument("--headless", action="store_true", help="Enable Playwright headless validation")
        enh.add_argument("--headless-timeout", type=int, default=30000, help="Headless timeout (ms)")
        enh.add_argument("--headless-max-routes", type=int, default=25, help="Max routes to probe dynamically")
        enh.add_argument("--headless-crawl", dest="headless_crawl", action="store_true", default=True, help="Crawl same-origin links (default)")
        enh.add_argument("--no-headless-crawl", dest="headless_crawl", action="store_false", help="Disable headless crawl")
        enh.add_argument("--route-seed", action="append", default=[], help="Seed route (repeatable)")
        enh.add_argument("--login-script", help="Path to a JS file to run before crawl (auto-login etc.)")
        enh.add_argument("--login-wait", dest="login_wait", help="CSS selector to wait for after login")
        enh.add_argument("--prove-interception", action="store_true", default=True, help="Prove response interception via SW")
        enh.add_argument("--no-prove-interception", dest="prove_interception", action="store_false", help="Disable interception proof")
        enh.add_argument("--prove-precache", action="store_true", default=True, help="Prove precache via cache audit")
        enh.add_argument("--no-prove-precache", dest="prove_precache", action="store_false", help="Disable precache proof")
        enh.add_argument("--prove-swr", action="store_true", default=True, help="Try to detect stale-while-revalidate")
        enh.add_argument("--no-prove-swr", dest="prove_swr", action="store_false", help="Disable SWR proof")

        sec = parser.add_argument_group("Security Analysis Options")
        sec.add_argument("--risk-threshold", type=int, default=0, help="Only output findings with risk score >= N (0-100)")
        sec.add_argument("--no-risk-assessment", action="store_true", help="Skip risk scoring and security analysis")
        sec.add_argument("--include-patterns", action="store_true", help="Output detected security patterns in detail")
        sec.add_argument("--sensitive-only", action="store_true", help="Only output workers with sensitive route patterns")

        out = parser.add_argument_group("Output Options")
        out.add_argument("--json", action="store_true", help="JSONL output with full security analysis")
        out.add_argument("--quiet", action="store_true", help="Suppress comments and progress messages")
        out.add_argument("--verbose", action="store_true", help="Detailed security analysis output")
        out.add_argument("-o", "--output", help="Write results to file")

        net = parser.add_argument_group("Network Options")
        net.add_argument("--ua", "--user-agent", dest="user_agent", help="Custom User-Agent string")
        net.add_argument("--header", action="append", dest="headers", help="Extra HTTP header (repeatable)")
        net.add_argument("--cookie", help="Cookie header value")
        net.add_argument("--proxy", help="HTTP proxy URL (currently unused)")
        return parser

    def parse_arguments(self) -> argparse.Namespace:
        return self.parser.parse_args()

    def show_help(self) -> None:
        print(BANNER)
        print(TITLE + "\n")
        self.parser.print_help()
        print("\nFor more information: https://github.com/bl4ck0w1/swmap\n")

    def _create_scan_config(self, args: argparse.Namespace) -> ScanConfig:
        headers = {}
        if args.headers:
            for header in args.headers:
                if ":" in header:
                    k, v = header.split(":", 1)
                    headers[k.strip()] = v.strip()

        return ScanConfig(
            parallel=args.parallel,
            timeout=args.timeout,
            max_sw_bytes=args.max_sw_bytes,
            max_routes=args.max_routes,
            user_agent=args.user_agent,
            headers=headers,
            cookies=args.cookie,
            probe_common_paths=not args.no_probe,
            deep_analysis=args.deep,
            risk_threshold=args.risk_threshold,
            output_format="json" if args.json else "tsv",
            quiet_mode=args.quiet,
            verbose=args.verbose,
        )

    def _create_scanner(self, config: ScanConfig, args: argparse.Namespace):
        from src.core.scanner import SWScanner

        ast_depth = args.ast_depth if args.ast_depth is not None else (2 if args.deep else 0)

        return SWScanner(
            parallel=config.parallel,
            timeout=config.timeout,
            max_sw_bytes=config.max_sw_bytes,
            max_routes=config.max_routes,
            user_agent=config.user_agent,
            headers=config.headers,
            cookies=config.cookies,
            no_risk_assessment=args.no_risk_assessment,
            enable_ast_analysis=args.ast,
            ast_max_depth=ast_depth,
            ast_request_timeout=max(5, min(30, config.timeout)),
            enable_headless_analysis=args.headless,
            headless_timeout_ms=args.headless_timeout,
            headless_max_routes=args.headless_max_routes,
            headless_crawl=args.headless_crawl,
            headless_crawl_limit=50,
            headless_backoff_attempts=4,
            headless_backoff_ms=500,
            headless_prove_interception=args.prove_interception,
            headless_prove_precache=args.prove_precache,
            headless_prove_swr=args.prove_swr,
            headless_login_script=args.login_script,
            headless_login_wait_selector=args.login_wait,
            headless_route_seeds=args.route_seed or [],
)

    def _setup_output(self, args: argparse.Namespace) -> None:
        if args.output:
            try:
                d = os.path.dirname(args.output)
                if d and not os.path.exists(d):
                    os.makedirs(d, exist_ok=True)
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write("")
                logger.info(f"Output will be written to: {args.output}")
            except Exception as e:
                logger.error(f"Cannot write to output file: {e}")
                sys.exit(EXIT_CODES["CONFIG_ERROR"])

    def _load_targets(self, args: argparse.Namespace) -> List[ScanTarget]:
        targets: List[ScanTarget] = []

        if args.target:
            try:
                targets.append(ScanTarget(args.target))
                logger.info(f"Added target: {args.target}")
            except Exception as e:
                logger.error(f"Invalid target URL: {e}")
                sys.exit(EXIT_CODES["CONFIG_ERROR"])

        if args.input_file:
            try:
                with open(args.input_file, "r", encoding="utf-8") as f:
                    for line_num, line in enumerate(f, 1):
                        url = line.strip()
                        if url and not url.startswith("#"):
                            try:
                                targets.append(ScanTarget(url))
                            except Exception as e:
                                logger.warning(f"Invalid target on line {line_num}: {url} - {e}")
                logger.info(f"Loaded {len(targets)} targets from {args.input_file}")
            except Exception as e:
                logger.error(f"Failed to read input file: {e}")
                sys.exit(EXIT_CODES["CONFIG_ERROR"])

        if not targets:
            logger.error("No valid targets provided")
            self.show_help()
            sys.exit(EXIT_CODES["USAGE_ERROR"])

        return targets

    def _write_output(self, results: List[SWResult], args: argparse.Namespace) -> None:
        output_file = None
        if args.output:
            try:
                output_file = open(args.output, "w", encoding="utf-8")
            except Exception as e:
                logger.error(f"Failed to open output file: {e}")
                output_file = None

        try:
            out_stream = output_file or sys.stdout
            if not args.json and not args.quiet:
                out_stream.write(SWResult.get_tsv_header() + "\n")

            for r in results:
                out_stream.write((r.to_json(include_details=args.include_patterns) if args.json else r.to_tsv()) + "\n")
            out_stream.flush()
        finally:
            if output_file:
                output_file.close()

    def _print_summary(self, results: List[SWResult], scanner) -> None:
        if not results:
            return
        summary = ScanSummary(
            scan_id=f"scan_{int(scanner.stats.get('start_time', 0))}",
            start_time=scanner.stats.get("start_time", 0),
            end_time=scanner.stats.get("end_time", 0),
            config={},
            total_targets=scanner.stats.get("targets_processed", 0),
            targets_processed=scanner.stats.get("targets_processed", 0),
            targets_with_sw=scanner.stats.get("sw_found", 0),
            targets_with_errors=scanner.stats.get("errors", 0),
            results=results,
        )
        if not self.config or not self.config.quiet_mode:
            summary.print_summary()

    def run(self, args: argparse.Namespace) -> int:
        try:
            self.config = self._create_scan_config(args)
            self.config.validate()
            setup_logging(level=("DEBUG" if args.verbose else "INFO") if not args.quiet else "WARNING", enable_console=not args.quiet)

            targets = self._load_targets(args)
            self._setup_output(args)

            scanner = self._create_scanner(self.config, args)
            self.scanner = scanner

            logger.info(f"Starting scan of {len(targets)} targets")

            results: List[SWResult] = []
            for result in scanner.scan_targets(targets, probe=not args.no_probe):
                if result and (args.risk_threshold <= 0 or result.risk_score >= args.risk_threshold):
                    if not args.sensitive_only or result.routes_seen:
                        results.append(result)

            self._write_output(results, args)
            self._print_summary(results, scanner)

            return EXIT_CODES["NETWORK_ERROR"] if scanner.stats.get("errors", 0) > 0 else EXIT_CODES["SUCCESS"]
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
            return EXIT_CODES["UNKNOWN_ERROR"]
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            if args.verbose:
                logger.exception("Detailed error:")
            return EXIT_CODES["UNKNOWN_ERROR"]
        finally:
            if self.scanner:
                try:
                    self.scanner.close()
                except Exception:
                    pass


def main():
    cli = SWMapCLI()
    args = cli.parse_arguments()
    if args.help:
        print(BANNER)
        print(TITLE + "\n")
        cli.parser.print_help()
        print("\nFor more information: https://github.com/bl4ck0w1/swmap")
        sys.exit(EXIT_CODES["SUCCESS"])

    if args.version:
        print(BANNER)
        print(f"SWMap - Service Worker Security Analyzer v{get_version()}")
        print("Advanced recon tool for Service Worker security assessment")
        print("https://github.com/bl4ck0w1/swmap.git")
        sys.exit(EXIT_CODES["SUCCESS"])

    sys.exit(cli.run(args))
    
if __name__ == "__main__":
    main()
