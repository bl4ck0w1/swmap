#!/usr/bin/env python3
from __future__ import annotations
import os
import sys
import argparse
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
from src.core.scanner import SWScanner
from src.models.target import ScanTarget, ScanConfig
from src.models.result import SWResult, ScanSummary
from src.utils.logger import setup_logging, get_logger
from src.utils.output_formatter import output_formatter, result_serializer
from src.utils.validator import url_validator, input_sanitizer
from config.constants import DEFAULT_CONFIG, SCAN_LIMITS, EXIT_CODES, get_version

logger = get_logger('cli')

BANNER = r'''                                                            
                                                            
  █████  █████ ███ █████ █████████████    ██████   ████████ 
 ███░░  ░░███ ░███░░███ ░░███░░███░░███  ░░░░░███ ░░███░░███
░░█████  ░███ ░███ ░███  ░███ ░███ ░███   ███████  ░███ ░███
 ░░░░███ ░░███████████   ░███ ░███ ░███  ███░░███  ░███ ░███
 ██████   ░░████░████    █████░███ █████░░████████ ░███████ 
░░░░░░     ░░░░ ░░░░    ░░░░░ ░░░ ░░░░░  ░░░░░░░░  ░███░░░  
                                                   ░███     
                                                   █████    
                                                  ░░░░░     
    '''

class SWMapCLI:
    def __init__(self):
        self.parser = self.create_parser()
        self.config: ScanConfig | None = None
        self.scanner: SWScanner | None = None

    def create_parser(self) -> argparse.ArgumentParser:
        description = BANNER + "\nService Worker Security Mapper - Advanced SW reconn tool"

        parser = argparse.ArgumentParser(
            description=description,
            epilog='For more information: https://github.com/bl4ck0w1/swmap',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            add_help=False  
        )

        info_group = parser.add_argument_group('Information Options')
        info_group.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
        info_group.add_argument('-V', '--version', action='store_true', help='Show version information and exit')
        
        input_group = parser.add_argument_group('Input Options')
        input_group.add_argument('target', nargs='?', help='Single URL to scan (e.g., https://example.com)')
        input_group.add_argument('-i', '--input', dest='input_file', help='Read targets from file (one URL per line)')
        input_group.add_argument('--no-probe', action='store_true', help='Skip common SW filename probing')

        scan_group = parser.add_argument_group('Scan Options')
        scan_group.add_argument('-P', '--parallel', type=int, default=DEFAULT_CONFIG['parallel_workers'], help=f'Concurrent scans (default: {DEFAULT_CONFIG["parallel_workers"]}, 'f'max: {SCAN_LIMITS["max_concurrent_connections"]})')
        scan_group.add_argument('-t', '--timeout', type=int, default=DEFAULT_CONFIG['request_timeout'], help=f'Request timeout in seconds (default: {DEFAULT_CONFIG["request_timeout"]})')
        scan_group.add_argument('--max-sw-bytes', type=int, default=DEFAULT_CONFIG['max_sw_bytes'], help=f'Maximum SW script size in bytes (default: {DEFAULT_CONFIG["max_sw_bytes"]})')
        scan_group.add_argument('--max-routes', type=int, default=DEFAULT_CONFIG['max_routes_per_sw'], help=f'Maximum routes to extract per SW (default: {DEFAULT_CONFIG["max_routes_per_sw"]})')
        scan_group.add_argument('--deep', action='store_true', help='Legacy deep static parse hint (will set --ast-depth=2 if not provided)')

        enh = parser.add_argument_group('Enhanced Analysis (optional)')
        enh.add_argument('--ast', dest='ast', action='store_true', default=True, help='Enable AST analysis (default)')
        enh.add_argument('--no-ast', dest='ast', action='store_false', help='Disable AST analysis')
        enh.add_argument('--ast-depth', type=int, default=None, help='Recurse importScripts/ESM to this depth (default: 0; or 2 if --deep)')
        enh.add_argument('--headless', action='store_true', help='Enable Playwright headless validation')
        enh.add_argument('--headless-timeout', type=int, default=30000, help='Headless timeout (ms)')
        enh.add_argument('--headless-max-routes', type=int, default=25, help='Max routes to probe dynamically')
        enh.add_argument('--headless-crawl', dest='headless_crawl', action='store_true', default=True, help='Crawl same-origin links (default)')
        enh.add_argument('--no-headless-crawl', dest='headless_crawl', action='store_false', help='Disable headless crawl')

        sec = parser.add_argument_group('Security Analysis Options')
        sec.add_argument('--risk-threshold', type=int, default=0, help='Only output findings with risk score >= N (0-100)')
        sec.add_argument('--no-risk-assessment', action='store_true', help='Skip risk scoring and security analysis')
        sec.add_argument('--include-patterns', action='store_true', help='Output detected security patterns in detail')
        sec.add_argument('--sensitive-only', action='store_true', help='Only output workers with sensitive route patterns')

        out = parser.add_argument_group('Output Options')
        out.add_argument('--json', action='store_true', help='JSONL output with full security analysis')
        out.add_argument('--quiet', action='store_true', help='Suppress comments and progress messages')
        out.add_argument('--verbose', action='store_true', help='Detailed security analysis output')
        out.add_argument('-o', '--output', help='Write results to file')
        
        net = parser.add_argument_group('Network Options')
        net.add_argument('--ua', '--user-agent', dest='user_agent', help='Custom User-Agent string')
        net.add_argument('--header', action='append', dest='headers', help='Extra HTTP header (repeatable)')
        net.add_argument('--cookie', help='Cookie header value')
        net.add_argument('--proxy', help='HTTP proxy URL (currently unused)')

        return parser

    def parse_arguments(self) -> argparse.Namespace:
        return self.parser.parse_args()

    def show_help(self):
        print(BANNER)
        print("Service Worker Security Analyzer - Advanced recon tool")
        print("\nAdvanced recon tool for Service Worker security assessment")
        self.parser.print_help()
        print("\n" + "=" * 60)
        print("Examples:")
        print("=" * 60)
        print("  # Single target scan")
        print("  swmap https://app.example.com")
        print("")
        print("  # Batch scan with JSON output")
        print("  swmap -i targets.txt --json -o results.jsonl")
        print("")
        print("  # High-risk targets only")
        print("  swmap -i urls.txt --risk-threshold 80 --quiet")
        print("")
        print("  # Deep AST recursion + headless validation")
        print("  swmap https://target.com --ast-depth 2 --headless --cookie \"session=abc123\"")
        print("")
        print("Output Fields (TSV):")
        print("  origin, sw_url, effective_scope, http_status, has_swa, workbox, cache_names,")
        print("  routes_seen, risk_level, security_flags, risk_score")
        print("")

    def setup_logging(self, args: argparse.Namespace):
        log_level = 'DEBUG' if args.verbose else 'INFO'
        if args.quiet:
            log_level = 'WARNING'
        setup_logging(level=log_level, enable_console=not args.quiet)

    def create_scan_config(self, args: argparse.Namespace) -> ScanConfig:
        headers = {}
        if args.headers:
            for header in args.headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()

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
            output_format='json' if args.json else 'tsv',
            quiet_mode=args.quiet,
            verbose=args.verbose,
        )

    def load_targets(self, args: argparse.Namespace) -> List[ScanTarget]:
        targets: List[ScanTarget] = []

        if args.target:
            try:
                targets.append(ScanTarget(args.target))
                logger.info(f"Added target: {args.target}")
            except Exception as e:
                logger.error(f"Invalid target URL: {e}")
                sys.exit(EXIT_CODES['CONFIG_ERROR'])

        if args.input_file:
            try:
                with open(args.input_file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        url = line.strip()
                        if url and not url.startswith('#'):
                            try:
                                targets.append(ScanTarget(url))
                            except Exception as e:
                                logger.warning(f"Invalid target on line {line_num}: {url} - {e}")
                logger.info(f"Loaded {len(targets)} targets from {args.input_file}")
            except Exception as e:
                logger.error(f"Failed to read input file: {e}")
                sys.exit(EXIT_CODES['CONFIG_ERROR'])

        if not targets:
            logger.error("No valid targets provided")
            self.show_help()
            sys.exit(EXIT_CODES['USAGE_ERROR'])

        return targets

    def create_scanner(self, config: ScanConfig, args: argparse.Namespace) -> SWScanner:
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
            ast_same_origin_only=True,
            ast_request_timeout=max(5, min(30, config.timeout)),
            enable_headless_analysis=args.headless,
            headless_timeout_ms=args.headless_timeout,
            headless_max_routes=args.headless_max_routes,
            headless_crawl=args.headless_crawl,
            headless_crawl_limit=50,
            headless_backoff_attempts=4,
            headless_backoff_ms=500,
        )

    def setup_output(self, args: argparse.Namespace):
        if args.output:
            try:
                output_dir = os.path.dirname(args.output)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write('')
                logger.info(f"Output will be written to: {args.output}")
            except Exception as e:
                logger.error(f"Cannot write to output file: {e}")
                sys.exit(EXIT_CODES['CONFIG_ERROR'])

    def write_output(self, results: List[SWResult], args: argparse.Namespace):
        output_file = None
        if args.output:
            try:
                output_file = open(args.output, 'w', encoding='utf-8')
            except Exception as e:
                logger.error(f"Failed to open output file: {e}")
                output_file = None

        try:
            out_stream = output_file or sys.stdout

            if not args.json and not args.quiet:
                header = SWResult.get_tsv_header()
                out_stream.write(header + '\n')

            for result in results:
                if args.json:
                    output_line = result.to_json(include_details=args.include_patterns)
                else:
                    output_line = result.to_tsv()
                out_stream.write(output_line + '\n')

            out_stream.flush()
        except Exception as e:
            logger.error(f"Output error: {e}")
        finally:
            if output_file:
                output_file.close()

    def print_summary(self, results: List[SWResult], scanner: SWScanner):
        if not results:
            return

        summary = ScanSummary(
            scan_id=f"scan_{int(scanner.stats.get('start_time', 0))}",
            start_time=scanner.stats.get('start_time', 0),
            end_time=scanner.stats.get('end_time', 0),
            config={},  
            total_targets=scanner.stats.get('targets_processed', 0),
            targets_processed=scanner.stats.get('targets_processed', 0),
            targets_with_sw=scanner.stats.get('sw_found', 0),
            targets_with_errors=scanner.stats.get('errors', 0),
            results=results
        )

        if not self.config or not self.config.quiet_mode:
            summary.print_summary()

    def run_scan(self, args: argparse.Namespace) -> int:
        try:
            if args.verbose and not args.quiet:
                print(BANNER)
                print("Service Worker Security Analyzer - Starting Security Scan")
                print("=" * 60)
                
            self.setup_logging(args)
            self.config = self.create_scan_config(args)
            self.config.validate()
            targets = self.load_targets(args)
            self.setup_output(args)
            
            scanner = self.create_scanner(self.config, args)
            self.scanner = scanner

            logger.info(f"Starting scan of {len(targets)} targets")
            results: List[SWResult] = []
            for result in scanner.scan_targets(targets, probe=not args.no_probe):
                if result and (args.risk_threshold <= 0 or result.risk_score >= args.risk_threshold):
                    if not args.sensitive_only or result.routes_seen:
                        results.append(result)

            self.write_output(results, args)
            self.print_summary(results, scanner)

            return EXIT_CODES['NETWORK_ERROR'] if scanner.stats.get('errors', 0) > 0 else EXIT_CODES['SUCCESS']
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
            return EXIT_CODES['UNKNOWN_ERROR']
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            if args.verbose:
                logger.exception("Detailed error:")
            return EXIT_CODES['UNKNOWN_ERROR']
        finally:
            if self.scanner:
                self.scanner.close()

def main():
    cli = SWMapCLI()
    args = cli.parse_arguments()
    if args.help:
        cli.show_help()
        sys.exit(EXIT_CODES['SUCCESS'])
    if args.version:
        print(BANNER)
        print(f"SWMap - Service Worker Security Analyzer v{get_version()}")
        print("Advanced reconnaissance tool for Service Worker security assessment")
        print("https://github.com/bl4ck0w1/swmap.git")
        sys.exit(EXIT_CODES['SUCCESS'])
    sys.exit(cli.run_scan(args))


if __name__ == '__main__':
    main()
