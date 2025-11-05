#!/usr/bin/env python3
from __future__ import annotations
import os
import sys
import argparse
import shutil
import re
import json
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from src.models.target import ScanTarget, ScanConfig
from src.models.result import SWResult, ScanSummary
from src.utils.logger import setup_logging, get_logger
from config.constants import DEFAULT_CONFIG, SCAN_LIMITS, EXIT_CODES, get_version

try:
    from src.core.fetcher import AdvancedFetcher
    from src.core.parser import SWParser
    _HAVE_RE_FETCH = True
except Exception:
    _HAVE_RE_FETCH = False

logger = get_logger("cli")

THEMES = {
    "safe": {
        "accent": "bright_cyan",
        "desc": "grey70",
        "section": "bright_yellow",
        "paren": "white",
        "banner_start": "bright_cyan",
        "banner_end": "cyan",
    },
    "brand": {
        "accent": "#d16868",
        "desc": "#6e6555",
        "section": "#59483d",
        "paren": "white",
        "banner_start": "#d16868",
        "banner_end": "#904e4e",
    },
}
HELP_THEME = os.getenv("SWMAP_HELP_THEME", "safe")
if HELP_THEME not in THEMES:
    HELP_THEME = "safe"

WAF_FRIENDLY_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}
WAF_FRIENDLY_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_RICH_AVAILABLE = False
try:
    from rich.console import Console
    from rich.text import Text
    from rich.table import Table
    from rich.panel import Panel
    _RICH_AVAILABLE = True
except Exception:
    _RICH_AVAILABLE = False

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_REGISTER_SNIPPET_RE = re.compile(
    r"(navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*[^\)]+\))",
    re.IGNORECASE | re.DOTALL,
)

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
TITLE = "Service Worker Security Mapper - Advanced SW recon tool"

def _normalize_target_url(u: str) -> str:
    if not u:
        return u
    if not _SCHEME_RE.match(u):
        return f"https://{u}"
    return u

def _host(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return "unknown"

def _safe_slug(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", s.strip())
    return s[:120] or "item"

def _redact(text: str) -> str:
    """Very conservative redaction for evidence artifacts."""
    if not text:
        return text

    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[redacted_email]", text)
    text = re.sub(r'(?i)(authorization\s*:\s*["\']?Bearer\s+[A-Za-z0-9._-]+["\']?)', r"\1[redacted_token]", text,)
    text = re.sub(r'(?i)(token|auth|secret|apikey|api_key)["\']?\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{16,}["\']', r'\1:"[redacted]"', text, )
    text = re.sub(r"([A-Fa-f0-9]{24,})", "[redacted_hex]", text)
    text = re.sub(r"([A-Za-z0-9+/=_-]{32,})", "[redacted_blob]", text)
    return text

def _is_akamai_sw(sw_url: str, resp_headers: dict) -> bool:
    sw_url = (sw_url or "").lower()
    if sw_url.endswith("/akam-sw.js") or sw_url.endswith("akam-sw.js"):
        return True
    h = {k.lower(): v for k, v in (resp_headers or {}).items()}
    if "x-akam-sw-version" in h:
        return True
    return False

class WideFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog):
        width = shutil.get_terminal_size((100, 20)).columns
        super().__init__(prog, max_help_position=32, width=max(90, min(width, 140)))

def _opt_metavar(action: argparse.Action) -> str:
    if action.option_strings:
        left = ", ".join(action.option_strings)
        if action.metavar:
            left += f" {action.metavar}"
        return left
    return action.metavar or action.dest

def _style_parens_rich(text: "Text", color: str) -> None:
    s = text.plain
    for m in re.finditer(r"\([^)]*\)", s):
        text.stylize(color, m.start(), m.end())

def _rich_print_help_aligned(parser: argparse.ArgumentParser, banner: str, title: str) -> None:
    theme = THEMES[HELP_THEME]
    console = Console()
    width = console.size.width

    t_banner = Text(banner)
    try:
        t_banner.apply_gradient(theme["banner_start"], theme["banner_end"])
    except Exception:
        t_banner.stylize(theme["banner_start"])
    console.print(t_banner)
    console.print(Text(title, style=f"bold {theme['accent']}"))

    all_lefts = []
    for g in parser._action_groups:
        for a in g._group_actions:
            if isinstance(a, argparse._HelpAction):
                continue
            all_lefts.append(_opt_metavar(a))
    left_w = max((len(s) for s in all_lefts), default=24)
    left_w = max(22, min(left_w, 36))

    for group in parser._action_groups:
        actions = [a for a in group._group_actions if not isinstance(a, argparse._HelpAction)]
        if not actions:
            continue
        console.print(f"[{theme['section']}]{group.title}[/]")
        from rich.table import Table

        table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
        table.add_column("opt", style=f"bold {theme['accent']}", no_wrap=True, min_width=left_w, max_width=left_w, )
        rem = max(20, width - left_w - 4)
        table.add_column("desc", style=theme["desc"], overflow="fold", min_width=rem, max_width=rem)
        for a in actions:
            left = _opt_metavar(a).ljust(left_w)
            desc = a.help or ""
            t_desc = Text(desc, style=theme["desc"])
            _style_parens_rich(t_desc, theme["paren"])
            table.add_row(left, t_desc)
        console.print(table)
        console.print()
    console.print("For more information: [link=https://github.com/bl4ck0w1/swmap]https://github.com/bl4ck0w1/swmap[/]")

class SWMapCLI:
    def __init__(self):
        self.parser = self._create_parser()
        self.config: ScanConfig | None = None
        self.scanner = None
        self._refetcher: Optional["AdvancedFetcher"] = None
        self._parser: Optional["SWParser"] = None

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description=TITLE, epilog="For more information: https://github.com/bl4ck0w1/swmap", formatter_class=WideFormatter, add_help=False, usage=argparse.SUPPRESS,)
        info = parser.add_argument_group("Information Options")
        info.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
        info.add_argument("-V", "--version", action="store_true", help="Show version information and exit")
        inp = parser.add_argument_group("Input Options")
        inp.add_argument("target", nargs="?", help="Single URL to scan (e.g., https://target.com)")
        inp.add_argument("-i", "--input", dest="input_file", help="Read targets from file (one URL per line)")
        
        scan = parser.add_argument_group("Scan Options")
        scan.add_argument("-P", "--parallel", type=int, default=DEFAULT_CONFIG["parallel_workers"], help=(f'Concurrent scans (default: {DEFAULT_CONFIG["parallel_workers"]}, 'f'max: {SCAN_LIMITS["max_concurrent_connections"]})'), )
        scan.add_argument("-t", "--timeout", type=int, default=DEFAULT_CONFIG["request_timeout"], help=f'Request timeout in seconds (default: {DEFAULT_CONFIG["request_timeout"]})',)
        scan.add_argument("--max-sw-bytes", type=int, default=DEFAULT_CONFIG["max_sw_bytes"], help=f'Maximum SW script size in bytes (default: {DEFAULT_CONFIG["max_sw_bytes"]})',)
        scan.add_argument("--max-routes", type=int, default=DEFAULT_CONFIG["max_routes_per_sw"], help=f'Maximum routes to extract per SW (default: {DEFAULT_CONFIG["max_routes_per_sw"]})',)
        scan.add_argument("--deep", action="store_true", help="Legacy deep static parse hint (sets AST recursion to 3 if not overridden)", )
        scan.add_argument("--delay-ms", type=int, default=0, help="Delay between headless navigations (ms) to avoid rate-limits (default: 0)",)
        scan.add_argument("--no-probe", action="store_true", help="Skip common SW filename probing")
        
        enh = parser.add_argument_group("Enhanced Analysis (runtime + AST)")
        enh.add_argument("--headless", dest="headless", action="store_true", default=False, help="Enable headless browser validation (default: off)",)
        enh.add_argument("--no-headless", dest="headless", action="store_false", help="Disable headless browser validation")
        enh.add_argument("--ast", dest="ast", action="store_true", default=True, help="Enable AST analysis (default)")
        enh.add_argument("--no-ast", dest="ast", action="store_false", help="Disable AST analysis")
        enh.add_argument("--ast-depth", type=int, default=None, help="Recurse importScripts/ESM to this depth (default: 2; or 3 if --deep and not overridden)",)
        enh.add_argument("--headless-timeout", type=int, default=30000, help="Headless timeout (ms)")
        enh.add_argument("--headless-max-routes", type=int, default=25, help="Max routes to probe dynamically")
        enh.add_argument("--headless-crawl", dest="headless_crawl", action="store_true", default=True, help="Crawl same-origin links (default)", )
        enh.add_argument("--no-headless-crawl", dest="headless_crawl", action="store_false", help="Disable headless crawl")
        enh.add_argument("--route-seed", action="append", default=[], help="Seed route (repeatable)")
        enh.add_argument("--login-script", help="Path to a JS file to run before crawl (auto-login etc.)")
        enh.add_argument("--login-wait", dest="login_wait", help="CSS selector to wait for after login")
        enh.add_argument("--prove-interception", action="store_true", default=True, help="Prove response interception via Service Worker",)
        enh.add_argument("--no-prove-interception", dest="prove_interception", action="store_false", help="Disable interception proof", )
        enh.add_argument("--prove-precache", action="store_true", default=True, help="Prove precache via CacheStorage audit", )
        enh.add_argument("--no-prove-precache", dest="prove_precache", action="store_false", help="Disable precache proof",)
        enh.add_argument("--prove-swr", action="store_true", default=True, help="Try to detect stale-while-revalidate behavior", )
        enh.add_argument("--no-prove-swr", dest="prove_swr", action="store_false", help="Disable SWR proof")
        enh.add_argument("--offline-replay", action="store_true", help="After crawl, go offline and replay seeds to prove offline render",)
        enh.add_argument("--offline-wait", type=int, default=1500, help="Wait after going offline before replay (ms, default: 1500)", )
        enh.add_argument("--logout-url", help="URL to visit to logout before offline replay")
        enh.add_argument("--logout-script", help="JS to execute to logout before offline replay")

        sec = parser.add_argument_group("Security Analysis Options")
        sec.add_argument("--risk-threshold", type=int, default=0, help="Only output findings with risk score >= N (0-100)", )
        sec.add_argument("--no-risk-assessment", action="store_true", help="Skip risk scoring and security analysis")
        sec.add_argument("--include-patterns", action="store_true", help="Output detected security patterns in detail")
        sec.add_argument("--sensitive-only", action="store_true", help="Only output workers with sensitive route patterns")

        out = parser.add_argument_group("Output Options")
        out.add_argument("--json", action="store_true", help="Emit stable JSON v1 (schema baked here; ignores custom SWResult.to_json)",)
        out.add_argument("--sarif", help="Write SARIF 2.1.0 file with findings")
        out.add_argument("--nuclei-out", help="Directory to write Nuclei verifier templates (one per SW)")
        out.add_argument("--evidence-dir", help="Directory to dump evidence bundle per target")
        out.add_argument("--explain", action="store_true", help="Print a decision chain for each target (discover/probe/runtime)",)
        out.add_argument("--quiet", action="store_true", help="Suppress comments and progress messages")
        out.add_argument("--verbose", action="store_true", help="Detailed analysis output")
        out.add_argument("-o", "--output", help="Write results table/JSONL to file")

        net = parser.add_argument_group("Network Options")
        net.add_argument("--ua", "--user-agent", dest="user_agent", help="Custom User-Agent string")
        net.add_argument("--header", action="append", dest="headers", help='Extra HTTP header (repeatable, e.g., "K: V")')
        net.add_argument("--cookie", help="Cookie header value")
        net.add_argument("--proxy", help="HTTP/SOCKS proxy URL (applies to HTTP fetches and headless)")
        net.add_argument("--cookies", help="Path to Netscape cookie file to import into headless context (auth-only SWs)",)
        net.add_argument("--profile", help="Load headers/cookies/proxy/login/route seeds from JSON profile (CLI args override profile)",)
        net.add_argument("--waf-friendly", action="store_true", help="Apply a browser-like header set to reduce WAF/tooling blocks",)

        return parser

    def parse_arguments(self) -> argparse.Namespace:
        return self.parser.parse_args()

    def show_help(self) -> None:
        if _RICH_AVAILABLE:
            _rich_print_help_aligned(self.parser, BANNER, TITLE)
        else:
            print(BANNER)
            print(TITLE + "\n")
            print(self.parser.format_help())
            print("For more information: https://github.com/bl4ck0w1/swmap")

    def _load_profile_file(self, path: str) -> Dict[str, Any]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("profile JSON must be an object")
            return data
        except Exception as e:
            logger.error(f"Failed to load profile {path}: {e}")
            return {}

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

        ast_depth = 3 if (args.deep and args.ast_depth is None) else (args.ast_depth if args.ast_depth is not None else 2)

        scanner = SWScanner(
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
            headless_offline_replay=args.offline_replay,
            headless_offline_wait_ms=args.offline_wait,
            headless_logout_url=args.logout_url,
            headless_logout_script=args.logout_script,
            headless_nav_delay_ms=getattr(args, "delay_ms", 0),
            proxy_url=getattr(args, "proxy", None),
            headless_cookies_netscape_file=getattr(args, "cookies", None),
        )

        if getattr(args, "cookies", None):
            try:
                ha = getattr(scanner, "enhanced_analyzer", None)
                if ha is not None:
                    hm = getattr(ha, "headless_manager", None)
                    if hm is not None and getattr(hm, "cfg", None) is not None:
                        hm.cfg.cookies_netscape_file = args.cookies
                        logger.debug(f"Headless will import cookies from: {args.cookies}")
            except Exception as e:
                logger.debug(f"Failed to inject cookies file into headless config: {e}")

        return scanner

    def _setup_output(self, args: argparse.Namespace) -> None:
        if args.output:
            try:
                d = os.path.dirname(args.output)
                if d and not os.path.exists(d):
                    os.makedirs(d, exist_ok=True)
                with open(args.output, "w", encoding="utf-8"):
                    pass
                logger.debug(f"Output will be written to: {args.output}")
            except Exception as e:
                logger.error(f"Cannot write to output file: {e}")
                sys.exit(EXIT_CODES["CONFIG_ERROR"])
        if args.evidence_dir:
            try:
                Path(args.evidence_dir).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.error(f"Cannot create evidence dir: {e}")
                sys.exit(EXIT_CODES["CONFIG_ERROR"])
        if args.nuclei_out:
            try:
                Path(args.nuclei_out).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.error(f"Cannot create nuclei-out dir: {e}")
                sys.exit(EXIT_CODES["CONFIG_ERROR"])

    def _load_targets(self, args: argparse.Namespace) -> List[ScanTarget]:
        targets: List[ScanTarget] = []

        if args.target:
            try:
                norm = _normalize_target_url(args.target)
                targets.append(ScanTarget(norm))
                logger.debug(f"Added target: {norm}")
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
                                targets.append(ScanTarget(_normalize_target_url(url)))
                            except Exception as e:
                                logger.warning(f"Invalid target on line {line_num}: {url} - {e}")
                logger.debug(f"Loaded {len(targets)} targets from {args.input_file}")
            except Exception as e:
                logger.error(f"Failed to read input file: {e}")
                sys.exit(EXIT_CODES["CONFIG_ERROR"])

        if not targets:
            logger.error("No valid targets provided")
            self.show_help()
            sys.exit(EXIT_CODES["USAGE_ERROR"])

        return targets

    def _json_v1_of(self, r: SWResult, include_details: bool) -> Dict[str, Any]:
        def g(obj, k, default=None):
            if hasattr(obj, k):
                return getattr(obj, k, default)
            if isinstance(obj, dict):
                return obj.get(k, default)
            return default

        dyn = (g(r, "enhanced_analysis", {}) or {})
        head = dyn.get("headless_analysis") or {}
        labels = head.get("labels") or []
        cache_audit = head.get("cache_audit") or {}
        responses = head.get("responses") or []

        j = {
            "schema": "swmap.v1",
            "schema_version": "1.0.0",
            "origin": g(r, "origin", ""),
            "sw_url": g(r, "sw_url", ""),
            "effective_scope": g(r, "effective_scope", ""),
            "http_status": g(r, "http_status", 0),
            "response_headers": g(r, "response_headers", {}) or {},
            "has_swa": g(r, "has_swa", False),
            "workbox": g(r, "workbox", False),
            "risk_score": int(g(r, "risk_score", 0) or 0),
            "risk_level": "-",
            "security_flags": g(r, "security_flags", []) or [],
            "workbox_modules": g(r, "workbox_modules", []) or [],
            "routes_seen": g(r, "routes_seen", []) or [],
            "cache_names": g(r, "cache_names", []) or [],
            "discovery_path": g(r, "discovery_path", "") or "",
            "block_reason": g(r, "block_reason", "") or "",
            "labels": labels,
            "scan_timestamp": g(r, "scan_timestamp", 0),
        }

        sw_url = j.get("sw_url", "")
        resp_headers = j.get("response_headers", {})
        if _is_akamai_sw(sw_url, resp_headers):
            if j.get("labels") is None:
                j["labels"] = []
            if "AKAMAI_SW" not in j["labels"]:
                j["labels"].append("AKAMAI_SW")

        if include_details:
            j["detected_patterns"] = g(r, "detected_patterns", {}) or {}
            j["security_findings"] = g(r, "security_findings", {}) or {}
            j["headless"] = {
                "cache_audit": cache_audit,
                "responses": responses[:250],
            }
            j["rationale"] = g(r, "rationale", []) or []

            if _is_akamai_sw(sw_url, resp_headers):
                sec = j.get("security_findings") or {}
                notes = sec.get("notes") or []
                notes.append("Detected known CDN/infrastructure SW (Akamai 3PM/SPOF); some patterns may be expected.")
                sec["notes"] = notes
                sugg = sec.get("suggested_probes") or []
                if "/akam-sw-policy.json" not in sugg:
                    sugg.append("/akam-sw-policy.json")
                sec["suggested_probes"] = sugg
                j["security_findings"] = sec

        return j

    def _build_explain(self, r: SWResult) -> str:
        parts = []
        parts.append(f"HTML fetched {getattr(r, 'http_status', 0) or 'n/a'}")
        disc = getattr(r, "discovery_path", "") or ""
        if disc:
            parts.append(f"discovery={disc}")
        swu = getattr(r, "sw_url", "") or ""
        if swu:
            parts.append(f"SW={swu}")
        else:
            br = getattr(r, "block_reason", "") or ""
            if br:
                parts.append(f"blocked={br}")
        routes = getattr(r, "routes_seen", []) or []
        if routes:
            parts.append(f"routes={min(len(routes), 50)}")
        dyn = getattr(r, "enhanced_analysis", {}) or {}
        head_labels = (dyn.get("headless_analysis") or {}).get("labels") or []
        json_labels = getattr(r, "labels", []) or []
        all_labels = sorted(set(head_labels + json_labels))
        if all_labels:
            parts.append("labels=" + ",".join(all_labels))
        score = int(getattr(r, "risk_score", 0) or 0)
        parts.append(f"score={score}")
        return " → ".join(parts)

    def _ensure_refetchers(
        self,
        ua: Optional[str],
        headers: Dict[str, str],
        cookies: Optional[str],
        timeout: int,
        proxy: Optional[str],
    ):
        if not _HAVE_RE_FETCH:
            return
        if self._refetcher is None:
            try:
                self._refetcher = AdvancedFetcher(timeout=timeout, user_agent=ua, proxy=proxy)
            except TypeError:
                self._refetcher = AdvancedFetcher(timeout=timeout, user_agent=ua)
            if headers:
                self._refetcher.session.headers.update(headers)
            if cookies:
                self._refetcher.session.headers["Cookie"] = cookies
        if self._parser is None:
            try:
                self._parser = SWParser()
            except Exception:
                self._parser = None

    def _dump_evidence(self, r: SWResult, args: argparse.Namespace) -> None:
        if not args.evidence_dir:
            return
        base = Path(args.evidence_dir)
        host = _safe_slug(_host(getattr(r, "origin", "")))
        swu = getattr(r, "sw_url", "") or "-"
        leaf = _safe_slug((urlparse(swu).path or "/").replace("/", "_")) if swu != "-" else "no_sw"
        stamp = time.strftime("%Y%m%d_%H%M%S")
        d = base / host / f"{leaf}_{stamp}"
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.debug(f"evidence mkdir failed: {e}")
            return

        try:
            with open(d / "summary.json", "w", encoding="utf-8") as f:
                json.dump(self._json_v1_of(r, include_details=True), f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        try:
            dyn = getattr(r, "enhanced_analysis", {}) or {}
            head = dyn.get("headless_analysis") or {}
            if head:
                with open(d / "cache_audit.json", "w", encoding="utf-8") as f:
                    json.dump(head.get("cache_audit") or {}, f, ensure_ascii=False, indent=2)
                har = {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "swmap", "version": str(get_version())},
                        "entries": [
                            {
                                "request": {"url": e.get("url"), "method": "GET"},
                                "response": {"status": e.get("status"), "statusText": "", "headers": []},
                                "timings": {"wait": e.get("ttfb_ms")},
                                "cache": {},
                                "_fromServiceWorker": bool(e.get("from_service_worker")),

                            }
                            for e in (head.get("responses") or [])[:1000]
                        ],
                    }
                }
                with open(d / "responses.har.json", "w", encoding="utf-8") as f:
                    json.dump(har, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        self._ensure_refetchers(
            args.user_agent,
            self.config.headers,
            self.config.cookies,
            self.config.timeout,
            getattr(args, "proxy", None),
        )

        try:
            if _HAVE_RE_FETCH and getattr(r, "sw_url", ""):
                ok, sc, hdrs = self._refetcher.probe_exists(getattr(r, "sw_url", ""))
                with open(d / "sw_headers.json", "w", encoding="utf-8") as f:
                    json.dump({"status": sc, "headers": hdrs or {}, "exists": ok}, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        try:
            if _HAVE_RE_FETCH and getattr(r, "origin", ""):
                html, hdrs, sc = self._refetcher.fetch_url(getattr(r, "origin", ""), max_bytes=512 * 1024)
                if html:
                    with open(d / "origin_redacted.html.txt", "w", encoding="utf-8") as f:
                        f.write(_redact(html))
                    snips = _REGISTER_SNIPPET_RE.findall(html or "") or []
                    if snips:
                        with open(d / "register_snippet.js", "w", encoding="utf-8") as f:
                            f.write("\n\n/* --- */\n\n".join(_redact(s) for s in snips[:10]))
        except Exception:
            pass

    def _maybe_enhance_result(self, r: SWResult, args: argparse.Namespace) -> None:
        if getattr(r, "enhanced_analysis", None):
            return
        if not args.headless:
            return
        sw_url = getattr(r, "sw_url", "") or ""
        origin = getattr(r, "origin", "") or ""
        if not sw_url or not origin:
            return
        if not _HAVE_RE_FETCH:
            return

        self._ensure_refetchers(
            args.user_agent,
            self.config.headers,
            self.config.cookies,
            self.config.timeout,
            getattr(args, "proxy", None),
        )
        try:
            sw_code, hdrs, sc = self._refetcher.fetch_url(sw_url, max_bytes=args.max_sw_bytes)
        except Exception as e:
            logger.debug(f"CLI-side enhanced analysis skipped: failed to fetch SW: {e}")
            return

        from src.core.enhanced_analyzer import EnhancedAnalyzer, EnhancedAnalysisConfig
        import logging as _logging
 
        _logging.getLogger("enhanced_analyzer").setLevel(_logging.WARNING)
        _logging.getLogger("ast_analyzer").setLevel(_logging.WARNING)
        _logging.getLogger("headless_analyzer").setLevel(_logging.WARNING)

        ast_depth = 3 if (args.deep and args.ast_depth is None) else (args.ast_depth if args.ast_depth is not None else 2)

        enh_cfg = EnhancedAnalysisConfig(
            enable_ast=bool(args.ast),
            ast_max_depth=ast_depth,
            ast_same_origin_only=True,
            ast_request_timeout=max(5, min(30, self.config.timeout)),
            enable_headless=True,
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
            headless_extra_headers=self.config.headers or {},
            headless_offline_replay=args.offline_replay,
            headless_offline_wait_ms=args.offline_wait,
            headless_logout_url=args.logout_url,
            headless_logout_script=args.logout_script,
            headless_nav_delay_ms=getattr(args, "delay_ms", 0),
            proxy_url=getattr(args, "proxy", None),
        )
        enhancer = EnhancedAnalyzer(config=enh_cfg)
        try:
            enhanced = enhancer.analyze_service_worker(
                javascript_code=sw_code or "",
                target_url=origin,
                static_findings=self._json_v1_of(r, include_details=False),
                base_url_for_ast=sw_url,
                effective_scope=getattr(r, "effective_scope", "") or "",
                seed_routes=getattr(r, "routes_seen", []) or [],
                request_headers=self.config.headers,
                cookies=self.config.cookies,
                user_agent=self.config.user_agent,
            )
            try:
                r.enhanced_analysis = enhanced
            except Exception:
                if hasattr(r, "__dict__"):
                    r.__dict__["enhanced_analysis"] = enhanced
        except Exception as e:
            logger.debug(f"CLI-side enhanced analysis failed: {e}")

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
            if args.json:
                for r in results:
                    has_dyn = bool(getattr(r, "enhanced_analysis", None))
                    include_details = bool(args.include_patterns or has_dyn)
                    out_stream.write(
                        json.dumps(
                            self._json_v1_of(r, include_details=include_details),
                            ensure_ascii=False,
                            indent=2,
                        )
                    )
                    out_stream.write("\n")
            else:
                if not args.quiet:
                    out_stream.write(SWResult.get_tsv_header() + "\n")
                for r in results:
                    out_stream.write(r.to_tsv() + "\n")
            out_stream.flush()
        finally:
            if output_file:
                output_file.close()

    def _emit_sarif(self, results: List[SWResult], path: str) -> None:
        try:
            runs = [
                {
                    "tool": {
                        "driver": {
                            "name": "SWMap",
                            "version": str(get_version()),
                            "informationUri": "https://github.com/bl4ck0w1/swmap",
                            "rules": [
                                {
                                    "id": "SWMAP.SWDetected",
                                    "name": "Service Worker Detected",
                                    "shortDescription": {"text": "A Service Worker was discovered"},
                                    "defaultConfiguration": {"level": "note"},
                                },
                                {
                                    "id": "SWMAP.SensitiveRoutes",
                                    "name": "Sensitive Route Patterns",
                                    "shortDescription": {
                                        "text": "Service Worker routes match sensitive paths"
                                    },
                                    "defaultConfiguration": {"level": "note"},
                                },
                            ],
                        }
                    },
                    "results": [],
                }
            ]

            for r in results:
                j = self._json_v1_of(r, include_details=True)
                origin = j["origin"]
                swu = j["sw_url"]
                loc = {"physicalLocation": {"artifactLocation": {"uri": swu or origin}}}
                if swu:
                    runs[0]["results"].append(
                        {
                            "ruleId": "SWMAP.SWDetected",
                            "level": "note",
                            "message": {
                                "text": f"Service Worker: {swu} (scope={j.get('effective_scope','')})"
                            },
                            "locations": [loc],
                            "properties": {
                                "risk_score": j.get("risk_score", 0),
                                "labels": j.get("labels", []),
                            },
                        }
                    )
                sens = ((j.get("security_findings") or {}).get("sensitive_routes") or [])
                if sens:
                    runs[0]["results"].append(
                        {
                            "ruleId": "SWMAP.SensitiveRoutes",
                            "level": "note",
                            "message": {"text": f"Sensitive route patterns: {', '.join(sens[:6])}"},
                            "locations": [loc],
                            "properties": {"risk_score": j.get("risk_score", 0)},
                        }
                    )

            sarif = {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": runs,
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(sarif, f, ensure_ascii=False, indent=2)
            logger.debug(f"SARIF written: {path}")
        except Exception as e:
            logger.error(f"SARIF generation failed: {e}")

    def _emit_nuclei(self, results: List[SWResult], out_dir: str) -> None:
        try:
            base = Path(out_dir)
            base.mkdir(parents=True, exist_ok=True)
            for r in results:
                swu = getattr(r, "sw_url", "") or ""
                if not swu:
                    continue
                host = _safe_slug(_host(getattr(r, "origin", "")))
                name = base / f"swmap_{host}.yaml"
                tpl = {
                    "id": f"swmap-{host}",
                    "info": {
                        "name": f"Service Worker presence on {host}",
                        "author": ["swmap"],
                        "severity": "info",
                        "description": "Validates the discovered Service Worker endpoint responds as expected",
                        "tags": "service-worker,swmap",
                    },
                    "http": [
                        {
                            "method": "GET",
                            "path": [swu],
                            "matchers-condition": "and",
                            "matchers": [
                                {"type": "status", "status": [200, 304]},
                                {
                                    "type": "word",
                                    "words": [
                                        "self.addEventListener",
                                        "serviceWorker",
                                        "skipWaiting",
                                    ],
                                    "condition": "or",
                                },
                            ],
                        }
                    ],
                }
                with open(name, "w", encoding="utf-8") as f:
                    f.write("---\n")
                    f.write(json.dumps(tpl, ensure_ascii=False, indent=2))
                logger.debug(f"Nuclei template written: {name}")
        except Exception as e:
            logger.error(f"Nuclei template generation failed: {e}")

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
            profile: Dict[str, Any] = {}
            if getattr(args, "profile", None):
                profile = self._load_profile_file(args.profile)

            profile_headers = (profile.get("headers") or {}).copy()

            if not getattr(args, "cookies", None) and profile.get("cookies_file"):
                args.cookies = profile["cookies_file"]

            if not getattr(args, "proxy", None) and profile.get("proxy"):
                args.proxy = profile["proxy"]

            if not getattr(args, "login_script", None) and profile.get("login_script"):
                args.login_script = profile["login_script"]

            if (not getattr(args, "route_seed", None)) and profile.get("route_seeds"):
                args.route_seed = profile["route_seeds"]

            merged_headers: Dict[str, str] = {}
            merged_headers.update(profile_headers)

            if getattr(args, "waf_friendly", False):
                for k, v in WAF_FRIENDLY_HEADERS.items():
                    merged_headers.setdefault(k, v)
                if not getattr(args, "user_agent", None):
                    args.user_agent = WAF_FRIENDLY_UA

            if getattr(args, "headers", None):
                for header in args.headers:
                    if ":" in header:
                        k, v = header.split(":", 1)
                        merged_headers[k.strip()] = v.strip()

            if getattr(args, "user_agent", None):
                merged_headers["User-Agent"] = args.user_agent
            else:
                if "User-Agent" in profile_headers:
                    args.user_agent = profile_headers["User-Agent"]

            args.headers = [f"{k}: {v}" for k, v in merged_headers.items()]

            if (args.headless is False) and (
                args.prove_interception
                or args.prove_precache
                or args.prove_swr
                or args.offline_replay
                or args.login_script
                or args.login_wait
                or args.logout_url
                or args.logout_script
                or (args.route_seed and len(args.route_seed) > 0)
            ):
                logger.debug(
                    "Headless disabled but runtime proof flags are set; enable headless or remove runtime flags."
                )

            self.config = self._create_scan_config(args)
            self.config.validate()

            if args.verbose:
                lvl = "DEBUG"
            else:
                lvl = "WARNING"
            setup_logging(
                level=lvl,
                enable_console=not args.quiet,
            )

            import logging as _logging
            for noisy in ("enhanced_analyzer", "ast_analyzer", "headless_analyzer", "src.core.scanner"):
                _logging.getLogger(noisy).setLevel(_logging.WARNING)

            targets = self._load_targets(args)
            self._setup_output(args)

            scanner = self._create_scanner(self.config, args)
            self.scanner = scanner
            self._ensure_refetchers(
                args.user_agent,
                self.config.headers,
                self.config.cookies,
                self.config.timeout,
                getattr(args, "proxy", None),
            )

            logger.debug(f"Starting scan of {len(targets)} targets")

            results: List[SWResult] = []
            for result in scanner.scan_targets(targets, probe=not args.no_probe):
                if result and (args.risk_threshold <= 0 or result.risk_score >= args.risk_threshold):
                    if not args.sensitive_only or (getattr(result, "routes_seen", []) or []):
                        self._maybe_enhance_result(result, args)

                        results.append(result)

                        if args.explain:
                            br = getattr(result, "block_reason", "") or ""
                            is_net = br.startswith("html_fetch: NETWORK_ERROR")
                            if (not is_net) or (is_net and args.verbose):
                                chain = self._build_explain(result)
                                if _RICH_AVAILABLE and not args.quiet:
                                    c = Console()
                                    c.print(Panel(chain, title=_host(getattr(result, "origin", "")), expand=False))
                                else:
                                    print(f"[{_host(getattr(result, 'origin',''))}] {chain}")

                        if args.evidence_dir:
                            self._dump_evidence(result, args)

            self._write_output(results, args)
            if args.sarif:
                self._emit_sarif(results, args.sarif)
            if args.nuclei_out:
                self._emit_nuclei(results, args.nuclei_out)

            if not args.json:
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
        cli.show_help()
        sys.exit(EXIT_CODES["SUCCESS"])

    if args.version:
        if _RICH_AVAILABLE:
            theme = THEMES[HELP_THEME]
            c = Console()
            t_banner = Text(BANNER)
            try:
                t_banner.apply_gradient(theme["banner_start"], theme["banner_end"])
            except Exception:
                t_banner.stylize(theme["banner_start"])
            c.print(t_banner)
            c.print(
                f"[bold {theme['accent']}]SWMap[/] - Service Worker Security Analyzer v{get_version()}"
            )
            c.print("Advanced recon tool for Service Worker security assessment")
            c.print("[link=https://github.com/bl4ck0w1/swmap]https://github.com/bl4ck0w1/swmap[/]")
        else:
            print(BANNER)
            print(f"SWMap - Service Worker Security Analyzer v{get_version()}")
            print("Advanced recon tool for Service Worker security assessment")
            print("https://github.com/bl4ck0w1/swmap")
        sys.exit(EXIT_CODES["SUCCESS"])

    sys.exit(cli.run(args))


if __name__ == "__main__":
    main()
