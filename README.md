# SWMap

![swmap-logo](logo.png)

**SWMap** is an advanced **Service Worker security Analyzer**. It discovers, fetches, and analyzes Service Workers (SW) to surface **scope risks, caching issues, route exposure, Workbox usage, and code-risk patterns**—then summarizes findings with **standardized risk levels** and operator-ready output.

Built for **product security teams, red teams, and bug-bounty hunters** that demand rigor, speed, and explainability.

## Why SWMap?

Most PWA/SW security reviews stop at “is there a service worker?”. Real apps are complex. **SWMap** digs into **what** the worker does and **how** it can widen attack surface:

* **Security-first analysis** — Effective scope calc (incl. `Service-Worker-Allowed`), broadened scopes, mixed-origin pitfalls.
* **Caching scrutiny** — Sensitive route patterns (`/api`, `/auth`, `/user`, `/admin`), pre/runtime caching, cache-poisoning indicators.
* **Workbox awareness** — Detects Workbox and modules (precaching, routing, strategies).
* **Code-risk patterns** — `eval`/`Function` usage, string-timers, third-party imports, dynamic execution hints.
* **Operator-ready outputs** — TSV (grep-able) and JSONL (automation); quiet/verbose modes for ops or CI in the future.
* **Deep analysis** — **AST-based** parsing for precision (Node.js) and **Headless** validation for real behavior (Playwright).

## Features at a Glance

* **Scope Calculator**: Computes effective scope, validates `Service-Worker-Allowed`, rates scope breadth.
* **Security Flags & Levels**: Standardized flags (ex, `WIDENED_SCOPE`, `SENSITIVE_CACHING`, `EVAL_USAGE`) + `CRITICAL/HIGH/MEDIUM/LOW/INFO`.
* **Workbox Detection**: Finds Workbox usage and modules (`precaching`, `routing`, `strategies`).
* **Route Discovery**: Extracts candidate routes; optional **route coverage** (seeded routes and same-origin crawl).
* **Pattern Engine**: Extensible matcher with context capture; transparent outputs for triage.
* **AST Analysis (optional)**: Uses Babel to parse SWs (and bounded `importScripts`/module imports) for reduced false (±) positives.
* **Headless Validation (optional)**: Playwright run to observe lifecycle, **intercepted routes**, and **in-page cache audit**.
* **Stability Hardening**: Retries/backoff around SW install/activate; clear reasons (ex: “SW not active after 2 attempts”).
* **Performance Utilities**: Benchmarks, concurrency tests, memory profiling (optional).

---
**Flow:** Targets → Fetch/Probe → Analyze (scope, routes, caching, Workbox, patterns) → *(optional)* AST → *(optional)* Headless validate → Score & flag → Filter/Serialize → Summarize.

---

## 🚀 Quick Start

### Requirements

* **Python** ≥ 3.9
* **macOS / Linux / Windows** (PowerShell supported)
* **Optional (AST)**: **Node.js** ≥ 16 (for Babel parsing)
* **Optional (Headless)**: **Playwright**
  After installing the Python package, install a browser engine once:

  ```bash
  python -m pip install playwright
  python -m playwright install chromium
  # (or firefox / webkit)
  ```

### Install

**From source (recommended for now):**

* **Linux/macOS (bash):**

  ```bash
  bash scripts/install.sh
  ```
* **Windows (PowerShell):**

  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass 
  .\scripts\install.ps1 [-Dev] [-Full]
  ```

> After install, you’ll have the `swmap` command on PATH. You can always run in place with `python swmap.py`.

### Verify

```bash
swmap --help
# or
python swmap.py --help
```

### Update Security Patterns (optional)

```bash
python scripts/update_patterns.py --update
#validate
python scripts/update_patterns.py --validate
```

## 🧰 CLI --help Output Command
```bash
$ swmap --help

                                                            
  █████  █████ ███ █████ █████████████    ██████   ████████ 
 ███░░  ░░███ ░███░░███ ░░███░░███░░███  ░░░░░███ ░░███░░███
░░█████  ░███ ░███ ░███  ░███ ░███ ░███   ███████  ░███ ░███
 ░░░░███ ░░███████████   ░███ ░███ ░███  ███░░███  ░███ ░███
 ██████   ░░████░████    █████░███ █████░░████████ ░███████ 
░░░░░░     ░░░░ ░░░░    ░░░░░ ░░░ ░░░░░  ░░░░░░░░  ░███░░░  
                                                   ░███     
                                                   █████    
                                                  ░░░░░     

        SWMap — Service Worker Security Mapper
Advanced recon tool for Service Worker security assessment

Usage:
  swmap [OPTIONS] [target]
  swmap -i targets.txt [OPTIONS]

Positional:
  target                        Single URL to scan (e.g., https://target.com)

Information Options:
  -h, --help                    Show this help message and exit
  -v, --version                 Show version information and exit

Input Options:
  -i, --input FILE              Read targets from file (one URL per line)
      --no-probe                Skip common SW filename probing if no registration found

Scan Options:
  -P, --parallel INT            Concurrent scans (default: 6)
  -t, --timeout INT             Request timeout in seconds (default: 15)
      --max-sw-bytes INT        Maximum SW script size in KB (default: 512)
      --max-routes INT          Maximum routes to extract per SW (default: 50)
      --deep                    Recursively analyze importScripts() (depth: 2)

Security Analysis Options:
      --risk-threshold INT      Only output findings with risk score >= N (0–100)
      --no-risk-assessment      Skip risk scoring and security analysis
      --include-patterns        Include detected security patterns in JSON output
      --sensitive-only          Only output workers with sensitive route patterns

Output Options:
      --json                    Emit JSONL (one JSON record per line)
  -o, --output FILE             Write results to file (stdout if omitted)
      --quiet                   Suppress banners/progress; warnings+errors only
      --verbose                 Detailed logs and summary

Network Options:
      --ua, --user-agent STR    Custom User-Agent string
      --header "K: V"           Extra HTTP header (repeatable)
      --cookie STR              Cookie header value
      --proxy URL               HTTP proxy URL

Enhanced Analysis (optional extras):
      --ast                     Enable AST-based analysis (Node.js required)
      --no-ast                  Disable AST analysis
      --ast-depth INT           Max import recursion depth (default: 2)
      --ast-timeout SEC         AST worker timeout (default: 30)
      --node-path PATH          Path to Node.js executable (default: node)
      --headless                Enable headless browser validation (Playwright)
      --headless-timeout MS     Headless timeout in milliseconds (default: 30000)
      --browser NAME            Browser engine: chromium|firefox|webkit (default: chromium)

Route Coverage (when headless enabled):
      --route-seed PATH         Route to probe (repeatable), e.g., /api/me
      --crawl                   Crawl same-origin links to expand routes under test
      --crawl-max INT           Max pages to crawl (default: 30)
      --crawl-scope PATH        Limit crawl under path prefix (e.g., /app)

Notes:
  • Headless mode requires: pip install "playwright" and a one-time `python -m playwright install`.
  • AST mode requires Node.js in PATH (or set --node-path) and will analyze importScripts/module imports.
  • Use --json for machine-readable records suitable for pipelines/CI.

For more information: https://github.com/bl4ck0w1/swmap
```

## 🧾 Usage Examples

**Single target, TSV to stdout**

```bash
swmap https://app.example.com
```

**Batch scan, JSONL to file**

```bash
swmap -i targets.txt --json -o results.jsonl
```

**Deep static analysis, sensitive routes only, thresholded**

```bash
swmap -i urls.txt --deep --sensitive-only --risk-threshold 70
```

**Custom headers/cookies/proxy**

```bash
swmap https://target.com --header "X-Forwarded-For: 127.0.0.1" --cookie "session=abc123" --ua "SWMap/1.0 (+security@example.com)" --proxy http://127.0.0.1:8080
```

**AST + Headless validation (real behavior check)**

```bash
swmap https://pwa.example.com --ast --headless --browser chromium --route-seed /api/me --route-seed /settings --crawl --crawl-max 20 --crawl-scope /app
```

## ❓ Five Questions You Should Ask

1. **Could this Service Worker control more of my origin than intended?**
   Check for broadened scopes (ex: `Service-Worker-Allowed: /`) and verify the **effective scope** SWMap calculates.

2. **Is anything sensitive being precached or served from cache?**
   Look for `/api`, `/auth`, `/user`, `/admin` routes in findings and confirm via **headless cache audit** when possible.

3. **Which strategies is the worker actually using—and are they safe here?**
   Identify `cacheFirst`, `networkFirst`, `staleWhileRevalidate`, or races; match strategy to data sensitivity.

4. **Do static indicators match real behavior?**
   Use **headless validation** to confirm route interception and network flows before filing or remediating.

5. **What would make this finding actionable in CI or a bug report?**
   Export **JSONL**, include flags, scope math, and (if used) headless witnesses; set `--risk-threshold` to enforce policy.


## 🛠️ Troubleshooting
- If you encounter any issues, please [open an issue](https://github.com/bl4ck0w1/swmap/issues) on GitHub.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the APACHE 2.O License - see the [LICENSE](LICENSE) file for details.

## Author

### Security Researcher 😎
- [LinkedIn](www.linkedin.com/in/elie-uwimana)

## Compliance & Ethics

⚠️ **Authorized Use Only** - DeepFuzz is designed for:
- Penetration testing with explicit written permission
- Bug bounty programs within platform guidelines  
- Government cybersecurity operations
- Academic research in controlled environments
