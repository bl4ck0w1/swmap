# SWMap

![swmap-logo](logo.png)

**SWMap** is an advanced **Service Worker security analyzer** for modern web apps. It discovers, fetches, and analyzes Service Workers to surface scope risks, caching issues, route exposure, Workbox/Flutter usage, and dangerous code patterns and can prove behavior with a headless browser. Results are summarized with standardized risk levels and operator-ready output.

Built for bug bounty hunters, red teams, and product security engineers who demand rigor, speed, and explainability.

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
**Flow:** Targets → Fetch/Probe → Static(scope, routes, patterns) → *(optional)* AST → *(optional)* Headless validate → Score & flag → Filter/Serialize → Summarize.

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

Service Worker Security Mapper - Advanced SW reconn tool

Information Options:
  -h, --help            Show this help message and exit
  -V, --version         Show version information and exit

Input Options:
  target                Single URL to scan (e.g: https://target.com)
  -i INPUT_FILE, --input INPUT_FILE
                        Read targets from file (one URL per line)
  --no-probe            Skip common SW filename probing

Scan Options:
  -P PARALLEL, --parallel PARALLEL
                        Concurrent scans (default: 6, max: 20)
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 15)
  --max-sw-bytes MAX_SW_BYTES
                        Maximum SW script size in bytes (default: 524288)
  --max-routes MAX_ROUTES
                        Maximum routes to extract per SW (default: 50)
  --deep                Legacy deep static parse hint (will set --ast-depth=2 if not provided)

Enhanced Analysis (optional):
  --ast                 Enable AST analysis (default)
  --no-ast              Disable AST analysis
  --ast-depth AST_DEPTH
                        Recurse importScripts/ESM to this depth (default: 0; or 2 if --deep)
  --headless            Enable Playwright headless validation
  --headless-timeout HEADLESS_TIMEOUT
                        Headless timeout (ms)
  --headless-max-routes HEADLESS_MAX_ROUTES
                        Max routes to probe dynamically
  --headless-crawl      Crawl same-origin links (default)
  --no-headless-crawl   Disable headless crawl
  --route-seed ROUTE    Seed route (repeatable)
  --login-script PATH   Path to a JS file to run before crawl (auto-login etc.)
  --login-wait SELECTOR
                        CSS selector to wait for after login
  --prove-interception  Prove response interception via SW
  --no-prove-interception
                        Disable interception proof
  --prove-precache      Prove precache via cache audit
  --no-prove-precache  Disable precache proof
  --prove-swr           Try to detect stale-while-revalidate
  --no-prove-swr       Disable SWR proof

Security Analysis Options:
  --risk-threshold RISK_THRESHOLD
                        Only output findings with risk score >= N (0-100)
  --no-risk-assessment  Skip risk scoring and security analysis
  --include-patterns    Output detected security patterns in detail
  --sensitive-only      Only output workers with sensitive route patterns

Output Options:
  --json                JSONL output with full security analysis
  --quiet               Suppress comments and progress messages
  --verbose             Detailed security analysis output
  -o OUTPUT, --output OUTPUT
                        Write results to file

Network Options:
  --ua USER_AGENT, --user-agent USER_AGENT
                        Custom User-Agent string
  --header HEADERS      Extra HTTP header (repeatable)
  --cookie COOKIE       Cookie header value
  --proxy PROXY         HTTP proxy URL (currently unused)

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

⚠️ **Authorized Use Only** - Swmap is designed for:
- Penetration testing with explicit written permission
- Bug bounty programs within platform guidelines  
- Government cybersecurity operations
- Academic research in controlled environments
