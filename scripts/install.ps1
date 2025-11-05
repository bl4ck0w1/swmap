# scripts/install.ps1
$Green = 'Green'
$Yellow = 'Yellow'
$Red = 'Red'
$Blue = 'Blue'

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Red
}

function Test-Python {
    Write-Info "Checking Python installation..."

    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        $python = Get-Command python3 -ErrorAction SilentlyContinue
    }

    if (-not $python) {
        Write-Error "Python not found. Please install Python 3.9+ from https://python.org and re-run."
        exit 1
    }

    $version = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
    if (-not $version) {
        Write-Error "Failed to get Python version"
        exit 1
    }

    $major, $minor = $version.Split(".")
    if ([int]$major -lt 3 -or ([int]$major -eq 3 -and [int]$minor -lt 9)) {
        Write-Warning "Detected Python $version — SWMap is tested with Python 3.9+. Proceeding anyway."
    }

    Write-Success "Found Python $version"
}

function Install-SWMap {
    Write-Info "Upgrading pip..."
    python -m pip install --upgrade pip --quiet

    Write-Info "Installing SWMap package from current directory (editable)..."
    python -m pip install -e . 
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install SWMap package (pip -e .). Make sure you're running this from the repo root."
        exit 1
    }
    Write-Success "SWMap package installed."
}

function Install-HeadlessSupport {
    Write-Info "Installing Playwright Python package..."
    python -m pip install playwright
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Playwright Python package install failed. Headless features may not work."
        return
    }

    Write-Info "Installing Playwright browser (chromium)..."
    python -m playwright install chromium
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Playwright browser install failed. Headless features may not work."
    } else {
        Write-Success "Playwright headless environment ready."
    }
}

function Initialize-Config {
    $configDir = Join-Path $env:USERPROFILE ".swmap"
    if (-not (Test-Path $configDir)) {
        Write-Info "Creating configuration directory at $configDir ..."
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    $subdirs = @('logs', 'cache', 'patterns')
    foreach ($sub in $subdirs) {
        $p = Join-Path $configDir $sub
        if (-not (Test-Path $p)) {
            New-Item -ItemType Directory -Path $p -Force | Out-Null
        }
    }
    Write-Success "Config directories initialized at $configDir"
}

function Main {
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════╗" -ForegroundColor $Blue
    Write-Host "║           SWMap Installer             ║" -ForegroundColor $Blue
    Write-Host "║    Service Worker Security Analyzer   ║" -ForegroundColor $Blue
    Write-Host "╚════════════════════════════════════════╝" -ForegroundColor $Blue
    Write-Host ""

    Write-Info "Starting SWMap installation on Windows..."

    Test-Python
    Install-SWMap
    Install-HeadlessSupport
    Initialize-Config

    Write-Success "🎉 SWMap installation completed successfully!"
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor $Blue
    Write-Host "  swmap --help" -ForegroundColor $Green
    Write-Host "  python swmap.py https://example.com" -ForegroundColor $Green
    Write-Host ""
    Write-Host "If PowerShell blocked this script, run first:" -ForegroundColor $Yellow
    Write-Host "  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass" -ForegroundColor $Yellow
    Write-Host ""
    Write-Host "Docs: https://github.com/bl4ck0w1/swmap" -ForegroundColor $Blue
}

Main
