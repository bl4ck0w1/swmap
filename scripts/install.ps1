
param(
    [switch]$Dev = $false,
    [switch]$Full = $false,
    [switch]$Help = $false
)

if ($Help) {
    Write-Host "SWMap Windows Installer" -ForegroundColor Green
    Write-Host "Usage: .\install.ps1 [-Dev] [-Full] [-Help]"
    Write-Host "  -Dev   : Install development dependencies"
    Write-Host "  -Full  : Install with all optional dependencies" 
    Write-Host "  -Help  : Show this help message"
    exit 0
}

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
        Write-Error "Python not found. Please install Python 3.9+ from https://python.org"
        exit 1
    }
    
    $version = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
    if (-not $version) {
        Write-Error "Failed to get Python version"
        exit 1
    }
    
    Write-Success "Found Python $version"
    return $true
}

function Install-Dependencies {
    param([bool]$Dev, [bool]$Full)
    
    Write-Info "Installing dependencies..."
    
    try {
        & python -m pip install --upgrade pip
        & python -m pip install -e .
        
        if ($Dev) {
            Write-Info "Installing development dependencies..."
            & python -m pip install -e ".[dev]"
        }
        
        if ($Full) {
            Write-Info "Installing full dependencies..."
            & python -m pip install -e ".[full]"
        }
        
        Write-Success "Dependencies installed successfully"
    }
    catch {
        Write-Error "Failed to install dependencies: $($_.Exception.Message)"
        exit 1
    }
}

function Initialize-Config {
    $configDir = "$env:USERPROFILE\.swmap"
    
    if (-not (Test-Path $configDir)) {
        Write-Info "Creating configuration directory..."
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        Write-Success "Created config directory: $configDir"
    }
    $subdirs = @('logs', 'cache', 'patterns')
    foreach ($subdir in $subdirs) {
        $path = Join-Path $configDir $subdir
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

function Main {
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════╗" -ForegroundColor $Blue
    Write-Host "║           SWMap Installer             ║" -ForegroundColor $Blue  
    Write-Host "║    Service Worker Security Analyzer    ║" -ForegroundColor $Blue
    Write-Host "╚════════════════════════════════════════╝" -ForegroundColor $Blue
    Write-Host "`n"
    
    Write-Info "Starting SWMap installation on Windows..."
    
    Test-Python
    Install-Dependencies -Dev $Dev -Full $Full
    Initialize-Config
    
    Write-Success "🎉 SWMap installation completed successfully!"
    Write-Host "`nUsage:" -ForegroundColor $Blue
    Write-Host "  python swmap.py --help" -ForegroundColor $Green
    Write-Host "  python swmap.py https://example.com" -ForegroundColor $Green
    Write-Host "`nDocumentation: https://github.com/bl4ck0w1/swmap" -ForegroundColor $Blue
}

Main