#!/usr/bin/env bash
set -euo pipefail

# ---------- Colors ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------- Config ----------
PYTHON_MIN_VERSION="3.9"
SWMAP_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
DEFAULT_INSTALL_DIR="/usr/local/bin"
ALT_INSTALL_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.swmap"

# CLI flags
NO_DEPS=false
TEST_ONLY=false

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -h, --help       Show this help message
  --no-deps        Skip Python dependency installation
  --test-only      Run post-install tests only (do not install/link)
EOF
}

# ---------- Arg parsing ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0;;
    --no-deps) NO_DEPS=true; shift;;
    --test-only) TEST_ONLY=true; shift;;
    *) log_warning "Unknown option: $1"; usage; exit 1;;
  esac
done

# ---------- Checks ----------
check_root() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    log_warning "Running as root user"
  fi
}

compare_versions() {
  # returns 0 if $1 >= $2
  printf '%s\n%s\n' "$1" "$2" | sort -C -V
}

check_python() {
  log_info "Checking Python version..."
  if ! command -v python3 >/dev/null 2>&1; then
    log_error "Python 3 is not installed. Install Python ${PYTHON_MIN_VERSION}+ from https://python.org"
    exit 1
  fi

  PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
  PY_FULL=$(python3 -c 'import sys; print(sys.version)')
  log_info "Found Python: $PY_FULL"

  if ! compare_versions "$PYTHON_VERSION" "$PYTHON_MIN_VERSION"; then
    log_error "Python ${PYTHON_MIN_VERSION}+ required (found $PYTHON_VERSION)"
    exit 1
  fi
  log_success "Python version check passed"
}

check_dependencies() {
  log_info "Checking optional system dependencies (curl, wget, git)..."
  local missing=()
  for cmd in curl wget git; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if ((${#missing[@]})); then
    log_warning "Missing optional tools: ${missing[*]} (functionality may be limited)"
  fi
  log_success "Dependency check completed"
}

# ---------- Setup tasks ----------
create_config_dir() {
  log_info "Creating configuration directory at $CONFIG_DIR"
  mkdir -p "$CONFIG_DIR"/{logs,cache,patterns}
  log_success "Configuration directory prepared"
}

install_python_deps() {
  $NO_DEPS && { log_info "Skipping dependency installation (--no-deps)"; return; }
  log_info "Installing Python dependencies via pip..."

  if ! command -v pip3 >/dev/null 2>&1; then
    log_error "pip3 is not available. Please install pip for Python 3."
    exit 1
  fi

  python3 -m pip install --upgrade pip --quiet

  # Minimal runtime deps used in scripts (expand if your package has more)
  local requirements=(
    "requests>=2.28.0"
    "urllib3>=1.26.0"
    "psutil>=5.9.0"
  )
  for pkg in "${requirements[@]}"; do
    log_info "Installing $pkg ..."
    if python3 -m pip install "$pkg" --quiet; then
      log_success "Installed $pkg"
    else
      log_error "Failed to install $pkg"
      exit 1
    fi
  done

  log_success "Python dependencies installed"
}

pick_install_dir() {
  # choose a writable install directory for the CLI symlink
  if [[ -w "$DEFAULT_INSTALL_DIR" ]]; then
    echo "$DEFAULT_INSTALL_DIR"
  else
    mkdir -p "$ALT_INSTALL_DIR"
    echo "$ALT_INSTALL_DIR"
  fi
}

install_swmap() {
  $TEST_ONLY && { log_info "Skipping install/link (--test-only)"; return; }

  log_info "Installing SWMap CLI launcher..."
  local dest_dir
  dest_dir="$(pick_install_dir)"
  local target="$PROJECT_ROOT/swmap.py"
  local link_path="$dest_dir/swmap"

  if [[ ! -f "$target" ]]; then
    log_error "swmap.py not found in $PROJECT_ROOT"
    log_error "Please run this script from the project root"
    exit 1
  fi

  chmod +x "$target"
  ln -sf "$target" "$link_path"
  log_success "Installed launcher: $link_path"

  # Desktop entry (Linux GUI)
  if command -v xdg-desktop-menu >/dev/null 2>&1; then
    create_desktop_entry "$link_path"
  fi

  # Ensure $dest_dir is on PATH
  if [[ ":$PATH:" != *":$dest_dir:"* ]]; then
    log_info "Adding $dest_dir to PATH in your shell profile"
    add_to_path "$dest_dir"
  fi
}

create_desktop_entry() {
  local exec_path="$1"
  local entry="$HOME/.local/share/applications/swmap.desktop"
  mkdir -p "$(dirname "$entry")"
  cat >"$entry" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=SWMap
Comment=Service Worker Security Analyzer
Exec=$exec_path
Icon=terminal
Terminal=true
Categories=Security;Development;
Keywords=security;service-worker;pwa;analysis;
EOF
  log_success "Desktop entry created: $entry"
}

add_to_path() {
  local bin_dir="$1"
  local profile=""
  if [[ -n "${BASH_VERSION:-}" ]]; then
    profile="$HOME/.bashrc"
  elif [[ -n "${ZSH_VERSION:-}" ]]; then
    profile="$HOME/.zshrc"
  else
    profile="$HOME/.profile"
  fi
  if [[ -w "$profile" ]]; then
    echo 'export PATH="$PATH:'"$bin_dir"'"' >> "$profile"
    log_success "Added to PATH in $profile"
    log_info "Run 'source $profile' or reopen your terminal"
  else
    log_warning "Could not update PATH automatically; add $bin_dir to your PATH"
  fi
}

run_tests() {
  log_info "Running post-installation tests..."
  if python3 -c "import requests, psutil; print('OK')" >/dev/null 2>&1; then
    log_success "Python dependency import test passed"
  else
    log_error "Dependency import test failed"
    exit 1
  fi

  if [[ -f "$PROJECT_ROOT/swmap.py" ]]; then
    if python3 "$PROJECT_ROOT/swmap.py" --version >/dev/null 2>&1; then
      log_success "SWMap version check passed"
    else
      log_warning "SWMap version check failed (may be normal during dev)"
    fi
  fi
  log_success "All tests completed"
}

show_summary() {
  echo
  log_success "🎉 SWMap Installation Completed Successfully!"
  echo
  log_info "Summary:"
  echo -e "  ${GREEN}✓${NC} Config directory: $CONFIG_DIR"
  if command -v swmap >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Executable: $(command -v swmap)"
    echo
    log_info "Usage:"
    echo "  swmap --help"
    echo "  swmap https://example.com"
  else
    echo -e "  ${YELLOW}⚠${NC} Executable: $PROJECT_ROOT/swmap.py"
    echo
    log_info "Usage:"
    echo "  python3 $PROJECT_ROOT/swmap.py --help"
  fi
  echo
  log_info "Documentation:"
  echo "  https://github.com/bl4ck0w1/swmap"
  echo
  log_info "Support:"
  echo "  https://github.com/bl4ck0w1/swmap/issues"
}

main() {
  echo
  echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║           SWMap Installer              ║${NC}"
  echo -e "${BLUE}║    Service Worker Security Mapper      ║${NC}"
  echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
  echo

  check_root
  check_python
  check_dependencies
  create_config_dir
  install_python_deps
  install_swmap
  run_tests
  show_summary
}

main
