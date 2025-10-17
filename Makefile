SHELL := /bin/bash

# --- Config -------------------------------------------------------------------
PYTHON ?= python3
PIP    ?= $(PYTHON) -m pip
PKG    ?= swmap

SRC    := swmap.py src config tests
# Override with: make TESTS="tests/test_scanner.py -k fast"
TESTS  ?= tests

# --- Helpers ------------------------------------------------------------------
.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo

# --- Install / Setup ----------------------------------------------------------
.PHONY: install
install: ## Editable install (base)
	$(PIP) install --upgrade pip
	$(PIP) install -e .

.PHONY: install-full
install-full: ## Editable install with [full] extras
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[full]"

.PHONY: install-headless
install-headless: ## Editable install with [headless] extras (Playwright)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[headless]"

.PHONY: install-dev
install-dev: ## Editable install with [dev] extras
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

.PHONY: init
init: ## Base + full + headless + dev extras
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[full,headless,dev]"

# --- Code Quality -------------------------------------------------------------
.PHONY: format
format: ## Auto-format with black
	$(PYTHON) -m black $(SRC)

.PHONY: lint
lint: ## Lint (black --check + flake8)
	$(PYTHON) -m black --check $(SRC)
	$(PYTHON) -m flake8 $(SRC)

.PHONY: typecheck
typecheck: ## Static type-check with mypy
	$(PYTHON) -m mypy src swmap.py

# --- Tests --------------------------------------------------------------------
.PHONY: test
test: ## Run tests (pytest)
	$(PYTHON) -m pytest $(TESTS)

.PHONY: test-cov
test-cov: ## Run tests with coverage
	$(PYTHON) -m pytest --cov=src --cov-report=term-missing $(TESTS)

# --- Tools / Scripts ----------------------------------------------------------
.PHONY: bench
bench: ## Run performance benchmark (uses scripts/benchmark.py)
	$(PYTHON) scripts/benchmark.py

.PHONY: patterns-update
patterns-update: ## Update pattern DB (scripts/update_patterns.py --update)
	$(PYTHON) scripts/update_patterns.py --update

.PHONY: patterns-validate
patterns-validate: ## Validate local patterns
	$(PYTHON) scripts/update_patterns.py --validate

# --- Packaging / Release ------------------------------------------------------
.PHONY: dist
dist: ## Build sdist and wheel into dist/
	$(PIP) install build twine
	$(PYTHON) -m build

.PHONY: lsdist
lsdist: ## List artifacts in dist/
	@ls -l dist || true

.PHONY: publish-test
publish-test: ## Upload to TestPyPI
	$(PYTHON) -m twine upload --repository testpypi dist/*

.PHONY: publish
publish: ## Upload to PyPI
	$(PYTHON) -m twine upload dist/*

# --- Maintenance --------------------------------------------------------------
.PHONY: clean
clean: ## Remove build/pytest/mypy caches and dist artifacts
	rm -rf build/ dist/ .eggs/ *.egg-info \
	       .pytest_cache/ .mypy_cache/ .coverage coverage.xml

.PHONY: reinstall
reinstall: clean ## Reinstall editable with full+headless+dev extras
	-$(PIP) uninstall -y $(PKG) || true
	$(PIP) install -e ".[full,headless,dev]"

# --- CLI convenience ----------------------------------------------------------
.PHONY: run
run: ## Run CLI directly (no install needed)
	$(PYTHON) swmap.py --help
