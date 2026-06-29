.PHONY: install dev install-dev run test test-cov security-ci lint ci smoke health ready help

PYTHON ?= python3
VENV ?= venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python
PYTEST := $(VENV)/bin/pytest
RUFF := $(VENV)/bin/ruff
BANDIT := $(VENV)/bin/bandit
PIP_AUDIT := $(VENV)/bin/pip-audit
UVICORN := $(VENV)/bin/uvicorn

help:
	@echo "ShieldScan — BreachDirect / Stellar Wave 7"
	@echo ""
	@echo "  make install      Install production dependencies"
	@echo "  make install-dev  Install dev + test dependencies"
	@echo "  make run          Start server on :8000"
	@echo "  make test         Run pytest suite"
	@echo "  make security-ci  Bandit + pip-audit"
	@echo "  make lint         Ruff check"
	@echo "  make ci           Full CI gate (lint + test + security-ci)"
	@echo "  make smoke        Health + readiness smoke check"

install:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -r requirements.txt

install-dev: install
	$(PIP) install -r requirements-dev.txt

run:
	$(UVICORN) app.main:app --host 0.0.0.0 --port 8000 --reload

test:
	SHIELDSCAN_DATABASE_URL=sqlite:///:memory: $(PYTEST) tests/ -v

test-cov:
	SHIELDSCAN_DATABASE_URL=sqlite:///:memory: $(PYTEST) tests/ -v --cov=app --cov-report=term-missing

lint:
	$(RUFF) check app tests

security-ci:
	$(BANDIT) -r app -ll -q
	$(PIP_AUDIT) -r requirements.txt

ci: lint test security-ci
	@echo "✅ make ci passed"

smoke: health ready

health:
	@curl -sf http://127.0.0.1:8000/health | $(PYTHON) -m json.tool > /dev/null && echo "✅ /health ok"

ready:
	@curl -sf http://127.0.0.1:8000/ready | $(PYTHON) -m json.tool > /dev/null && echo "✅ /ready ok"
