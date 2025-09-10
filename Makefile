PY := python3.11
PIP := $(PY) -m pip

.PHONY: help install venv lint fmt test run run-enhanced docker-build docker-up docker-down pre-commit push-branch

help:
	@echo "Targets:"
	@echo "  venv            Create virtual environment (venv)"
	@echo "  install         Install dependencies into venv"
	@echo "  lint            Run flake8"
	@echo "  fmt             Run black + isort"
	@echo "  test            Run pytest"
	@echo "  run             Run basic Flask app (backend/app.py)"
	@echo "  run-enhanced    Run enhanced app (backend/enhanced_app.py)"
	@echo "  docker-build    Build docker image"
	@echo "  docker-up       Start with docker-compose"
	@echo "  docker-down     Stop docker-compose"
	@echo "  pre-commit      Install git pre-commit hooks"
	@echo "  push-branch     Commit current changes and push a new PR branch"

venv:
	@test -d venv || $(PY) -m venv venv
	@. venv/bin/activate; $(PIP) install --upgrade pip

install: venv
	@. venv/bin/activate; $(PIP) install -r requirements.txt

lint:
	@. venv/bin/activate; flake8 backend tests

fmt:
	@. venv/bin/activate; black backend tests || true
	@. venv/bin/activate; isort backend tests || true

test:
	@. venv/bin/activate; pytest -q || true

run: install
	@. venv/bin/activate; $(PY) backend/app.py

run-enhanced: install
	@. venv/bin/activate; $(PY) backend/enhanced_app.py

docker-build:
	@docker build -t network-anomaly-backend -f backend/Dockerfile .

docker-up:
	@docker compose up --build

docker-down:
	@docker compose down

pre-commit:
	@. venv/bin/activate; $(PIP) install pre-commit
	@. venv/bin/activate; pre-commit install

push-branch:
	@bash scripts/push_pr_branch.sh