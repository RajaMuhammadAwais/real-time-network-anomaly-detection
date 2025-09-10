# Contributing to Network Traffic Anomaly Detection

Thank you for taking the time to contribute. This guide explains how to get a development environment running, our coding standards, and how to submit changes.

- Project overview: see README.md
- Developer guide: see Makefile targets below
- Code of Conduct: see CODE_OF_CONDUCT.md

## Quick start

1) Fork and clone
- Fork the repository on GitHub
- Clone your fork and add the upstream remote

2) Create a branch
- Use a descriptive branch name:
  - feat/<short-name> for features
  - fix/<short-name> for bug fixes
  - chore/<short-name> for maintenance
  - docs/<short-name> for documentation

3) Set up environment
- Python 3.11 is required
- Create venv and install dependencies:
  - make install
- Install pre-commit hooks:
  - make pre-commit

4) Run locally
- Basic app: make run (backend/app.py)
- Enhanced app: make run-enhanced (backend/enhanced_app.py)
- Docker (optional): docker compose up --build

5) Validate before pushing
- Format: make fmt
- Lint: make lint
- Tests: make test
- Ensure all GitHub Actions checks pass on your PR

## Development workflow

- Edit code in small, focused commits
- Keep existing style, imports, and comments intact where possible
- Write tests for new behavior when applicable (tests/ directory)
- Update README.md or docs/ for user-facing changes

Makefile shortcuts:
- make install        Create venv and install dependencies
- make fmt            Run black and isort
- make lint           Run flake8
- make test           Run pytest
- make run            Start Flask app
- make run-enhanced   Start enhanced app
- make docker-up      Start via docker-compose
- make docker-down    Stop containers

## Coding standards

- Language: Python 3.11
- Style: black + isort + flake8 (max line length 100)
- Avoid broad try/except; prefer explicit error handling
- Keep functions small and readable; add minimal, meaningful comments only when necessary
- Follow existing patterns in the codebase

Commit messages (Conventional Commits):
- feat: add LSTM detector threshold configuration
- fix: handle empty dataframe in feature extractor
- chore: update CI caching for pip
- docs: add deployment instructions

## Pull requests

- Use the PR template; fill all required sections
- Ensure CI (lint/test/build) passes
- Link related issues (e.g., Closes #123)
- Provide screenshots or logs for UI/behavioral changes
- Keep PRs focused; prefer multiple small PRs over one large PR
- Be responsive to review feedback

## Contributor License Agreement (CLA)

First-time contributors will be asked by the CLA Assistant bot (in the PR) to sign a Contributor License Agreement electronically. This is required before a PR can be merged.

## Security

Please do not open public issues for security vulnerabilities. See SECURITY.md for private disclosure instructions.

## Questions and support

- Use GitHub Issues for bugs and feature requests
- For design/architecture discussions, open a discussion in an issue before large changes
- Be professional and respectful in all interactions

Thank you for contributing!