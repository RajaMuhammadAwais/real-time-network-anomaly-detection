# Contributing Guide

Thank you for your interest in contributing! This project brings together networking, machine learning, and a modern web UI. This guide explains how we work, how to get set up locally, and specific guidance for different contributor roles — including a dedicated section for DevOps engineers.

- Project language/runtime: Python 3.11
- Style and tooling: black, isort, flake8, pre-commit
- Packaging: requirements.txt
- Orchestration: docker-compose
- Make targets: see Makefile
- CI: via pre-commit hooks locally (you can mirror these in your CI system)

If anything is unclear, open an issue and we’ll help. Please also review our [Code of Conduct](CODE_OF_CONDUCT.md) and [Security Policy](SECURITY.md) before contributing.

## Table of contents

- Getting started
- Development workflow
- Testing
- Code style and formatting
- Commit messages and branching
- Pull request process and review checklist
- Documentation style
- Performance and scalability guidelines
- Dependency management policy
- Versioning and releases
- Security and responsible disclosure
- Contributor roles
  - Backend and ML contributors
  - Frontend contributors
  - DevOps contributors (detailed)
- Support matrix
- Using Architectural Decision Records (ADRs)
- Troubleshooting

---

## Getting started

1) Fork and clone the repository
2) Python and tooling
   - Use Python 3.11
   - Create a virtual environment:
     - make venv
     - make install
   - Install pre-commit hooks:
     - make pre-commit
3) Verify setup
   - Code style/lint: make fmt && make lint
   - Tests: make test
   - Run locally:
     - make run (basic) or
     - make run-enhanced (enhanced backend)

Alternatively, you can use Docker:

- docker compose up --build

The backend runs on http://localhost:5000.

## Development workflow

- Create a feature branch from main, e.g., feature/my-change or fix/issue-123.
- Keep pull requests small and focused; prefer several small PRs over one large one.
- Ensure pre-commit checks pass locally before pushing.
- Add or update tests for new behavior.
- Update documentation when behavior or interfaces change.
- Prefer Conventional Commits for commit messages (e.g., feat:, fix:, docs:, chore:, refactor:, test:, perf:, ci:).
- Sign-off commits if your organization requires DCO: git commit -s -m "feat: message"

## Testing

- Unit tests live under tests/.
- Run the full suite locally: make test
- Keep tests deterministic and fast. Prefer realistic but minimal fixtures.
- If adding external integrations, mock network and OS interactions.

## Code style and formatting

- black, isort, and flake8 are enforced via pre-commit.
- Run:
  - make fmt  # black + isort
  - make lint # flake8
- Keep functions small and focused; favor readability over cleverness.
- Prefer pure functions where possible and avoid global mutable state.
- Document non-obvious behavior with short, meaningful comments rather than verbose docstrings.

## Commit messages and branching

- Branch naming:
  - feature/short-description
  - fix/short-description
  - chore/short-description
  - docs/short-description
- Commit convention (recommended):
  - type(scope): concise message
  - Examples: feat(backend): add websocket handler; fix(ci): pin action version
- Reference issues with “Fixes #123” or “Refs #123” in the PR description.
- For multi-commit PRs, squash-merge is preferred to keep history tidy (unless there’s value in preserving granular commits).

## Pull request process and review checklist

- Open PRs early as “Draft” to get feedback.
- Ensure the following before requesting review:
  - Code compiles and runs locally
  - pre-commit passes (black, isort, flake8, whitespace)
  - Tests are added/updated and pass locally: make test
  - README/docs updated for user-facing changes
  - No secrets or credentials included
  - Backwards compatibility considered (note any breaking changes)
- Reviewer checklist (maintainers):
  - Clear purpose and scope
  - Tests adequately cover new/changed behavior
  - Performance impact is acceptable
  - Security implications considered
  - Documentation updated
  - Small, atomic commits or a clean squashed history

## Documentation style

- Keep docs concise and task-oriented.
- Update README.md for high-level changes; add deeper runbooks or ADRs under docs/.
- Use plain English, short sentences, and active voice.
- Include example commands, expected outputs, and rollback instructions for ops docs.

## Performance and scalability guidelines

- Avoid O(n^2) operations on unbounded data; stream or window where possible.
- Keep packet-processing paths efficient; batch work and minimize per-packet overhead.
- Add caching only when measured; remove dead caches.
- Use profiling to justify optimizations and include results in PR description when relevant.

## Dependency management policy

- Prefer standard library and existing dependencies before adding new ones.
- New dependencies must be:
  - Actively maintained and reasonably popular
  - Compatible with our license (MIT) and Python 3.11
  - Pinned in requirements.txt with minimal version if necessary
- Remove unused dependencies when discovered.

## Versioning and releases

- Version is tracked in the top-level VERSION file.
- Use semantic versioning (MAJOR.MINOR.PATCH).
- For PRs that change the user-facing behavior or API, propose a version bump in the PR description.
- Release process (maintainers):
  - Update VERSION
  - Update CHANGELOG (if maintained)
  - Tag the commit: git tag -a vX.Y.Z -m "Release vX.Y.Z" && git push --tags
  - Build and push images to the registry (see DevOps: CI/CD)

## Security and responsible disclosure

- Do not include secrets in code, config, or commit history.
- If you discover a vulnerability:
  - Do not open a public issue.
  - Email the maintainers or use the private security contact channel if provided.
  - Provide steps to reproduce, affected versions, and suggested mitigations.
- Avoid enabling privileged container capabilities by default.
- See SECURITY.md for detailed reporting and patch timelines.

## Contributor roles

### Backend and ML contributors

- Follow the data model and feature engineering approach described in README.md.
- Keep long-running operations off the main request path; use background tasks where appropriate.
- If you change model parameters or feature extraction logic, update docs and tests accordingly.

### Frontend contributors

- Keep the dashboard performant; batch updates instead of frequent granular DOM changes.
- Prefer accessible, responsive design.
- Coordinate API changes with backend contributors.

### DevOps contributors (detailed)

DevOps work helps ensure the project is reproducible, observable, secure, and easy to deploy.

1) Local developer experience
- Makefile:
  - venv: create virtualenv
  - install: install Python deps
  - fmt / lint / test: local quality gates
  - run / run-enhanced: start backend variants
  - docker-build / docker-up / docker-down: container orchestration helpers
- Keep Make targets idempotent and fast. If you add new common tasks, add a Make target and document it in ‘make help’.

2) Containers and Compose
- Docker build:
  - docker compose up --build to run locally
  - Compose file: docker-compose.yml
    - Builds backend from backend/Dockerfile
    - Exposes 5000
    - Mounts ./logs into container /app/logs
    - Optional capabilities for real packet capture are commented out; avoid enabling by default.
- Backend Dockerfile should:
  - Pin a Python base image (e.g., python:3.11-slim)
  - Install only required dependencies
  - Run as non-root where practical
  - Use PYTHONUNBUFFERED=1 and a sensible working directory

3) Pre-commit and linting
- Hooks live in .pre-commit-config.yaml
  - black@24.8.0, isort, flake8, end-of-file-fixer, trailing-whitespace
- Ensure CI mirrors these checks for consistent results.
- Typical CI steps:
  - Setup Python 3.11
  - pip install -r requirements.txt
  - pip install pre-commit
  - pre-commit run --all-files
  - pytest -q

4) Observability
- Application logs are written to stdout; docker-compose mounts ./logs for persistence if needed.
- Consider wiring a structured logging format (JSON) if adding centralized logging.
- For metrics, propose a minimal, optional integration (e.g., Prometheus exporter) but keep it off-by-default.

5) Security and hardening
- Network capture typically requires elevated privileges; do not grant NET_ADMIN or NET_RAW by default.
- If enabling packet capture in containers, document risks and scope the permissions to the minimum needed.
- Prefer running containers as a non-root user.
- Validate inputs on exposed endpoints and rate-limit if you add new public-facing routes.
- For production:
  - Use a reverse proxy (nginx) with TLS termination
  - Restrict inbound ports in security groups/firewalls
  - Configure health checks and resource limits

6) Configuration and secrets
- Use environment variables for config; provide sane defaults for local dev.
- Do not commit secrets. Prefer a secret manager (e.g., AWS Secrets Manager, Vault) in production.
- Document any new env vars in README.md and docker-compose.yml.

7) CI/CD (example outline)
- Build-and-test job on push and PR:
  - Lint: pre-commit run --all-files
  - Test: pytest -q
  - Build: docker build -f backend/Dockerfile .
- Release job (on tag):
  - Read VERSION
  - Build and tag the image (e.g., ghcr.io/OWNER/REPO:VERSION)
  - Push image to registry
- Keep actions pinned to exact SHAs or version tags.

8) Environments
- Local: docker compose up or make run
- Staging/Prod (example approach):
  - Immutable images pushed to a registry
  - IaC (Terraform, Pulumi) to provision infra (out of scope here but welcome as separate PRs)
  - Deployment via GitOps (Argo CD/Flux) or a simple workflow if the stack is small
  - Blue/green or rolling update strategy
  - Centralized logs and metrics

9) Documentation
- Update README.md sections when changing runtime, ports, or interfaces.
- Add docs under docs/ for deeper operational runbooks (e.g., scaling, TLS, reverse proxy config).
- Keep docker-compose.yml comments accurate when toggling capabilities.

10) Quality gates
- PRs should pass: black, isort, flake8, pytest.
- Prefer introducing new checks via pre-commit config so they run locally and in CI.

## Support matrix

- Python: 3.11 (primary)
- OS (dev): Linux, macOS; Windows via WSL recommended
- Browsers: latest Chrome/Firefox; recent Safari/Edge
- Container runtime: Docker Engine 24+ or compatible

If you add platform-specific features, provide a graceful fallback and document any limitations.

## Using Architectural Decision Records (ADRs)

- When introducing impactful architectural changes (new components, protocols, storage, deployment models), create an ADR in docs/adr/:
  - Naming: docs/adr/NNN-short-title.md
  - Content: context, decision, alternatives considered, consequences
- Keep ADRs short and focused; link them from PR descriptions.
- If superseding a previous ADR, state it clearly.

## Troubleshooting

- Virtualenv issues: remove venv and re-run make venv && make install
- Docker build cache issues: docker builder prune -f
- Port collisions: lsof -i :5000; kill -9 <PID>
- Packet capture permissions: running locally may require sudo; prefer host networking for testing rather than privileged containers.

---

By contributing, you agree that your contributions will be licensed under the project’s MIT License.