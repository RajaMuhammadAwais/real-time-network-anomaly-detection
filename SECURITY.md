# Security Policy

We take security seriously and appreciate responsible disclosure.

## Reporting a vulnerability

- Do not file public issues for suspected vulnerabilities.
- Contact the maintainers privately (use the repository’s security advisory workflow if enabled, or email if provided).
- Include:
  - A detailed description of the issue and its impact
  - Steps to reproduce, proof-of-concept if available
  - Affected versions/commits
  - Suggested remediation if known

## Disclosure and patch process

- We will acknowledge reports within 5 business days.
- We aim to provide a fix or mitigation within 14 business days for high-severity issues.
- Coordinated disclosure is appreciated; we will credit reporters (unless anonymity is requested).

## Hardening guidance

- Do not enable privileged capabilities (NET_ADMIN/NET_RAW) unless absolutely necessary.
- Use TLS and a reverse proxy in production.
- Keep dependencies up to date and remove unused ones.
- Run containers as non-root where possible.