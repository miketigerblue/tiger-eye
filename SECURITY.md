# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in tiger-eye, please report it
responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@tigerblue.tech** with:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact assessment
4. Any suggested fixes (optional)

### What to expect

- **Acknowledgement** within 48 hours
- **Initial assessment** within 5 business days
- **Fix or mitigation** within 30 days for confirmed vulnerabilities
- Credit in release notes (unless you prefer anonymity)

## Scope

The following are in scope:

- SQL injection or parameter binding issues in pgvector queries
- Authentication/authorisation bypasses on internal API endpoints
- Secret leakage (API keys in logs, Docker images, or git history)
- Dependency vulnerabilities (supply chain)
- Server-side request forgery (SSRF) via feed content
- Prompt injection that causes the LLM to exfiltrate data

The following are out of scope:

- Denial of service against the enrichment loop (rate limiting is by design)
- Vulnerabilities in upstream dependencies already reported to their maintainers
- Social engineering attacks

## Security Controls

Tiger-eye implements the following security controls:

- **SAST**: Bandit + Semgrep + CodeQL run on every PR
- **DAST**: ZAP baseline scan against running container in CI
- **Dependency scanning**: pip-audit + Dependabot with weekly PR cadence
- **Secret scanning**: Gitleaks in CI + detect-secrets pre-commit hook
- **Container scanning**: Trivy vulnerability + SBOM generation
- **Input validation**: All LLM output normalised before database insertion
- **Parameterised queries**: No string concatenation in SQL
- **Secret isolation**: `.env` gitignored, `.dockerignore` excludes secrets from image
