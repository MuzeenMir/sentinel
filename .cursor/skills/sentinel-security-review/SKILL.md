---
name: sentinel-security-review
description: Review SENTINEL code for security issues, injection risks, and secret exposure. Use when reviewing PRs, auth/API code, or when the user asks for a security review or threat assessment of changes.
---

# SENTINEL security review

## Scope

SENTINEL is an enterprise security platform. Treat all changes to auth, API gateway, policy enforcement, data ingestion, and compliance as security-sensitive.

## Checklist

1. **Secrets**: No hardcoded API keys, passwords, tokens, or private keys. Use env vars and `.env.example` placeholders.
2. **Injection**: No SQL built from user input; use parameterized queries. No `eval`/`exec` on untrusted data.
3. **Auth**: New endpoints enforce JWT and RBAC; no bypass for “internal” or “dev” without explicit, documented guardrails.
4. **Logging**: Security events (auth failures, policy changes, alert acks) are logged for audit.
5. **Dependencies**: New deps checked for known vulnerabilities and license (avoid GPL/AGPL unless approved).

## Key paths

- Auth: `sentinel-core/backend/auth-service/`
- Gateway: `sentinel-core/backend/api-gateway/`
- Policy/firewall: `sentinel-core/backend/policy-orchestrator/`
- Security docs: `sentinel-core/docs/security.md`

## Output

- **Critical**: Must fix before merge (secrets, injection, auth bypass).
- **High**: Should fix (missing logging, weak validation).
- **Suggestions**: Hardening and best practices.
