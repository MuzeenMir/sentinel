# Bugbot Pro — SENTINEL project rules

Use this context for all PR reviews. SENTINEL is an enterprise-grade, AI-powered security platform. Security, correctness, and auditability are critical.

## Project context

- **Repo layout**: Main app under `sentinel-core/`. Backend = Python/Flask microservices in `sentinel-core/backend/`. Frontend = React + TypeScript + Vite in `sentinel-core/frontend/admin-console/`. Stream processing = Apache Flink in `sentinel-core/stream-processing/flink-jobs/`. Training = `sentinel-core/training/`. Infra = Terraform in `sentinel-core/infrastructure/`.
- **Architecture**: See `sentinel-core/docs/ARCHITECTURE-DESIGN-DEVELOPMENT.md` and `sentinel-core/readme.md` for data flow, services, and conventions.
- **Security**: Zero-trust style; JWT (RS256), RBAC, TLS/mTLS, no secrets in code. See `sentinel-core/docs/security.md`.

## Rules for PR reviews

### Security (blocking)

1. **No dangerous dynamic execution**  
   If any changed file contains `eval(`, `exec(`, or `__import__` used on user-controlled or unsanitized input:
   - Add a **blocking** Bug: "Dangerous dynamic execution"
   - Body: "Use of eval/exec/__import__ on untrusted input is not allowed. Use safe parsers, allowlists, or documented exceptions with tests."
   - Label: `security`.

2. **Secrets and credentials**  
   If changed files add or modify patterns that look like secrets (e.g. hardcoded API keys, passwords, private keys, `Bearer .*` in examples):
   - Add a **blocking** Bug: "Possible secret or credential in code"
   - Body: "Remove secrets from the repo. Use env vars, Secrets Manager, or .env.example placeholders only."
   - Label: `security`.

3. **SQL and injection**  
   If backend or Flink code builds SQL via string concatenation or f-strings with user/request data:
   - Add a **blocking** Bug: "Potential SQL injection"
   - Body: "Use parameterized queries or ORM. No raw SQL built from user input."
   - Label: `security`.

### Backend and services

4. **Tests for backend changes**  
   If the PR modifies files under `sentinel-core/backend/**` or `sentinel-core/stream-processing/**` and there are no changes in `**/*test*`, `**/tests/**`, or `**/__tests__/**`:
   - Add a **blocking** Bug: "Missing tests for backend/stream changes"
   - Body: "Backend or stream-processing code was changed without accompanying tests. Add or update unit/integration tests."
   - Label: `quality`.

5. **Error handling**  
   New backend endpoints or critical paths should log errors and return consistent error responses (no bare `except:` or swallowing exceptions without logging).

### Frontend

6. **React and data**  
   For `sentinel-core/frontend/**`: avoid storing sensitive data in localStorage/sessionStorage without encryption; use existing auth/token patterns from the codebase.

### Dependencies and compliance

7. **License and dependency changes**  
   If the PR modifies dependency files (`package.json`, `package-lock.json`, `requirements*.txt`, `pyproject.toml`, `Pipfile`, `go.mod`, `Cargo.toml`):
   - Run the built-in License Scan if available.
   - If any new or upgraded dependency has license in {GPL-2.0, GPL-3.0, AGPL-3.0} and the project does not allow it:
     - Add a **blocking** Bug: "Disallowed license detected"
     - Include package name, version, and license in the body.
     - Label: `compliance`.

### Quality and style

8. **TODO/FIXME**  
   If any changed file contains `TODO` or `FIXME` without an issue reference (e.g. `TODO(#123):` or `FIXME(JIRA-456):`):
   - Add a **non-blocking** Bug: "TODO/FIXME without issue reference"
   - Body: "Add an issue reference, e.g. `TODO(#123): ...`, or remove before merge."

9. **Logging and audit**  
   Security-sensitive actions (auth failures, policy changes, alert acknowledgments) should be logged for audit. Flag new security-sensitive code paths that have no logging.

## Autofix and suggestions

- Prefer **Create New Branch** for autofix so the author can review and merge.
- When suggesting fixes, prefer minimal, targeted changes and point to `sentinel-core/docs/` where relevant.
