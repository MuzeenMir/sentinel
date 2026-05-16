# Phase 0 Security Stabilization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the known deployment-blocking security and schema defects from DRAGON_SCALE v1 before any v2 feature or service-consolidation work starts.

**Architecture:** Keep v1 services intact and harden their current boundaries. Fix authentication ordering, gateway authorization, compose defaults/exposure, agent installer trust, internal-service authentication, and schema bootstrap ownership without introducing new product features or decommissioning v1 components.

**Tech Stack:** Python 3.12, Flask, Flask-JWT-Extended, SQLAlchemy/Alembic, pytest, Docker Compose v2, Bash/systemd, React/Vite test gates, GitHub Actions.

---

## Execution Rules

- Work in small commits. One task equals one reviewable commit unless the executor is explicitly told to squash.
- Do not start Phase 1 service consolidation, FastAPI rewrites, real LLM inference, or sensor replacement in this plan.
- Every security bug fix starts with a failing test or static verification script.
- Keep `sentinel-main/` untouched. The active repo is `/mnt/c/Projects/Dragon-Scale/dragon-scale`.
- Use `rg`, `pytest`, `docker compose config`, and targeted shell checks for fast feedback before full CI.
- Do not weaken a test to match current behavior. If a test exposes more related breakage, fix the behavior or split the test into a named follow-up.

## File Map

- Modify: `dragon-scale-core/backend/auth-service/app.py` — login lockout/status ordering, dummy hash timing defense, admin bootstrap hardening if included in the same auth slice.
- Modify: `dragon-scale-core/backend/tests/test_auth_security.py` — auth regression tests for account lockout, suspended status, unknown-user timing path, role/status validation.
- Modify: `dragon-scale-core/backend/api-gateway/app.py` — route decorators, CORS configuration, auth proxy header forwarding, internal token handling, query-token stripping where safe.
- Modify: `dragon-scale-core/backend/tests/test_api_gateway.py` — gateway RBAC, auth proxy, internal token, and query-token regression tests.
- Modify: `dragon-scale-core/docker-compose.yml` — remove unsafe secret fallbacks, stop host-exposing internal services, require internal token, reduce unnecessary privileges.
- Modify: `dragon-scale-core/.env.example` — keep placeholders for dev documentation, but avoid values that make production-looking starts succeed accidentally.
- Create: `dragon-scale-core/scripts/validate_compose_security.py` — static validation for compose secret fallbacks, host exposure, and empty bearer token configuration.
- Test: `dragon-scale-core/tests/test_compose_security.py` or `dragon-scale-core/backend/tests/test_compose_security.py` — pytest wrapper for compose validation.
- Modify: `dragon-scale-core/agent/install.sh` — HTTPS-only control plane, checksum/signature verification, safe JSON generation, hardened systemd unit.
- Create: `dragon-scale-core/agent/tests/test_install_script.py` — static tests for installer hardening.
- Modify: `dragon-scale-core/init.sql` — reduce schema bootstrap to extensions/functions/default seed after Alembic owns tables.
- Modify/Create: `dragon-scale-core/backend/migrations/versions/*.py` — consolidate missing tables, SSO/SCIM/MFA persistence, RLS enablement.
- Modify: `dragon-scale-core/backend/migrations/env.py` and `dragon-scale-core/backend/migrations/versions/*` only as needed to make empty-DB and round-trip migration checks deterministic.
- Modify: `dragon-scale-core/scripts/fresh_db_check.sh` — assert empty-DB upgrade and downgrade/upgrade paths.
- Modify: `.github/workflows/integration.yml`, `.github/workflows/security.yml`, `.github/workflows/lint.yml` only if local verification reveals the current workflows do not run the new checks.
- Modify: `dragon-scale-core/docs/revamp/SECRETS-ROTATION-LOG.md` — record that committed placeholders were removed from runtime defaults and list secrets operators must rotate in existing deployments.
- Modify: `CODE-REVIEW-main-2026-04-18.md` or create `dragon-scale-core/docs/reviews/phase-0-critical-fixes.md` — close findings with evidence after all tasks pass.

## Milestone Order

1. Baseline and guardrails.
2. Auth-service lockout and timing fixes.
3. Gateway RBAC and proxy correctness.
4. Compose secret/exposure hardening.
5. Internal service token behavior.
6. Agent installer trust and systemd hardening.
7. Schema convergence and migration CI.
8. Secondary hardening from the audit suggestions.
9. Full verification and review artifact.

---

### Task 0: Baseline Current Failures

**Files:**
- Read: `CODE-REVIEW-main-2026-04-18.md`
- Read: `dragon-scale-core/docs/DB-MIGRATION-DRIFT-AUDIT.md`
- Read: `dragon-scale-core/docker-compose.yml`
- Read: `dragon-scale-core/backend/auth-service/app.py`
- Read: `dragon-scale-core/backend/api-gateway/app.py`

- [ ] **Step 1: Confirm clean starting point**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale
git status --short
```

Expected: no unexpected modified product files. If there are unrelated changes, do not revert them; record them in the implementation notes.

- [ ] **Step 2: Run targeted existing tests**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/test_auth_security.py tests/test_api_gateway.py -v --tb=short
```

Expected: either PASS, or known failures that are captured before edits. Save the failure list in the task notes.

- [ ] **Step 3: Capture compose rendering**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
docker compose config > /tmp/dragon-scale-compose-before.yml
rg -n "change-this-in-production|ChangeMe|dragon_scale_password|Bearer |0\\.0\\.0\\.0|published:" /tmp/dragon-scale-compose-before.yml
```

Expected before fixes: matches for unsafe defaults and host-exposed ports. This proves the later security validation is catching real current behavior.

- [ ] **Step 4: Commit nothing**

Run:

```bash
git status --short
```

Expected: no new files from the baseline pass except ignored temporary files outside the repo.

---

### Task 1: Auth-Service Lockout and Timing

**Files:**
- Modify: `dragon-scale-core/backend/auth-service/app.py`
- Modify: `dragon-scale-core/backend/tests/test_auth_security.py`

- [ ] **Step 1: Add failing account lockout test**

In `dragon-scale-core/backend/tests/test_auth_security.py`, strengthen `TestSEC02_BruteForceProtection` with this test:

```python
def test_locked_account_rejects_correct_password_before_password_check(self, client):
    _create_user(client)
    with app.app_context():
        user = User.query.filter_by(username="secuser").first()
        user.failed_login_attempts = 5
        user.locked_until = auth_mod.datetime.utcnow() + auth_mod.timedelta(minutes=15)
        db.session.commit()

    with patch.object(User, "check_password", side_effect=AssertionError("password checked for locked user")):
        resp = _login(client)

    assert resp.status_code == 403
    assert "temporarily locked" in resp.get_json()["error"].lower()
```

If `failed_login_attempts` or `locked_until` use different model names, use the exact model names from `User` in `auth-service/app.py` and keep the assertion that `check_password` is not called.

- [ ] **Step 2: Add failing suspended-user ordering test**

In the same class or `TestSEC07_AccountStatus`, add:

```python
def test_suspended_account_rejects_before_password_check(self, client):
    _create_user(client)
    with app.app_context():
        user = User.query.filter_by(username="secuser").first()
        user.status = UserStatus.SUSPENDED
        db.session.commit()

    with patch.object(User, "check_password", side_effect=AssertionError("password checked for suspended user")):
        resp = _login(client)

    assert resp.status_code == 403
    assert "inactive or suspended" in resp.get_json()["error"].lower()
```

- [ ] **Step 3: Add unknown-user dummy hash test**

Add:

```python
def test_unknown_user_runs_dummy_password_check(self, client):
    with patch.object(auth_mod.bcrypt, "checkpw", return_value=False) as mock_check:
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "missing-user", "password": "WrongPassword1!"},
        )

    assert resp.status_code == 401
    assert mock_check.called
```

- [ ] **Step 4: Run tests and verify they fail for the right reason**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/test_auth_security.py::TestSEC02_BruteForceProtection tests/test_auth_security.py::TestSEC07_AccountStatus -v --tb=short
```

Expected: new ordering tests fail because current login calls `check_password` before status/lockout checks. Unknown-user dummy hash test may fail because no dummy bcrypt path exists.

- [ ] **Step 5: Implement auth ordering**

In `auth-service/app.py`, change `login()` to:

```python
DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"dummy-password-for-timing-only", bcrypt.gensalt())
```

Place that constant near the other auth constants after bcrypt is imported. Then structure login as:

```python
user = User.query.filter_by(username=username).first()

if user:
    if user.status != UserStatus.ACTIVE:
        audit_log(
            AuditCategory.AUTH,
            "login_blocked_inactive",
            actor=f"user:{username}",
            detail={"ip": ip_addr, "status": user.status.value},
            redis_client=redis_client,
        )
        return jsonify({"error": "Account is inactive or suspended"}), 403

    if login_attempts_exceeded(user):
        remaining_time = (
            int((user.locked_until - datetime.utcnow()).total_seconds())
            if user.locked_until
            else 0
        )
        return jsonify(
            {
                "error": "Account temporarily locked due to too many failed attempts",
                "retry_after": max(0, remaining_time),
            }
        ), 403
else:
    bcrypt.checkpw(password.encode("utf-8"), DUMMY_PASSWORD_HASH)

if not user or not user.check_password(password):
    if user:
        increment_failed_login(user)
    redis_client.incr(f"failed_login_ip:{ip_addr}")
    redis_client.expire(f"failed_login_ip:{ip_addr}", 3600)
    audit_log(
        AuditCategory.AUTH,
        "login_failed",
        actor=f"user:{username}",
        detail={"ip": ip_addr},
        redis_client=redis_client,
    )
    return jsonify({"error": "Invalid credentials"}), 401
```

Keep the existing MFA, token creation, and login-success logic after this block.

- [ ] **Step 6: Run auth security tests**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/test_auth_security.py -v --tb=short
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add dragon-scale-core/backend/auth-service/app.py dragon-scale-core/backend/tests/test_auth_security.py
git commit -m "fix(auth-service): enforce lockout before password verification"
```

---

### Task 2: Gateway RBAC on Mutating and Admin Routes

**Files:**
- Modify: `dragon-scale-core/backend/api-gateway/app.py`
- Modify: `dragon-scale-core/backend/tests/test_api_gateway.py`

- [ ] **Step 1: Add viewer-forbidden tests for policy mutation**

Add to `TestPolicyEndpoints`:

```python
@patch("requests.post", side_effect=_auth_verify_ok_viewer)
def test_update_policy_viewer_forbidden(self, _mock, client):
    resp = client.put(
        "/api/v1/policies/p1",
        headers=AUTH_HEADER,
        json={"action": "deny"},
        content_type="application/json",
    )
    assert resp.status_code == 403


@patch("requests.post", side_effect=_auth_verify_ok_viewer)
def test_delete_policy_viewer_forbidden(self, _mock, client):
    resp = client.delete("/api/v1/policies/p1", headers=AUTH_HEADER)
    assert resp.status_code == 403
```

- [ ] **Step 2: Add viewer-forbidden tests for alert mutation**

Add to `TestAlertEndpoints`:

```python
@patch("requests.post", side_effect=_auth_verify_ok_viewer)
def test_acknowledge_alert_viewer_forbidden(self, _mock, client):
    resp = client.post(
        "/api/v1/alerts/5/acknowledge",
        headers=AUTH_HEADER,
        json={"notes": "reviewed"},
        content_type="application/json",
    )
    assert resp.status_code == 403


@patch("requests.post", side_effect=_auth_verify_ok_viewer)
def test_resolve_alert_viewer_forbidden(self, _mock, client):
    resp = client.post(
        "/api/v1/alerts/5/resolve",
        headers=AUTH_HEADER,
        json={"resolution": "closed"},
        content_type="application/json",
    )
    assert resp.status_code == 403


@patch("requests.post", side_effect=_auth_verify_ok_viewer)
def test_update_alert_viewer_forbidden(self, _mock, client):
    resp = client.put(
        "/api/v1/alerts/5",
        headers=AUTH_HEADER,
        json={"status": "resolved"},
        content_type="application/json",
    )
    assert resp.status_code == 403
```

- [ ] **Step 3: Add viewer-forbidden tests for admin and tenant routes**

Add:

```python
class TestAdminAndTenantRBAC:
    @patch("requests.post", side_effect=_auth_verify_ok_viewer)
    def test_admin_users_viewer_forbidden(self, _mock, client):
        resp = client.get("/api/v1/admin/users", headers=AUTH_HEADER)
        assert resp.status_code == 403

    @patch("requests.post", side_effect=_auth_verify_ok_viewer)
    def test_admin_update_user_viewer_forbidden(self, _mock, client):
        resp = client.put(
            "/api/v1/admin/users/1",
            headers=AUTH_HEADER,
            json={"role": "admin"},
            content_type="application/json",
        )
        assert resp.status_code == 403

    @patch("requests.post", side_effect=_auth_verify_ok_viewer)
    def test_create_tenant_viewer_forbidden(self, _mock, client):
        resp = client.post(
            "/api/v1/tenants",
            headers=AUTH_HEADER,
            json={"name": "tenant-a"},
            content_type="application/json",
        )
        assert resp.status_code == 403

    @patch("requests.post", side_effect=_auth_verify_ok_viewer)
    def test_update_tenant_viewer_forbidden(self, _mock, client):
        resp = client.put(
            "/api/v1/tenants/1",
            headers=AUTH_HEADER,
            json={"status": "suspended"},
            content_type="application/json",
        )
        assert resp.status_code == 403

    @patch("requests.post", side_effect=_auth_verify_ok_viewer)
    def test_delete_tenant_viewer_forbidden(self, _mock, client):
        resp = client.delete("/api/v1/tenants/1", headers=AUTH_HEADER)
        assert resp.status_code == 403
```

- [ ] **Step 4: Run gateway tests and verify failures**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/test_api_gateway.py::TestPolicyEndpoints tests/test_api_gateway.py::TestAlertEndpoints tests/test_api_gateway.py::TestAdminAndTenantRBAC -v --tb=short
```

Expected: viewer-forbidden tests fail where routes still use `@require_auth`.

- [ ] **Step 5: Replace decorators on mutating policy routes**

In `api-gateway/app.py`, change:

```python
@app.route("/api/v1/policies/<policy_id>", methods=["PUT"])
@require_auth
def update_policy(policy_id):
```

to:

```python
@app.route("/api/v1/policies/<policy_id>", methods=["PUT"])
@require_role("admin")
def update_policy(policy_id):
```

Change delete policy the same way:

```python
@app.route("/api/v1/policies/<policy_id>", methods=["DELETE"])
@require_role("admin")
def delete_policy(policy_id):
```

- [ ] **Step 6: Replace decorators on alert mutation routes**

Change these routes to `@require_role("admin")`:

```python
@app.route("/api/v1/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@app.route("/api/v1/alerts/<int:alert_id>/resolve", methods=["POST"])
@app.route("/api/v1/alerts/<int:alert_id>", methods=["PUT"])
```

Keep alert reads as `@require_auth`.

- [ ] **Step 7: Replace decorators on admin user routes**

Change:

```python
@app.route("/api/v1/admin/users", methods=["GET"])
@require_role("admin")
def admin_get_users():
```

and:

```python
@app.route("/api/v1/admin/users/<int:user_id>", methods=["PUT"])
@require_role("admin")
def admin_update_user(user_id):
```

- [ ] **Step 8: Split tenant route by method if needed**

If `/api/v1/tenants` currently has one function for GET and POST, split it so reads can remain authenticated and writes require admin:

```python
@app.route("/api/v1/tenants", methods=["GET"])
@require_auth
def tenants_list():
    return _proxy_to(app.config["AUTH_SERVICE_URL"], "/api/v1/tenants")


@app.route("/api/v1/tenants", methods=["POST"])
@require_role("admin")
def tenants_create():
    return _proxy_to(app.config["AUTH_SERVICE_URL"], "/api/v1/tenants")
```

If `/api/v1/tenants/<int:tenant_pk>` currently has one function for GET, PUT, DELETE, split it:

```python
@app.route("/api/v1/tenants/<int:tenant_pk>", methods=["GET"])
@require_auth
def tenant_get(tenant_pk):
    return _proxy_to(app.config["AUTH_SERVICE_URL"], f"/api/v1/tenants/{tenant_pk}")


@app.route("/api/v1/tenants/<int:tenant_pk>", methods=["PUT"])
@require_role("admin")
def tenant_update(tenant_pk):
    return _proxy_to(app.config["AUTH_SERVICE_URL"], f"/api/v1/tenants/{tenant_pk}")


@app.route("/api/v1/tenants/<int:tenant_pk>", methods=["DELETE"])
@require_role("admin")
def tenant_delete(tenant_pk):
    return _proxy_to(app.config["AUTH_SERVICE_URL"], f"/api/v1/tenants/{tenant_pk}")
```

- [ ] **Step 9: Run gateway tests**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/test_api_gateway.py -v --tb=short
```

Expected: PASS.

- [ ] **Step 10: Commit**

Run:

```bash
git add dragon-scale-core/backend/api-gateway/app.py dragon-scale-core/backend/tests/test_api_gateway.py
git commit -m "fix(api-gateway): require admin role for mutating routes"
```

---

### Task 3: Compose Secret Defaults and Host Exposure

**Files:**
- Modify: `dragon-scale-core/docker-compose.yml`
- Modify: `dragon-scale-core/.env.example`
- Create: `dragon-scale-core/scripts/validate_compose_security.py`
- Create: `dragon-scale-core/backend/tests/test_compose_security.py`

- [ ] **Step 1: Add compose security validator**

Create `dragon-scale-core/scripts/validate_compose_security.py`:

```python
#!/usr/bin/env python3
"""Validate docker-compose security invariants for Phase 0."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"

FORBIDDEN_DEFAULTS = [
    "POSTGRES_PASSWORD:-",
    "JWT_SECRET_KEY:-",
    "ADMIN_PASSWORD:-",
    "GRAFANA_PASSWORD:-",
    "INTERNAL_SERVICE_TOKEN:-",
    "change-this-in-production",
    "ChangeMe!2026",
    "dragon_scale_password",
    "dragon-scale}",
]

INTERNAL_SERVICES = {
    "postgres",
    "redis",
    "zookeeper",
    "kafka",
    "auth-service",
    "data-collector",
    "xdp-collector",
    "alert-service",
    "ai-engine",
    "elasticsearch",
    "kibana",
    "policy-orchestrator",
    "drl-engine",
    "xai-service",
    "compliance-engine",
    "hids-agent",
    "hardening-service",
    "prometheus",
    "grafana",
}

PUBLIC_SERVICES = {"api-gateway", "admin-console", "tempo"}


def service_blocks(text: str) -> dict[str, str]:
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = re.match(r"^  ([a-zA-Z0-9_-]+):\s*$", line)
        if match:
            current = match.group(1)
            blocks[current] = [line]
            continue
        if current is not None:
            blocks[current].append(line)
    return {name: "\n".join(lines) for name, lines in blocks.items()}


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    errors: list[str] = []

    for token in FORBIDDEN_DEFAULTS:
        if token in text:
            errors.append(f"forbidden compose default found: {token}")

    for name, block in service_blocks(text).items():
        has_ports = re.search(r"^    ports:\s*$", block, flags=re.MULTILINE)
        if name in INTERNAL_SERVICES and has_ports:
            errors.append(f"internal service exposes host ports: {name}")
        if name not in INTERNAL_SERVICES | PUBLIC_SERVICES:
            errors.append(f"unclassified compose service: {name}")

    if "INTERNAL_SERVICE_TOKEN=${INTERNAL_SERVICE_TOKEN?set INTERNAL_SERVICE_TOKEN}" not in text:
        errors.append("INTERNAL_SERVICE_TOKEN must use required-variable syntax")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("compose security validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Add pytest wrapper**

Create `dragon-scale-core/backend/tests/test_compose_security.py`:

```python
import subprocess
import sys
from pathlib import Path


def test_docker_compose_security_invariants():
    repo_core = Path(__file__).resolve().parents[2]
    script = repo_core / "scripts" / "validate_compose_security.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=repo_core,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
```

- [ ] **Step 3: Run validator and verify it fails**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
python scripts/validate_compose_security.py
```

Expected: FAIL with unsafe defaults and internal port exposure.

- [ ] **Step 4: Remove compose secret fallbacks**

In `docker-compose.yml`, replace secret-bearing defaults with required-variable syntax:

```yaml
POSTGRES_PASSWORD: ${POSTGRES_PASSWORD?set POSTGRES_PASSWORD}
```

and environment entries:

```yaml
- POSTGRES_PASSWORD=${POSTGRES_PASSWORD?set POSTGRES_PASSWORD}
- DATABASE_URL=postgresql://${POSTGRES_USER:-dragon-scale}:${POSTGRES_PASSWORD?set POSTGRES_PASSWORD}@dragon-scale-postgres:5432/${POSTGRES_DB:-dragon-scale}
- JWT_SECRET_KEY=${JWT_SECRET_KEY?set JWT_SECRET_KEY}
- ADMIN_PASSWORD=${ADMIN_PASSWORD?set ADMIN_PASSWORD}
- GRAFANA_PASSWORD=${GRAFANA_PASSWORD?set GRAFANA_PASSWORD}
- INTERNAL_SERVICE_TOKEN=${INTERNAL_SERVICE_TOKEN?set INTERNAL_SERVICE_TOKEN}
```

Keep non-secret dev defaults only where they are not credentials, such as service hostnames and ports.

- [ ] **Step 5: Remove host port exposure from internal services**

Delete `ports:` blocks from all internal services listed in the validator. Keep:

```yaml
api-gateway:
  ports:
    - "8080:8080"

admin-console:
  ports:
    - "3000:8080"
```

For local observability, keep `tempo` ports under its opt-in profile. If Grafana and Prometheus need local UI access, move their host ports behind `profiles: ["observability"]` and update the validator classification accordingly.

- [ ] **Step 6: Update `.env.example` with generated-value language**

Use explicit placeholders that make operators replace them:

```dotenv
JWT_SECRET_KEY=replace-with-64-random-characters
ADMIN_PASSWORD=replace-with-strong-admin-password
POSTGRES_PASSWORD=replace-with-strong-postgres-password
GRAFANA_PASSWORD=replace-with-strong-grafana-password
INTERNAL_SERVICE_TOKEN=replace-with-64-random-characters
```

- [ ] **Step 7: Run compose validation**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
python scripts/validate_compose_security.py
POSTGRES_PASSWORD=x JWT_SECRET_KEY=y ADMIN_PASSWORD=z GRAFANA_PASSWORD=g INTERNAL_SERVICE_TOKEN=t docker compose config >/tmp/dragon-scale-compose-after.yml
rg -n "change-this-in-production|ChangeMe|dragon_scale_password|published: \"(5000|5001|5002|5003|5004|5005|5006|5007|5010|5011|5433|6379|9092|2181|9200|9300|5601)\"" /tmp/dragon-scale-compose-after.yml
```

Expected: validator PASS; `rg` finds no unsafe default and no internal published host ports.

- [ ] **Step 8: Run pytest wrapper**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/test_compose_security.py -v
```

Expected: PASS.

- [ ] **Step 9: Commit**

Run:

```bash
git add dragon-scale-core/docker-compose.yml dragon-scale-core/.env.example dragon-scale-core/scripts/validate_compose_security.py dragon-scale-core/backend/tests/test_compose_security.py
git commit -m "fix(compose): remove unsafe defaults and internal port exposure"
```

---

### Task 4: Internal Service Token Must Be Non-Empty

**Files:**
- Modify: `dragon-scale-core/backend/api-gateway/app.py`
- Modify: `dragon-scale-core/backend/tests/test_api_gateway.py`
- Modify: `dragon-scale-core/docker-compose.yml`

- [ ] **Step 1: Add tests for missing internal token**

In `TestStatisticsEndpoint`, add:

```python
def test_fetch_downstream_stats_refuses_missing_internal_token(self, monkeypatch, _patch_redis):
    monkeypatch.delenv("INTERNAL_SERVICE_TOKEN", raising=False)
    _patch_redis.get.return_value = None

    with pytest.raises(RuntimeError, match="INTERNAL_SERVICE_TOKEN"):
        gw._fetch_downstream_stats()
```

Add:

```python
@patch("requests.get")
def test_fetch_downstream_stats_sends_non_empty_bearer(self, mock_get, monkeypatch, _patch_redis):
    monkeypatch.setenv("INTERNAL_SERVICE_TOKEN", "internal-token")
    _patch_redis.get.return_value = None
    mock_get.return_value = _mock_response(200, {})

    gw._fetch_downstream_stats()

    for call in mock_get.call_args_list:
        assert call.kwargs["headers"]["Authorization"] == "Bearer internal-token"
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/test_api_gateway.py::TestStatisticsEndpoint -v --tb=short
```

Expected: missing-token test fails because current code builds `Bearer `.

- [ ] **Step 3: Implement token getter**

In `api-gateway/app.py`, add:

```python
def _internal_service_headers():
    token = os.environ.get("INTERNAL_SERVICE_TOKEN", "").strip()
    if not token:
        raise RuntimeError("INTERNAL_SERVICE_TOKEN is required for downstream service stats")
    return {"Authorization": f"Bearer {token}"}
```

Then replace:

```python
headers = {
    "Authorization": f'Bearer {os.environ.get("INTERNAL_SERVICE_TOKEN", "")}'
}
```

with:

```python
headers = _internal_service_headers()
```

- [ ] **Step 4: Make stats route handle config error cleanly**

If `_fetch_downstream_stats()` is called from a route, catch `RuntimeError` at the route boundary and return `503`:

```python
try:
    stats = _fetch_downstream_stats()
except RuntimeError as exc:
    logger.error(str(exc))
    return jsonify({"error": "Gateway internal service token is not configured"}), 503
```

- [ ] **Step 5: Run tests**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/test_api_gateway.py -v --tb=short
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add dragon-scale-core/backend/api-gateway/app.py dragon-scale-core/backend/tests/test_api_gateway.py dragon-scale-core/docker-compose.yml
git commit -m "fix(api-gateway): require internal service token"
```

---

### Task 5: Agent Installer Trust and systemd Hardening

**Files:**
- Modify: `dragon-scale-core/agent/install.sh`
- Create: `dragon-scale-core/agent/tests/test_install_script.py`

- [ ] **Step 1: Add static installer tests**

Create `dragon-scale-core/agent/tests/test_install_script.py`:

```python
from pathlib import Path


INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"


def _script() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_installer_requires_https_server_url():
    text = _script()
    assert 'https://*' in text
    assert 'DRAGON_SCALE_API_URL' in text


def test_installer_verifies_checksum_before_chmod():
    text = _script()
    checksum_pos = text.index("sha256sum -c")
    chmod_pos = text.index('chmod 755 "$INSTALL_DIR/dragon-scale-agent"')
    assert checksum_pos < chmod_pos


def test_installer_builds_json_with_python_json_module():
    text = _script()
    assert "import json" in text
    assert "json.dump" in text
    assert "cat > \"$INSTALL_DIR/config.json\" <<EOF" not in text


def test_systemd_uses_no_new_privileges_and_capability_bounds():
    text = _script()
    assert "NoNewPrivileges=yes" in text
    assert "NoNewPrivileges=no" not in text
    assert "CapabilityBoundingSet=" in text
    assert "AmbientCapabilities=" in text
```

- [ ] **Step 2: Run installer tests and verify failure**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
python -m pytest agent/tests/test_install_script.py -v --tb=short
```

Expected: FAIL on checksum, JSON heredoc, and NoNewPrivileges assertions.

- [ ] **Step 3: Enforce HTTPS server URL**

In `parse_args()`, after required-value checks, add:

```bash
case "$DRAGON_SCALE_API_URL" in
    https://*) ;;
    *) die "--server must use https://";;
esac
```

- [ ] **Step 4: Install checksum dependency**

Change dependencies:

```bash
local deps=(curl ca-certificates coreutils python3)
```

For distros where `coreutils` and `python3` may already be installed, package managers will no-op.

- [ ] **Step 5: Verify binary checksum**

In `install_agent()`, download both binary and checksum:

```bash
local arch
arch="$(uname -m)"
local base_url="${DRAGON_SCALE_API_URL%/}/downloads/agent/${DRAGON_SCALE_VERSION}"
local binary_name="dragon-scale-agent-${arch}"
local download_url="${base_url}/${binary_name}"
local checksum_url="${download_url}.sha256"

log "Downloading agent binary from $download_url..."
curl -fsSL -o "$INSTALL_DIR/dragon-scale-agent" "$download_url" \
    || die "Failed to download agent binary. Verify --server URL and network connectivity."

log "Downloading checksum from $checksum_url..."
curl -fsSL -o "$INSTALL_DIR/dragon-scale-agent.sha256" "$checksum_url" \
    || die "Failed to download agent checksum."

(
    cd "$INSTALL_DIR"
    expected="$(cut -d' ' -f1 dragon-scale-agent.sha256)"
    printf '%s  dragon-scale-agent\n' "$expected" | sha256sum -c -
) || die "Agent checksum verification failed."
```

If cosign public-key verification is already available in release artifacts, add it after checksum verification. If not, make cosign a follow-up only after release artifacts exist; do not fake a cosign check.

- [ ] **Step 6: Generate JSON safely**

Replace the heredoc config with:

```bash
python3 - "$INSTALL_DIR/config.json" <<PY
import json
import sys

config = {
    "control_plane_url": "$DRAGON_SCALE_API_URL",
    "auth_token": "$DRAGON_SCALE_AGENT_TOKEN",
    "data_dir": "$DATA_DIR",
    "log_dir": "$LOG_DIR",
    "enable_xdp": True,
    "enable_hids": True,
    "enable_hardening": True,
    "enable_fim": True,
}

with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(config, fh, indent=2)
    fh.write("\n")
PY
```

- [ ] **Step 7: Harden systemd unit**

Change the service hardening block to:

```ini
# Security hardening for the service itself
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_RESOURCE
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_RESOURCE
ProtectSystem=strict
ReadWritePaths=$DATA_DIR $LOG_DIR /sys/fs/bpf
ProtectHome=true
PrivateTmp=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
```

If a tested kernel or distro rejects `CAP_BPF` or `CAP_PERFMON`, document the exact failure and gate those capabilities behind a distro check.

- [ ] **Step 8: Run shell syntax and static tests**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
bash -n agent/install.sh
python -m pytest agent/tests/test_install_script.py -v --tb=short
```

Expected: PASS.

- [ ] **Step 9: Commit**

Run:

```bash
git add dragon-scale-core/agent/install.sh dragon-scale-core/agent/tests/test_install_script.py
git commit -m "fix(agent): verify installer artifacts and harden systemd unit"
```

---

### Task 6: Schema Source of Truth and Fresh-DB Migrations

**Files:**
- Modify: `dragon-scale-core/init.sql`
- Modify/Create: `dragon-scale-core/backend/migrations/versions/*.py`
- Modify: `dragon-scale-core/backend/auth-service/app.py`
- Modify: `dragon-scale-core/scripts/fresh_db_check.sh`
- Modify: `.github/workflows/integration.yml` if needed

- [ ] **Step 1: Run current fresh DB migration check**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
bash scripts/fresh_db_check.sh
```

Expected before fixes: may fail or reveal idempotency gaps. Capture the exact output.

- [ ] **Step 2: Create migration for core tables**

Create a new Alembic revision after `20260313_001`, named:

```text
20260417_001_consolidate_schema.py
```

This revision must idempotently create or normalize:

```text
alerts
threats
firewall_policies
network_logs
audit_logs
training_data
rl_agent_states
system_config
```

Use SQLAlchemy inspector guards:

```python
def _has_table(bind, name: str) -> bool:
    return inspect(bind).has_table(name)


def _has_column(bind, table: str, column: str) -> bool:
    if not _has_table(bind, table):
        return False
    return any(c["name"] == column for c in inspect(bind).get_columns(table))
```

For `audit_log` singular, copy rows into `audit_logs` before dropping or leaving a compatibility view. Prefer a compatibility view during Phase 0:

```sql
CREATE OR REPLACE VIEW audit_log AS SELECT * FROM audit_logs;
```

This avoids breaking code that still reads the singular name while the app code is checked.

- [ ] **Step 3: Create migration for SSO/SCIM/MFA durability**

Create:

```text
20260417_002_sso_scim_mfa.py
```

It must create durable tables used by `auth-service/enterprise_auth.py`:

```text
saml_configs
oidc_configs
scim_tokens
mfa_challenges
```

It must add these columns to `users` if missing:

```text
mfa_secret
mfa_enabled
mfa_backup_codes
```

- [ ] **Step 4: Create migration for RLS enablement**

Create:

```text
20260417_003_enable_rls.py
```

Enable RLS for tenant-scoped tables:

```text
users
audit_logs
policy_decisions
compliance_assessments
alerts
threats
hids_events
hardening_scans
xai_explanations
```

Use policies that rely on a transaction-local tenant setting:

```sql
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_alerts ON alerts
USING (tenant_id::text = current_setting('app.current_tenant_id', true));
```

For Phase 0, keep policies permissive for service roles that do not yet set the tenant variable only if the role is explicitly named. Do not claim DB-enforced tenant isolation until all app paths set `app.current_tenant_id`.

- [ ] **Step 5: Reduce init.sql to bootstrap-only**

Change `init.sql` so it only handles:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

If a default tenant seed is still required before Alembic runs, move it into the first migration instead of `init.sql`.

- [ ] **Step 6: Remove service boot schema creation**

Find `db.create_all()` in `auth-service/app.py`. Replace boot-time schema creation with a startup assertion:

```python
def _assert_schema_ready():
    inspector = sa.inspect(db.engine)
    required = {"users", "token_blacklist", "tenants"}
    missing = sorted(required - set(inspector.get_table_names()))
    if missing:
        raise RuntimeError(
            "Database schema is not migrated. Run alembic upgrade head. "
            f"Missing tables: {', '.join(missing)}"
        )
```

Call `_assert_schema_ready()` during app initialization where `db.create_all()` currently runs. Keep test setup using `db.create_all()` inside tests.

- [ ] **Step 7: Strengthen fresh DB script**

Ensure `scripts/fresh_db_check.sh` runs:

```bash
alembic upgrade head
alembic downgrade base
alembic upgrade head
```

against an empty PostgreSQL container and exits non-zero on any command failure.

- [ ] **Step 8: Run migration checks**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
bash scripts/fresh_db_check.sh
```

Expected: PASS.

- [ ] **Step 9: Run auth tests after removing boot create_all**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/test_auth_service.py tests/test_auth_security.py -v --tb=short
```

Expected: PASS. If tests imported the app before setting SQLite config, adjust fixtures so test schema setup remains explicit.

- [ ] **Step 10: Commit**

Run:

```bash
git add dragon-scale-core/init.sql dragon-scale-core/backend/migrations dragon-scale-core/backend/auth-service/app.py dragon-scale-core/scripts/fresh_db_check.sh .github/workflows/integration.yml
git commit -m "fix(migrations): make alembic the schema source of truth"
```

---

### Task 7: Gateway CORS, Auth Proxy Headers, and Token Leakage

**Files:**
- Modify: `dragon-scale-core/backend/api-gateway/app.py`
- Modify: `dragon-scale-core/backend/tests/test_api_gateway.py`
- Modify: `dragon-scale-core/docker-compose.yml`
- Modify: `dragon-scale-core/.env.example`

- [ ] **Step 1: Add auth proxy header forwarding test**

In `TestAuthProxy`, add:

```python
@patch("requests.get")
def test_auth_get_proxy_forwards_authorization_header(self, mock_get, client):
    mock_get.return_value = _mock_response(200, {"ok": True})

    resp = client.get("/api/v1/auth/profile", headers=AUTH_HEADER)

    assert resp.status_code == 200
    assert mock_get.call_args.kwargs["headers"]["Authorization"] == "Bearer valid-token"
```

- [ ] **Step 2: Add token query stripping test**

In `TestProxyToHelper`, add:

```python
def test_proxy_strips_token_query_param(self, client):
    with gw.app.test_request_context("/test?token=secret&severity=high", method="GET"):
        with patch("requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"ok": True})
            gw._proxy_to("http://svc:5000", "/api/v1/items")
            params = mock_get.call_args.kwargs["params"]
            assert "token" not in params
            assert params["severity"] == "high"
```

- [ ] **Step 3: Add CORS explicit-origin smoke test**

Add:

```python
def test_cors_origin_is_not_wildcard(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:3000")
    assert gw._load_cors_origins() == ["http://localhost:3000"]
```

- [ ] **Step 4: Implement CORS config**

Replace `CORS(app)` with:

```python
def _load_cors_origins():
    origins = os.environ.get("CORS_ORIGINS", "").strip()
    if not origins:
        if os.environ.get("DRAGON_SCALE_ENV") == "production":
            raise RuntimeError("CORS_ORIGINS is required in production")
        return ["http://localhost:3000"]
    return [origin.strip() for origin in origins.split(",") if origin.strip()]


CORS(app, resources={r"/api/*": {"origins": _load_cors_origins()}})
```

- [ ] **Step 5: Forward Authorization in auth proxy**

Ensure auth proxy builds:

```python
headers = {"Content-Type": request.content_type or "application/json"}
if request.headers.get("Authorization"):
    headers["Authorization"] = request.headers["Authorization"]
```

for GET, POST, PUT, and DELETE.

- [ ] **Step 6: Strip token query param before downstream proxy**

In `_proxy_to()`, replace `params=request.args` with:

```python
params = request.args.to_dict(flat=True)
params.pop("token", None)
```

Pass `params=params`.

- [ ] **Step 7: Run gateway tests**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/test_api_gateway.py -v --tb=short
```

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```bash
git add dragon-scale-core/backend/api-gateway/app.py dragon-scale-core/backend/tests/test_api_gateway.py dragon-scale-core/docker-compose.yml dragon-scale-core/.env.example
git commit -m "fix(api-gateway): tighten cors and proxy token handling"
```

---

### Task 8: Container Privilege Tightening

**Files:**
- Modify: `dragon-scale-core/docker-compose.yml`
- Modify: `dragon-scale-core/scripts/validate_compose_security.py`
- Modify: `dragon-scale-core/backend/tests/test_compose_security.py`

- [ ] **Step 1: Extend compose validator for privileged containers**

Add this to `validate_compose_security.py`:

```python
PRIVILEGED_ALLOWED = {"xdp-collector", "hardening-service"}
```

Then inside the service loop:

```python
if "privileged: true" in block and name not in PRIVILEGED_ALLOWED:
    errors.append(f"unexpected privileged container: {name}")
```

- [ ] **Step 2: Run validator and verify current failures**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
python scripts/validate_compose_security.py
```

Expected before fix: fails for `data-collector` and `hids-agent` if they still use `privileged: true`.

- [ ] **Step 3: Replace broad privilege with capabilities**

For `data-collector`, replace:

```yaml
privileged: true
```

with:

```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
security_opt:
  - no-new-privileges:true
```

For `hids-agent`, replace:

```yaml
privileged: true
```

with:

```yaml
cap_add:
  - BPF
  - PERFMON
  - SYS_ADMIN
  - SYS_RESOURCE
security_opt:
  - no-new-privileges:true
```

If Docker Compose rejects `BPF` or `PERFMON` on the installed Docker version, use `SYS_ADMIN` as the compatibility fallback and document the exact Docker version in the commit body.

- [ ] **Step 4: Harden hardening-service while keeping required host write**

Add:

```yaml
security_opt:
  - no-new-privileges:true
read_only: true
tmpfs:
  - /tmp
```

Keep its explicit writable mounts:

```yaml
- /etc:/host/etc:rw
- hardening_backups:/var/lib/dragon-scale/backups
```

- [ ] **Step 5: Run compose validation**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
python scripts/validate_compose_security.py
POSTGRES_PASSWORD=x JWT_SECRET_KEY=y ADMIN_PASSWORD=z GRAFANA_PASSWORD=g INTERNAL_SERVICE_TOKEN=t docker compose config >/tmp/dragon-scale-compose-privileges.yml
```

Expected: validator PASS and compose renders.

- [ ] **Step 6: Commit**

Run:

```bash
git add dragon-scale-core/docker-compose.yml dragon-scale-core/scripts/validate_compose_security.py dragon-scale-core/backend/tests/test_compose_security.py
git commit -m "fix(compose): reduce container privileges"
```

---

### Task 9: Dockerfile Base Image Pinning

**Files:**
- Modify: `dragon-scale-core/backend/api-gateway/Dockerfile`
- Modify: `dragon-scale-core/backend/auth-service/Dockerfile`
- Modify: other service Dockerfiles only if the release process can handle mass digest updates.

- [ ] **Step 1: Identify current base image lines**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale
rg -n "^FROM python:3\\.12-slim" dragon-scale-core/backend
```

Expected: list of unpinned Python images.

- [ ] **Step 2: Pin highest-risk Dockerfiles first**

Resolve digest locally and rewrite only the selected Dockerfiles:

```bash
PYTHON_312_SLIM_DIGEST="$(
  docker buildx imagetools inspect python:3.12-slim |
  awk '/Digest:/ {print $2; exit}'
)"
test -n "$PYTHON_312_SLIM_DIGEST"
export PYTHON_312_SLIM_DIGEST

perl -0pi -e 's/^FROM python:3\.12-slim$/FROM python:3.12-slim@$ENV{PYTHON_312_SLIM_DIGEST}/m' \
  dragon-scale-core/backend/auth-service/Dockerfile \
  dragon-scale-core/backend/api-gateway/Dockerfile

rg -n "^FROM python:3\\.12-slim@" \
  dragon-scale-core/backend/auth-service/Dockerfile \
  dragon-scale-core/backend/api-gateway/Dockerfile
```

Do this at least for `auth-service` and `api-gateway`. If all service Dockerfiles share the same base and build succeeds, apply the same digest across all Python service Dockerfiles in one mechanical commit.

- [ ] **Step 3: Build pinned services**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
POSTGRES_PASSWORD=x JWT_SECRET_KEY=y ADMIN_PASSWORD=z GRAFANA_PASSWORD=g INTERNAL_SERVICE_TOKEN=t docker compose build auth-service api-gateway
```

Expected: build succeeds.

- [ ] **Step 4: Commit**

Run:

```bash
git add dragon-scale-core/backend/*/Dockerfile
git commit -m "build(docker): pin python base images by digest"
```

---

### Task 10: Final Verification and Closure Artifact

**Files:**
- Create: `dragon-scale-core/docs/reviews/phase-0-critical-fixes.md`
- Modify: `dragon-scale-core/docs/revamp/SECRETS-ROTATION-LOG.md`

- [ ] **Step 1: Run full backend unit/security slice**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/ \
  --ignore=tests/test_e2e_pipeline.py \
  -v --tb=short
```

Expected: PASS.

- [ ] **Step 2: Run frontend tests**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/frontend/admin-console
npm ci
npm run lint
npm run type-check
npm run test
```

Expected: PASS.

- [ ] **Step 3: Run migration and compose checks**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
bash scripts/fresh_db_check.sh
python scripts/validate_compose_security.py
POSTGRES_PASSWORD=x JWT_SECRET_KEY=y ADMIN_PASSWORD=z GRAFANA_PASSWORD=g INTERNAL_SERVICE_TOKEN=t docker compose config >/tmp/dragon-scale-compose-final.yml
```

Expected: PASS.

- [ ] **Step 4: Run e2e smoke stack**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
POSTGRES_PASSWORD=smoke_pg_password \
JWT_SECRET_KEY=ci-smoke-not-a-real-secret-do-not-reuse \
ADMIN_USERNAME=admin \
ADMIN_PASSWORD='Admin@123!SmokeTest' \
ADMIN_EMAIL=admin@example.com \
INTERNAL_SERVICE_TOKEN=ci-internal-token \
DRL_SHADOW_MODE=true \
docker compose up --build --abort-on-container-exit --exit-code-from db-migrate db-migrate
```

Then:

```bash
POSTGRES_PASSWORD=smoke_pg_password \
JWT_SECRET_KEY=ci-smoke-not-a-real-secret-do-not-reuse \
ADMIN_USERNAME=admin \
ADMIN_PASSWORD='Admin@123!SmokeTest' \
ADMIN_EMAIL=admin@example.com \
INTERNAL_SERVICE_TOKEN=ci-internal-token \
DRL_SHADOW_MODE=true \
docker compose up -d auth-service api-gateway ai-engine drl-engine policy-orchestrator alert-service admin-console
```

Verify:

```bash
curl -sf http://localhost:8080/health
curl -sf http://localhost:3000
docker compose down -v
```

Expected: gateway and console respond; stack tears down cleanly.

- [ ] **Step 5: Create closure artifact**

Create `dragon-scale-core/docs/reviews/phase-0-critical-fixes.md`:

```markdown
# Phase 0 Critical Fixes Closure

Date: 2026-05-07

## Closed Findings

| Finding | Status | Evidence |
|---|---|---|
| Gateway RBAC gaps | Closed | `tests/test_api_gateway.py` viewer-forbidden coverage; route decorators require admin for mutating/admin paths |
| Auth lockout ordering | Closed | `tests/test_auth_security.py` asserts locked/suspended accounts do not call `check_password` |
| Compose unsafe defaults | Closed | `scripts/validate_compose_security.py`; compose required-variable syntax |
| Agent installer trust | Closed | `agent/tests/test_install_script.py`; checksum verification before chmod |
| Agent systemd hardening | Closed | `NoNewPrivileges=yes` and bounded capabilities in installer |
| Empty internal token | Closed | `_internal_service_headers()` refuses missing token |
| Host-exposed internals | Closed | compose validator rejects internal `ports:` blocks |
| Schema drift | Closed | `scripts/fresh_db_check.sh` upgrade/downgrade/upgrade passes |

## Verification Commands

```bash
python -m pytest tests/test_auth_security.py tests/test_api_gateway.py tests/test_compose_security.py -v
bash scripts/fresh_db_check.sh
python scripts/validate_compose_security.py
```

## Remaining Follow-Ups

- Ratchet Semgrep from ERROR-only to full configured severity after Phase 0 green week.
- Replace placeholder CODEOWNERS entries with org team handles after teams exist.
- Execute the repo flatten only after seven consecutive green days on `main`.
```

- [ ] **Step 6: Update secrets rotation log**

In `dragon-scale-core/docs/revamp/SECRETS-ROTATION-LOG.md`, add a dated entry:

```markdown
## 2026-05-07 — Runtime Placeholder Removal

- Removed runtime compose fallbacks for `JWT_SECRET_KEY`, `ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `GRAFANA_PASSWORD`, and `INTERNAL_SERVICE_TOKEN`.
- Existing deployments that started from previous compose defaults must rotate all five values.
- Verification: `scripts/validate_compose_security.py` rejects known placeholder defaults and empty internal token configuration.
```

- [ ] **Step 7: Final git status**

Run:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale
git status --short
```

Expected: only intentional committed changes or a clean worktree.

- [ ] **Step 8: Commit closure docs**

Run:

```bash
git add dragon-scale-core/docs/reviews/phase-0-critical-fixes.md dragon-scale-core/docs/revamp/SECRETS-ROTATION-LOG.md
git commit -m "docs(revamp): record phase 0 critical fix evidence"
```

---

## Suggested PR Split

1. `fix(auth-service): enforce lockout before password verification`
2. `fix(api-gateway): require admin role for mutating routes`
3. `fix(compose): remove unsafe defaults and internal port exposure`
4. `fix(api-gateway): require internal service token`
5. `fix(agent): verify installer artifacts and harden systemd unit`
6. `fix(migrations): make alembic the schema source of truth`
7. `fix(api-gateway): tighten cors and proxy token handling`
8. `fix(compose): reduce container privileges`
9. `build(docker): pin python base images by digest`
10. `docs(revamp): record phase 0 critical fix evidence`

## Verification Gate Before Declaring Complete

Run these from a clean checkout after all commits:

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/backend
python -m pytest tests/ --ignore=tests/test_e2e_pipeline.py -v --tb=short
```

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core/frontend/admin-console
npm ci
npm run lint
npm run type-check
npm run test
```

```bash
cd /mnt/c/Projects/Dragon-Scale/dragon-scale/dragon-scale-core
bash scripts/fresh_db_check.sh
python scripts/validate_compose_security.py
POSTGRES_PASSWORD=x JWT_SECRET_KEY=y ADMIN_PASSWORD=z GRAFANA_PASSWORD=g INTERNAL_SERVICE_TOKEN=t docker compose config >/tmp/dragon-scale-compose-final.yml
```

Do not claim Phase 0 is complete until those commands pass and the closure artifact records the output.

## Self-Review

- Spec coverage: covers all seven critical findings from `CODE-REVIEW-main-2026-04-18.md`, the schema drift defects from `DB-MIGRATION-DRIFT-AUDIT.md`, and the highest-value secondary gateway/compose hardening items.
- Placeholder scan: the plan contains no deferred-work markers and every code-changing task has a file path, test, implementation shape, command, and expected result.
- Scope control: no FastAPI rewrite, LLM implementation, sensor swap, v2 service creation, or repo flatten is included.
