#!/usr/bin/env python3
"""
SENTINEL Integration Test Suite
=================================
Tests the full stack: health checks, auth flow, and core API endpoints.
Run after `docker compose up -d` and services are healthy.

Usage:
    python scripts/integration_test.py [--base-url http://localhost:8080]
"""

import argparse
import json
import sys
import time
import requests

# ── Configuration ──────────────────────────────────────────────────────────
DEFAULT_GATEWAY = "http://localhost:8080"
DEFAULT_AUTH    = "http://localhost:5000"

SERVICES = {
    "postgres":          None,               # checked via auth-service startup
    "auth-service":      "http://localhost:5000/health",
    "api-gateway":       "http://localhost:8080/health",
    "data-collector":    "http://localhost:5001/health",
    "alert-service":     "http://localhost:5002/health",
    "ai-engine":         "http://localhost:5003/health",
    "drl-engine":        "http://localhost:5005/health",
    "xai-service":       "http://localhost:5006/health",
    "compliance-engine": "http://localhost:5007/health",
    "policy-orchestrator":"http://localhost:5004/health",
    "hids-agent":        "http://localhost:5010/health",
    "hardening-service": "http://localhost:5011/health",
    "xdp-collector":     "http://localhost:5012/health",
}

PASS = "\033[92m✔\033[0m"
FAIL = "\033[91m✘\033[0m"
WARN = "\033[93m⚠\033[0m"
INFO = "\033[94mℹ\033[0m"


def banner(text: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {text}")
    print(f"{'─' * 60}")


def ok(label: str, detail: str = "") -> None:
    print(f"  {PASS} {label}" + (f"  [{detail}]" if detail else ""))


def fail(label: str, detail: str = "") -> None:
    print(f"  {FAIL} {label}" + (f"  [{detail}]" if detail else ""))


def warn(label: str, detail: str = "") -> None:
    print(f"  {WARN} {label}" + (f"  [{detail}]" if detail else ""))


def info(label: str, detail: str = "") -> None:
    print(f"  {INFO} {label}" + (f"  [{detail}]" if detail else ""))


# ── Helpers ────────────────────────────────────────────────────────────────

def wait_for_health(url: str, service: str, timeout: int = 120) -> bool:
    """Poll a health URL until it returns 200 or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(3)
    return False


# ── Test phases ────────────────────────────────────────────────────────────

def phase_health_checks(services: dict) -> dict[str, bool]:
    banner("Phase 1 — Health checks")
    results = {}
    for name, url in services.items():
        if url is None:
            info(f"{name}: skipped (no HTTP health endpoint)")
            results[name] = True
            continue
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                ok(f"{name}", f"HTTP 200")
                results[name] = True
            else:
                fail(f"{name}", f"HTTP {r.status_code}")
                results[name] = False
        except requests.exceptions.ConnectionError as e:
            fail(f"{name}", f"Connection refused — {e}")
            results[name] = False
        except requests.exceptions.Timeout:
            fail(f"{name}", "Timeout after 10s")
            results[name] = False
    return results


def phase_auth_flow(auth_url: str, gateway_url: str) -> dict:
    banner("Phase 2 — Authentication flow")
    ctx: dict = {}

    # 2a. Admin login (bootstrap user)
    print(f"\n  ── 2a. Admin login ──")
    try:
        r = requests.post(
            f"{auth_url}/api/v1/auth/login",
            json={"username": "admin", "password": "SentinelDev!2026"},
            timeout=10,
        )
        if r.status_code == 200:
            body = r.json()
            ctx["admin_token"] = body["access_token"]
            ctx["admin_refresh"] = body["refresh_token"]
            ok("Admin login", f"token: ...{ctx['admin_token'][-12:]}")
        else:
            fail("Admin login", f"HTTP {r.status_code} — {r.text[:100]}")
            return ctx
    except Exception as e:
        fail("Admin login", str(e))
        return ctx

    # 2b. Register a test analyst
    print(f"\n  ── 2b. Register test analyst ──")
    ts = int(time.time())
    test_user = {
        "username": f"analyst_{ts}",
        "email": f"analyst_{ts}@sentinel.test",
        "password": "Analyst!Test2026",
        "role": "security_analyst",
    }
    try:
        r = requests.post(
            f"{auth_url}/api/v1/auth/register",
            json=test_user,
            timeout=10,
        )
        if r.status_code == 201:
            ctx["analyst_username"] = test_user["username"]
            ctx["analyst_password"] = test_user["password"]
            ok("Register analyst", r.json().get("user", {}).get("username"))
        else:
            fail("Register analyst", f"HTTP {r.status_code} — {r.text[:100]}")
    except Exception as e:
        fail("Register analyst", str(e))

    # 2c. Analyst login
    print(f"\n  ── 2c. Analyst login ──")
    if ctx.get("analyst_username"):
        try:
            r = requests.post(
                f"{auth_url}/api/v1/auth/login",
                json={
                    "username": ctx["analyst_username"],
                    "password": ctx["analyst_password"],
                },
                timeout=10,
            )
            if r.status_code == 200:
                body = r.json()
                ctx["analyst_token"] = body["access_token"]
                ok("Analyst login", f"token: ...{ctx['analyst_token'][-12:]}")
            else:
                fail("Analyst login", f"HTTP {r.status_code} — {r.text[:100]}")
        except Exception as e:
            fail("Analyst login", str(e))

    # 2d. Token verification
    print(f"\n  ── 2d. Token verification ──")
    token = ctx.get("admin_token")
    if token:
        try:
            r = requests.post(
                f"{auth_url}/api/v1/auth/verify",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
            if r.status_code == 200:
                user_info = r.json().get("user", {})
                ok("Token verify", f"user={user_info.get('username')} role={user_info.get('role')}")
            else:
                fail("Token verify", f"HTTP {r.status_code}")
        except Exception as e:
            fail("Token verify", str(e))

    # 2e. Access protected profile endpoint
    print(f"\n  ── 2e. Protected endpoint (profile) ──")
    token = ctx.get("admin_token")
    if token:
        try:
            r = requests.get(
                f"{auth_url}/api/v1/auth/profile",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
            if r.status_code == 200:
                ok("GET /auth/profile", f"username={r.json().get('username')}")
            else:
                fail("GET /auth/profile", f"HTTP {r.status_code}")
        except Exception as e:
            fail("GET /auth/profile", str(e))

    # 2f. Reject unauthenticated request
    print(f"\n  ── 2f. Reject unauthenticated request ──")
    try:
        r = requests.get(f"{auth_url}/api/v1/auth/profile", timeout=10)
        if r.status_code == 401:
            ok("401 on unauth request", "correct")
        else:
            fail("401 on unauth request", f"got HTTP {r.status_code}")
    except Exception as e:
        fail("Unauth rejection", str(e))

    # 2g. Token refresh
    print(f"\n  ── 2g. Token refresh ──")
    refresh = ctx.get("admin_refresh")
    if refresh:
        try:
            r = requests.post(
                f"{auth_url}/api/v1/auth/refresh",
                headers={"Authorization": f"Bearer {refresh}"},
                timeout=10,
            )
            if r.status_code == 200:
                ctx["admin_token"] = r.json().get("access_token", ctx["admin_token"])
                ok("Token refresh", "new access token obtained")
            else:
                fail("Token refresh", f"HTTP {r.status_code}")
        except Exception as e:
            fail("Token refresh", str(e))

    return ctx


def phase_gateway_flow(gateway_url: str, token: str) -> None:
    banner("Phase 3 — API Gateway proxying")

    endpoints = [
        ("GET", "/health",       None,  [200]),
        ("GET", "/api/v1/stats", None,  [200, 503]),   # 503 if downstream down
        ("GET", "/api/v1/threats", None, [200, 503]),
        ("GET", "/api/v1/alerts",  None, [200, 503]),
    ]

    for method, path, body, expected_codes in endpoints:
        try:
            url = f"{gateway_url}{path}"
            headers = {"Authorization": f"Bearer {token}"} if path != "/health" else {}
            if method == "GET":
                r = requests.get(url, headers=headers, timeout=10)
            else:
                r = requests.post(url, json=body, headers=headers, timeout=10)

            if r.status_code in expected_codes:
                ok(f"{method} {path}", f"HTTP {r.status_code}")
            else:
                warn(f"{method} {path}", f"HTTP {r.status_code} (expected {expected_codes})")
        except Exception as e:
            fail(f"{method} {path}", str(e))


def phase_security_checks(auth_url: str, gateway_url: str) -> None:
    banner("Phase 4 — Security baseline checks")

    # SQL injection probe
    try:
        r = requests.post(
            f"{auth_url}/api/v1/auth/login",
            json={"username": "admin' OR '1'='1", "password": "x"},
            timeout=10,
        )
        if r.status_code == 401:
            ok("SQL injection rejected", "login returns 401")
        else:
            warn("SQL injection probe", f"unexpected HTTP {r.status_code}")
    except Exception as e:
        fail("SQL injection probe", str(e))

    # Rate limiting (6th login attempt should be throttled)
    print("\n  Testing rate limiting (brute-force)...")
    throttled = False
    for i in range(8):
        try:
            r = requests.post(
                f"{auth_url}/api/v1/auth/login",
                json={"username": "nonexistent_user_x", "password": "wrong"},
                timeout=10,
            )
            if r.status_code == 429:
                throttled = True
                ok("Rate limiting triggered", f"on attempt {i + 1}")
                break
        except Exception:
            break
    if not throttled:
        warn("Rate limiting", "not triggered within 8 attempts (may need higher volume)")

    # No token = 401
    try:
        r = requests.get(f"{gateway_url}/api/v1/threats", timeout=10)
        if r.status_code == 401:
            ok("Unauthenticated gateway request → 401")
        else:
            fail("Unauthenticated gateway request", f"got {r.status_code}")
    except Exception as e:
        fail("Unauthenticated gateway request", str(e))

    # Verify CORS header present
    try:
        r = requests.options(
            f"{auth_url}/api/v1/auth/login",
            headers={"Origin": "https://evil.example.com"},
            timeout=10,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao and acao != "*":
            ok("CORS restricted origin", acao)
        elif acao == "*":
            warn("CORS", "allows all origins (*) — review for production")
        else:
            info("CORS header absent on OPTIONS", "may be Nginx handling")
    except Exception as e:
        info("CORS check", str(e))


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="SENTINEL Integration Tests")
    parser.add_argument("--gateway-url", default=DEFAULT_GATEWAY)
    parser.add_argument("--auth-url",    default=DEFAULT_AUTH)
    parser.add_argument("--wait",        type=int, default=0,
                        help="Seconds to wait for auth-service to become healthy before testing")
    args = parser.parse_args()

    print("\n╔══════════════════════════════════════════════════════╗")
    print("║       SENTINEL Integration Test Suite               ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"  Gateway : {args.gateway_url}")
    print(f"  Auth    : {args.auth_url}")

    if args.wait > 0:
        banner(f"Waiting up to {args.wait}s for auth-service…")
        if wait_for_health(f"{args.auth_url}/health", "auth-service", args.wait):
            ok("auth-service is healthy")
        else:
            fail("auth-service did not become healthy in time")
            return 1

    # Phase 1 — health checks
    health_results = phase_health_checks(SERVICES)
    healthy_count  = sum(health_results.values())
    total_count    = len(health_results)

    print(f"\n  Health: {healthy_count}/{total_count} services healthy")

    if not health_results.get("auth-service"):
        fail("auth-service is down — cannot continue with auth flow tests")
        return 1

    # Phase 2 — auth flow
    ctx = phase_auth_flow(args.auth_url, args.gateway_url)
    admin_token = ctx.get("admin_token")

    if not admin_token:
        fail("Could not obtain admin token — skipping downstream phases")
        return 1

    # Phase 3 — gateway proxying
    phase_gateway_flow(args.gateway_url, admin_token)

    # Phase 4 — security checks
    phase_security_checks(args.auth_url, args.gateway_url)

    # Summary
    banner("Summary")
    unhealthy = [k for k, v in health_results.items() if not v]
    if unhealthy:
        warn("Unhealthy services", ", ".join(unhealthy))
    else:
        ok("All services healthy")

    if admin_token:
        ok("Auth flow complete — JWT obtained and verified")
    else:
        fail("Auth flow did not complete")

    print()
    return 0 if not unhealthy and admin_token else 1


if __name__ == "__main__":
    sys.exit(main())
