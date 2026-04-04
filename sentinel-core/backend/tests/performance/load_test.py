#!/usr/bin/env python3
"""
SENTINEL Full-Surface HTTP Load Test

Drives concurrent HTTP traffic against the API Gateway to measure throughput,
latency percentiles, and error rates across all endpoint categories.

Usage:
    python load_test.py --url http://localhost:8080 --concurrency 50 --duration 60
    python load_test.py --url http://localhost:8080 --concurrency 100 --duration 300 --ramp-up 30
    python load_test.py --url http://localhost:8080 --json --output results.json
"""
import argparse
import json
import math
import os
import random
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Event, Lock
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class LoadTestConfig:
    target_url: str = "http://localhost:8080"
    auth_url: str = ""
    concurrency: int = 50
    duration: int = 60
    ramp_up: int = 10
    admin_user: str = os.getenv("ADMIN_USER", "admin")
    admin_pass: str = os.getenv("ADMIN_PASS", "ChangeMe!2026")
    timeout: int = 30


# ---------------------------------------------------------------------------
# Metrics collection
# ---------------------------------------------------------------------------

@dataclass
class EndpointMetrics:
    name: str
    latencies: List[float] = field(default_factory=list)
    errors: int = 0
    successes: int = 0
    status_codes: Dict[int, int] = field(default_factory=dict)


class MetricsCollector:
    """Thread-safe aggregation of per-request metrics."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._endpoints: Dict[str, EndpointMetrics] = {}
        self._start_time: float = 0.0
        self._end_time: float = 0.0
        self._total_bytes: int = 0

    def start(self) -> None:
        self._start_time = time.monotonic()

    def stop(self) -> None:
        self._end_time = time.monotonic()

    def record(
        self,
        endpoint: str,
        latency_ms: float,
        status_code: int,
        response_bytes: int,
        is_error: bool,
    ) -> None:
        with self._lock:
            if endpoint not in self._endpoints:
                self._endpoints[endpoint] = EndpointMetrics(name=endpoint)
            m = self._endpoints[endpoint]
            m.latencies.append(latency_ms)
            m.status_codes[status_code] = m.status_codes.get(status_code, 0) + 1
            if is_error:
                m.errors += 1
            else:
                m.successes += 1
            self._total_bytes += response_bytes

    def report(self) -> Dict[str, Any]:
        elapsed = max(self._end_time - self._start_time, 0.001)
        all_latencies: List[float] = []
        total_requests = 0
        total_errors = 0

        endpoint_reports = {}
        for name, m in sorted(self._endpoints.items()):
            total_requests += m.successes + m.errors
            total_errors += m.errors
            all_latencies.extend(m.latencies)
            endpoint_reports[name] = _percentile_report(m)

        global_report = {
            "total_requests": total_requests,
            "total_errors": total_errors,
            "error_rate_pct": round(total_errors / max(total_requests, 1) * 100, 3),
            "requests_per_sec": round(total_requests / elapsed, 2),
            "throughput_mbps": round(self._total_bytes / elapsed / 1024 / 1024, 3),
            "elapsed_seconds": round(elapsed, 2),
        }

        if all_latencies:
            all_latencies.sort()
            global_report["latency_ms"] = {
                "min": round(all_latencies[0], 2),
                "p50": round(_percentile(all_latencies, 50), 2),
                "p95": round(_percentile(all_latencies, 95), 2),
                "p99": round(_percentile(all_latencies, 99), 2),
                "max": round(all_latencies[-1], 2),
                "mean": round(statistics.mean(all_latencies), 2),
                "stdev": round(statistics.stdev(all_latencies), 2) if len(all_latencies) > 1 else 0.0,
            }

        global_report["endpoints"] = endpoint_reports
        return global_report


def _percentile(sorted_data: List[float], pct: float) -> float:
    if not sorted_data:
        return 0.0
    idx = (pct / 100) * (len(sorted_data) - 1)
    lower = int(math.floor(idx))
    upper = min(lower + 1, len(sorted_data) - 1)
    weight = idx - lower
    return sorted_data[lower] * (1 - weight) + sorted_data[upper] * weight


def _percentile_report(m: EndpointMetrics) -> Dict[str, Any]:
    total = m.successes + m.errors
    latencies = sorted(m.latencies)
    report: Dict[str, Any] = {
        "total": total,
        "successes": m.successes,
        "errors": m.errors,
        "error_rate_pct": round(m.errors / max(total, 1) * 100, 3),
        "status_codes": m.status_codes,
    }
    if latencies:
        report["latency_ms"] = {
            "min": round(latencies[0], 2),
            "p50": round(_percentile(latencies, 50), 2),
            "p95": round(_percentile(latencies, 95), 2),
            "p99": round(_percentile(latencies, 99), 2),
            "max": round(latencies[-1], 2),
        }
    return report


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------

class LoadTestScenarios:
    """Generates randomised API calls against each endpoint category."""

    def __init__(self, cfg: LoadTestConfig, token: str) -> None:
        self._cfg = cfg
        self._headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        self._base = cfg.target_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update(self._headers)

    def _get(self, path: str) -> Tuple[float, int, int]:
        url = f"{self._base}{path}"
        start = time.monotonic()
        resp = self._session.get(url, timeout=self._cfg.timeout)
        latency = (time.monotonic() - start) * 1000
        return latency, resp.status_code, len(resp.content)

    def _post(self, path: str, payload: Any = None) -> Tuple[float, int, int]:
        url = f"{self._base}{path}"
        start = time.monotonic()
        resp = self._session.post(url, json=payload, timeout=self._cfg.timeout)
        latency = (time.monotonic() - start) * 1000
        return latency, resp.status_code, len(resp.content)

    def _put(self, path: str, payload: Any = None) -> Tuple[float, int, int]:
        url = f"{self._base}{path}"
        start = time.monotonic()
        resp = self._session.put(url, json=payload, timeout=self._cfg.timeout)
        latency = (time.monotonic() - start) * 1000
        return latency, resp.status_code, len(resp.content)

    # -- scenario runners --

    def health_check(self) -> Tuple[str, float, int, int]:
        lat, sc, sz = self._get("/health")
        return "health", lat, sc, sz

    def auth_verify(self) -> Tuple[str, float, int, int]:
        lat, sc, sz = self._post("/api/v1/auth/verify")
        return "auth_verify", lat, sc, sz

    def list_threats(self) -> Tuple[str, float, int, int]:
        lat, sc, sz = self._get("/api/v1/threats")
        return "threats_list", lat, sc, sz

    def detect_single(self) -> Tuple[str, float, int, int]:
        payload = {
            "traffic_data": {
                "src_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "dst_ip": "10.0.0.1",
                "dst_port": random.choice([22, 80, 443, 3306, 8080]),
                "protocol": random.choice(["TCP", "UDP"]),
                "bytes_sent": random.randint(64, 65535),
                "bytes_recv": random.randint(64, 65535),
                "duration_ms": random.randint(1, 30000),
                "packets": random.randint(1, 500),
            }
        }
        lat, sc, sz = self._post("/api/v1/detect", payload)
        return "detect_single", lat, sc, sz

    def detect_batch(self) -> Tuple[str, float, int, int]:
        batch = [
            {
                "src_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "dst_port": random.choice([22, 80, 443]),
                "protocol": "TCP",
                "bytes_sent": random.randint(64, 65535),
                "packets": random.randint(1, 500),
            }
            for _ in range(10)
        ]
        lat, sc, sz = self._post("/api/v1/detect/batch", {"traffic_batch": batch})
        return "detect_batch", lat, sc, sz

    def list_policies(self) -> Tuple[str, float, int, int]:
        lat, sc, sz = self._get("/api/v1/policies")
        return "policies_list", lat, sc, sz

    def create_policy(self) -> Tuple[str, float, int, int]:
        payload = {
            "name": f"loadtest-{random.randint(1000, 9999)}",
            "action": random.choice(["ALLOW", "DENY", "RATE_LIMIT"]),
            "source": f"10.0.{random.randint(0, 255)}.0/24",
            "destination": "10.0.0.0/8",
            "protocol": "TCP",
            "port": random.randint(1, 65535),
        }
        lat, sc, sz = self._post("/api/v1/policies", payload)
        return "policies_create", lat, sc, sz

    def list_alerts(self) -> Tuple[str, float, int, int]:
        lat, sc, sz = self._get("/api/v1/alerts?limit=20")
        return "alerts_list", lat, sc, sz

    def create_alert(self) -> Tuple[str, float, int, int]:
        payload = {
            "type": random.choice([
                "network_anomaly", "brute_force", "malware_detected", "unauthorized_access",
            ]),
            "severity": random.choice(["low", "medium", "high", "critical"]),
            "description": f"Load test alert {random.randint(1, 99999)}",
            "source": "load_test",
        }
        lat, sc, sz = self._post("/api/v1/alerts", payload)
        return "alerts_create", lat, sc, sz

    def compliance_frameworks(self) -> Tuple[str, float, int, int]:
        lat, sc, sz = self._get("/api/v1/frameworks")
        return "compliance_frameworks", lat, sc, sz

    def compliance_assess(self) -> Tuple[str, float, int, int]:
        payload = {
            "framework": random.choice(["NIST", "GDPR", "HIPAA", "PCI-DSS", "SOC2"]),
            "policies": [],
            "configurations": {},
        }
        lat, sc, sz = self._post("/api/v1/assess", payload)
        return "compliance_assess", lat, sc, sz

    def statistics(self) -> Tuple[str, float, int, int]:
        lat, sc, sz = self._get("/api/v1/stats")
        return "statistics", lat, sc, sz

    def drl_decide(self) -> Tuple[str, float, int, int]:
        payload = {
            "detection_id": f"det_{random.randint(10000, 99999)}",
            "threat_score": round(random.uniform(0.1, 1.0), 2),
            "threat_type": random.choice(["brute_force", "port_scan", "malware"]),
            "source_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "dest_ip": "10.0.0.1",
            "dest_port": random.choice([22, 80, 443]),
            "protocol": "TCP",
            "asset_criticality": random.randint(1, 5),
        }
        lat, sc, sz = self._post("/api/v1/decide", payload)
        return "drl_decide", lat, sc, sz

    def xai_explain(self) -> Tuple[str, float, int, int]:
        payload = {
            "detection_id": f"det_{random.randint(10000, 99999)}",
            "features": {"bytes_sent": 5000, "packets": 200},
            "prediction": {"confidence": 0.92, "is_threat": True},
            "model_verdicts": {
                "xgboost": {"is_threat": True, "confidence": 0.94},
                "lstm": {"is_threat": True, "confidence": 0.88},
            },
        }
        lat, sc, sz = self._post("/api/v1/explain/detection", payload)
        return "xai_explain", lat, sc, sz

    def get_scenario_pool(self) -> List[Callable]:
        """Weighted scenario pool reflecting realistic traffic patterns."""
        return (
            [self.health_check] * 5
            + [self.list_threats] * 10
            + [self.list_alerts] * 10
            + [self.statistics] * 8
            + [self.list_policies] * 5
            + [self.detect_single] * 15
            + [self.detect_batch] * 5
            + [self.create_alert] * 5
            + [self.create_policy] * 3
            + [self.compliance_frameworks] * 4
            + [self.compliance_assess] * 3
            + [self.drl_decide] * 8
            + [self.xai_explain] * 4
            + [self.auth_verify] * 5
        )


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def _authenticate(cfg: LoadTestConfig) -> str:
    """Obtain a JWT token from the auth service."""
    auth_base = cfg.auth_url or cfg.target_url
    url = f"{auth_base.rstrip('/')}/api/v1/auth/login"
    try:
        resp = requests.post(
            url,
            json={"username": cfg.admin_user, "password": cfg.admin_pass},
            timeout=cfg.timeout,
        )
        if resp.status_code == 200:
            return resp.json().get("access_token", "")
    except requests.RequestException as exc:
        print(f"[WARN] Authentication failed: {exc}", file=sys.stderr)
    return ""


def run_load_test(cfg: LoadTestConfig) -> Dict[str, Any]:
    """Execute the load test and return a report dict."""
    print(f"Authenticating against {cfg.auth_url or cfg.target_url} ...")
    token = _authenticate(cfg)
    if not token:
        print("[WARN] No auth token obtained; authenticated endpoints will return 401")

    collector = MetricsCollector()
    stop_event = Event()

    scenarios = LoadTestScenarios(cfg, token)
    pool = scenarios.get_scenario_pool()

    def worker(worker_id: int) -> None:
        while not stop_event.is_set():
            scenario = random.choice(pool)
            try:
                name, latency, status, size = scenario()
                is_error = status >= 400
                collector.record(name, latency, status, size, is_error)
            except requests.RequestException as exc:
                collector.record(
                    scenario.__name__ if hasattr(scenario, "__name__") else "unknown",
                    0.0, 0, 0, True,
                )

    collector.start()

    print(
        f"Starting load test: {cfg.concurrency} VUs, "
        f"{cfg.duration}s duration, {cfg.ramp_up}s ramp-up"
    )

    with ThreadPoolExecutor(max_workers=cfg.concurrency) as executor:
        futures = []

        ramp_step = max(cfg.ramp_up / max(cfg.concurrency, 1), 0.01)
        for i in range(cfg.concurrency):
            if cfg.ramp_up > 0 and i > 0:
                time.sleep(ramp_step)
            futures.append(executor.submit(worker, i))

        try:
            remaining = max(cfg.duration - cfg.ramp_up, 0)
            time.sleep(remaining)
        except KeyboardInterrupt:
            print("\nInterrupted -- collecting results ...")
        finally:
            stop_event.set()

        for f in as_completed(futures, timeout=cfg.timeout):
            pass

    collector.stop()
    report = collector.report()
    report["config"] = {
        "target_url": cfg.target_url,
        "concurrency": cfg.concurrency,
        "duration": cfg.duration,
        "ramp_up": cfg.ramp_up,
    }
    return report


def _print_report(report: Dict[str, Any]) -> None:
    lat = report.get("latency_ms", {})
    print("\n" + "=" * 70)
    print("SENTINEL Load Test Results")
    print("=" * 70)
    print(f"  Target:          {report['config']['target_url']}")
    print(f"  Concurrency:     {report['config']['concurrency']} VUs")
    print(f"  Duration:        {report['elapsed_seconds']}s")
    print(f"  Total requests:  {report['total_requests']}")
    print(f"  Requests/sec:    {report['requests_per_sec']}")
    print(f"  Error rate:      {report['error_rate_pct']}%")
    print(f"  Throughput:      {report['throughput_mbps']} MB/s")
    if lat:
        print(f"  Latency p50:     {lat['p50']}ms")
        print(f"  Latency p95:     {lat['p95']}ms")
        print(f"  Latency p99:     {lat['p99']}ms")
        print(f"  Latency max:     {lat['max']}ms")
    print("-" * 70)
    print(f"  {'Endpoint':<25} {'Reqs':>6} {'Err%':>7} {'p50':>8} {'p95':>8} {'p99':>8}")
    print("-" * 70)
    for name, ep in sorted(report.get("endpoints", {}).items()):
        ep_lat = ep.get("latency_ms", {})
        print(
            f"  {name:<25} {ep['total']:>6} "
            f"{ep['error_rate_pct']:>6.1f}% "
            f"{ep_lat.get('p50', 0):>7.1f} "
            f"{ep_lat.get('p95', 0):>7.1f} "
            f"{ep_lat.get('p99', 0):>7.1f}"
        )
    print("=" * 70)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL HTTP Load Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", default=os.getenv("BASE_URL", "http://localhost:8080"),
                        help="API Gateway base URL")
    parser.add_argument("--auth-url", default=os.getenv("AUTH_URL", ""),
                        help="Auth service URL (defaults to --url)")
    parser.add_argument("--concurrency", type=int, default=50,
                        help="Number of concurrent virtual users")
    parser.add_argument("--duration", type=int, default=60,
                        help="Test duration in seconds")
    parser.add_argument("--ramp-up", type=int, default=10,
                        help="Ramp-up period in seconds")
    parser.add_argument("--user", default=os.getenv("ADMIN_USER", "admin"))
    parser.add_argument("--password", default=os.getenv("ADMIN_PASS", "ChangeMe!2026"))
    parser.add_argument("--json", action="store_true", help="Output raw JSON to stdout")
    parser.add_argument("--output", default="", help="Write JSON report to file")

    args = parser.parse_args()

    cfg = LoadTestConfig(
        target_url=args.url,
        auth_url=args.auth_url,
        concurrency=args.concurrency,
        duration=args.duration,
        ramp_up=args.ramp_up,
        admin_user=args.user,
        admin_pass=args.password,
    )

    report = run_load_test(cfg)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.output}")

    p95 = report.get("latency_ms", {}).get("p95", 0)
    err = report.get("error_rate_pct", 0)
    if p95 > 500 or err > 1.0:
        sys.exit(1)


if __name__ == "__main__":
    main()
