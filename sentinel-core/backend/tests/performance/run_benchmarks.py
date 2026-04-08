#!/usr/bin/env python3
"""
SENTINEL Consolidated Benchmark Runner

Runs all performance benchmarks and produces a JSON report.

Usage:
    python run_benchmarks.py [--k6-path k6] [--output report.json]
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent

PERFORMANCE_TARGETS = {
    "api_gateway": {"metric": "p95_ms", "target": 200, "unit": "ms"},
    "ai_engine": {"metric": "p95_ms", "target": 100, "unit": "ms"},
    "drl_engine": {"metric": "p95_ms", "target": 50, "unit": "ms"},
    "kafka": {"metric": "throughput_eps", "target": 50000, "unit": "events/sec"},
    "xdp": {"metric": "pps", "target": 100000, "unit": "packets/sec"},
}


def _run_k6(script: str, k6_path: str, env: dict) -> dict | None:
    cmd = [k6_path, "run", "--quiet", "--out", "json=/dev/null", str(SCRIPT_DIR / script)]
    full_env = {**os.environ, **env}
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=full_env)
        output = result.stdout + result.stderr
        metrics = {}
        for line in output.splitlines():
            if "http_req_duration" in line and "p(95)" in line:
                parts = line.split()
                for p in parts:
                    try:
                        val = float(p.replace("ms", "").replace("s", ""))
                        metrics["p95_ms"] = val
                        break
                    except ValueError:
                        continue
            if "checks" in line:
                for p in line.split():
                    if "%" in p:
                        try:
                            metrics["check_pass_pct"] = float(p.replace("%", ""))
                        except ValueError:
                            pass
        return {
            "exit_code": result.returncode,
            "metrics": metrics,
            "raw_summary": output[-2000:] if len(output) > 2000 else output,
        }
    except FileNotFoundError:
        return {"error": f"k6 not found at {k6_path}", "skip": True}
    except subprocess.TimeoutExpired:
        return {"error": "k6 timed out after 300s"}


def _run_python_bench(script: str, extra_args: list[str]) -> dict | None:
    cmd = [sys.executable, str(SCRIPT_DIR / script), "--json"] + extra_args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return json.loads(result.stdout)
        return {"error": result.stderr[-500:], "exit_code": result.returncode}
    except Exception as e:
        return {"error": str(e)}


def run_all(k6_path: str, base_url: str, auth_url: str,
            kafka_broker: str, xdp_url: str) -> dict:
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "targets": PERFORMANCE_TARGETS,
        "results": {},
    }

    k6_env = {"BASE_URL": base_url, "AUTH_URL": auth_url}

    print("[1/5] API Gateway benchmark...")
    report["results"]["api_gateway"] = _run_k6("k6_api_gateway.js", k6_path, k6_env)

    print("[2/5] AI Engine benchmark...")
    ai_env = {**k6_env, "BASE_URL": os.getenv("AI_ENGINE_URL", "http://localhost:5003")}
    report["results"]["ai_engine"] = _run_k6("k6_ai_engine.js", k6_path, ai_env)

    print("[3/5] DRL Engine benchmark...")
    drl_env = {**k6_env, "BASE_URL": os.getenv("DRL_ENGINE_URL", "http://localhost:5005")}
    report["results"]["drl_engine"] = _run_k6("k6_drl_engine.js", k6_path, drl_env)

    print("[4/5] Kafka throughput benchmark...")
    report["results"]["kafka"] = _run_python_bench(
        "benchmark_kafka.py", ["--broker", kafka_broker]
    )

    print("[5/5] XDP collector benchmark...")
    report["results"]["xdp"] = _run_python_bench(
        "benchmark_xdp.py", ["--url", xdp_url, "--duration", "15"]
    )

    passed = 0
    total = 0
    for name, result in report["results"].items():
        if result and not result.get("skip") and not result.get("error"):
            total += 1
            if result.get("pass") or result.get("metrics", {}).get("p95_ms", 999) < \
                    PERFORMANCE_TARGETS.get(name, {}).get("target", 999):
                passed += 1

    report["summary"] = {
        "total": total,
        "passed": passed,
        "failed": total - passed,
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="SENTINEL benchmark runner")
    parser.add_argument("--k6-path", default=os.getenv("K6_PATH", "k6"))
    parser.add_argument("--base-url", default=os.getenv("BASE_URL", "http://localhost:8080"))
    parser.add_argument("--auth-url", default=os.getenv("AUTH_URL", "http://localhost:5000"))
    parser.add_argument("--kafka-broker", default=os.getenv("KAFKA_BROKER", "localhost:9092"))
    parser.add_argument("--xdp-url", default=os.getenv("XDP_URL", "http://localhost:5010"))
    parser.add_argument("--output", default="benchmark_report.json")
    args = parser.parse_args()

    report = run_all(
        k6_path=args.k6_path,
        base_url=args.base_url,
        auth_url=args.auth_url,
        kafka_broker=args.kafka_broker,
        xdp_url=args.xdp_url,
    )

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to {args.output}")

    print(f"\nResults: {report['summary']['passed']}/{report['summary']['total']} passed")
    for name, result in report["results"].items():
        if result:
            status = "SKIP" if result.get("skip") else ("PASS" if result.get("pass") else "FAIL")
            target = PERFORMANCE_TARGETS.get(name, {})
            print(f"  {name:20s} {status:6s}  target={target.get('target','?')} {target.get('unit','')}")


if __name__ == "__main__":
    main()
