#!/usr/bin/env python3
"""
SENTINEL XDP Collector Performance Benchmark

Target: 100k pps packet processing, < 5μs per-packet overhead

Usage:
    python benchmark_xdp.py --url http://localhost:5010 --duration 30
"""
import argparse
import json
import os
import time

import requests


def run_benchmark(base_url: str, duration_sec: int):
    session = requests.Session()

    health = session.get(f"{base_url}/health", timeout=5)
    if health.status_code != 200:
        print(f"ERROR: XDP collector not healthy: {health.status_code}")
        return None

    config_resp = session.get(f"{base_url}/api/v1/xdp/config", timeout=5)
    xdp_config = config_resp.json() if config_resp.status_code == 200 else {}

    metrics_before = session.get(f"{base_url}/api/v1/xdp/metrics", timeout=5)
    if metrics_before.status_code != 200:
        print("ERROR: Cannot read XDP metrics")
        return None
    before = metrics_before.json()

    print(f"Collecting metrics for {duration_sec}s...")
    time.sleep(duration_sec)

    metrics_after = session.get(f"{base_url}/api/v1/xdp/metrics", timeout=5)
    if metrics_after.status_code != 200:
        print("ERROR: Cannot read XDP metrics after wait")
        return None
    after = metrics_after.json()

    pkts_before = before.get("packets_processed", before.get("total_packets", 0))
    pkts_after = after.get("packets_processed", after.get("total_packets", 0))
    dropped_before = before.get("packets_dropped", 0)
    dropped_after = after.get("packets_dropped", 0)

    pkts_delta = pkts_after - pkts_before
    dropped_delta = dropped_after - dropped_before
    pps = pkts_delta / duration_sec if duration_sec > 0 else 0
    drop_rate = dropped_delta / max(pkts_delta, 1)

    ns_per_pkt_raw = after.get("avg_processing_ns", 0)
    us_per_pkt = ns_per_pkt_raw / 1000 if ns_per_pkt_raw else (1_000_000 / max(pps, 1))

    results = {
        "duration_sec": duration_sec,
        "packets_processed": pkts_delta,
        "packets_dropped": dropped_delta,
        "pps": round(pps, 1),
        "drop_rate": round(drop_rate, 6),
        "us_per_packet": round(us_per_pkt, 3),
        "xdp_config": xdp_config,
        "pass": pps >= 100000 and us_per_pkt < 5,
    }
    return results


def main():
    parser = argparse.ArgumentParser(description="XDP collector benchmark")
    parser.add_argument("--url", default=os.getenv("XDP_URL", "http://localhost:5010"))
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    results = run_benchmark(args.url, args.duration)
    if results is None:
        return

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{'='*50}")
        print(f"Duration:        {results['duration_sec']}s")
        print(f"Packets:         {results['packets_processed']}")
        print(f"PPS:             {results['pps']}")
        print(f"Drop rate:       {results['drop_rate']}")
        print(f"μs/packet:       {results['us_per_packet']}")
        print(f"PASS:            {'YES' if results['pass'] else 'NO'}")
        print(f"{'='*50}")


if __name__ == "__main__":
    main()
