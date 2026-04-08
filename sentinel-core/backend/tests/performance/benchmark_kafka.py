#!/usr/bin/env python3
"""
SENTINEL Kafka Throughput Benchmark

Target: 50k events/sec sustained ingestion, p99 produce latency < 20ms

Usage:
    python benchmark_kafka.py --broker localhost:9092 --events 100000 --batch 500
"""
import argparse
import json
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

TOPIC = "raw-security-events"


def _create_event(seq: int) -> bytes:
    event = {
        "event_id": f"bench-{seq}",
        "timestamp": time.time(),
        "source_ip": f"10.{seq % 256}.{(seq // 256) % 256}.{(seq // 65536) % 256}",
        "dest_ip": "192.168.1.1",
        "dest_port": 443,
        "protocol": "TCP",
        "payload_size": 128,
        "flags": ["SYN"],
        "raw": "benchmark-payload",
    }
    return json.dumps(event).encode()


def _produce_batch(producer, topic: str, events: list[bytes]):
    latencies = []
    for ev in events:
        t0 = time.perf_counter()
        producer.produce(topic, value=ev)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)
    producer.flush()
    return latencies


def run_benchmark(broker: str, total_events: int, batch_size: int, threads: int):
    try:
        from confluent_kafka import Producer
    except ImportError:
        print("ERROR: confluent-kafka not installed. pip install confluent-kafka")
        return None

    conf = {
        "bootstrap.servers": broker,
        "linger.ms": 5,
        "batch.num.messages": batch_size,
        "queue.buffering.max.messages": total_events,
        "acks": "all",
    }
    producer = Producer(conf)

    events = [_create_event(i) for i in range(total_events)]
    batches = [events[i:i + batch_size] for i in range(0, len(events), batch_size)]

    all_latencies = []
    t_start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_produce_batch, producer, TOPIC, batch) for batch in batches]
        for f in as_completed(futures):
            all_latencies.extend(f.result())

    t_elapsed = time.perf_counter() - t_start
    throughput = total_events / t_elapsed

    all_latencies.sort()
    results = {
        "total_events": total_events,
        "batch_size": batch_size,
        "threads": threads,
        "elapsed_sec": round(t_elapsed, 3),
        "throughput_eps": round(throughput, 1),
        "latency_p50_ms": round(all_latencies[len(all_latencies) // 2], 3),
        "latency_p95_ms": round(all_latencies[int(len(all_latencies) * 0.95)], 3),
        "latency_p99_ms": round(all_latencies[int(len(all_latencies) * 0.99)], 3),
        "latency_mean_ms": round(statistics.mean(all_latencies), 3),
        "pass": all_latencies[int(len(all_latencies) * 0.99)] < 20 and throughput > 50000,
    }
    return results


def main():
    parser = argparse.ArgumentParser(description="Kafka throughput benchmark")
    parser.add_argument("--broker", default=os.getenv("KAFKA_BROKER", "localhost:9092"))
    parser.add_argument("--events", type=int, default=100000)
    parser.add_argument("--batch", type=int, default=500)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    print(f"Kafka benchmark: {args.events} events, batch={args.batch}, threads={args.threads}")
    results = run_benchmark(args.broker, args.events, args.batch, args.threads)

    if results is None:
        return

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{'='*50}")
        print(f"Events:       {results['total_events']}")
        print(f"Elapsed:      {results['elapsed_sec']}s")
        print(f"Throughput:   {results['throughput_eps']} events/sec")
        print(f"Latency p50:  {results['latency_p50_ms']}ms")
        print(f"Latency p95:  {results['latency_p95_ms']}ms")
        print(f"Latency p99:  {results['latency_p99_ms']}ms")
        print(f"PASS:         {'YES' if results['pass'] else 'NO'}")
        print(f"{'='*50}")


if __name__ == "__main__":
    main()
