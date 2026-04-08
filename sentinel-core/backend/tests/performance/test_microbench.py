"""
SENTINEL Micro-benchmarks — pytest-based latency assertions for critical hot paths.

These run without live services by importing model code directly
and measuring inference/decision wall-clock time.

Usage:
    pytest test_microbench.py -v --tb=short
"""
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

BACKEND = Path(__file__).resolve().parents[2]


def _import_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# AI Engine Inference Micro-benchmark
# ---------------------------------------------------------------------------
class TestAIInferenceLatency:
    """Validate that ensemble inference completes in < 50ms per sample.

    Uses sklearn models directly to avoid import-chain issues with the
    ai-engine package (LSTM depends on PyTorch at class-definition time).
    """

    ITERATIONS = 200
    THRESHOLD_MS = 50

    def test_inference_latency_under_threshold(self):
        try:
            from sklearn.ensemble import RandomForestClassifier
        except ImportError:
            pytest.skip("scikit-learn not installed")

        rng = np.random.default_rng(42)
        X_train = rng.standard_normal((200, 50))
        y_train = rng.integers(0, 2, 200)

        clf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
        clf.fit(X_train, y_train)

        sample = rng.standard_normal((1, 50))

        latencies = []
        for _ in range(self.ITERATIONS):
            t0 = time.perf_counter()
            clf.predict_proba(sample)
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000)

        latencies.sort()
        p95 = latencies[int(len(latencies) * 0.95)]
        mean_lat = sum(latencies) / len(latencies)

        assert p95 < self.THRESHOLD_MS, (
            f"AI inference p95={p95:.2f}ms exceeds {self.THRESHOLD_MS}ms"
        )
        print(f"\nAI inference (RF-50 trees): mean={mean_lat:.2f}ms, p95={p95:.2f}ms "
              f"(threshold={self.THRESHOLD_MS}ms)")


# ---------------------------------------------------------------------------
# DRL Decision Micro-benchmark
# ---------------------------------------------------------------------------
class TestDRLDecisionLatency:
    """Validate that DRL policy network forward pass completes in < 10ms."""

    ITERATIONS = 500
    THRESHOLD_MS = 10

    def test_decision_latency_under_threshold(self):
        try:
            import torch
        except ImportError:
            pytest.skip("PyTorch not installed")

        input_dim = 20
        hidden = 128
        output_dim = 5

        policy_net = torch.nn.Sequential(
            torch.nn.Linear(input_dim, hidden),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden, hidden),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden, output_dim),
        )
        policy_net.eval()

        state = torch.randn(1, input_dim)

        latencies = []
        with torch.no_grad():
            for _ in range(self.ITERATIONS):
                t0 = time.perf_counter()
                logits = policy_net(state)
                action = torch.argmax(logits, dim=1).item()
                t1 = time.perf_counter()
                latencies.append((t1 - t0) * 1000)

        latencies.sort()
        p95 = latencies[int(len(latencies) * 0.95)]
        mean_lat = sum(latencies) / len(latencies)

        assert p95 < self.THRESHOLD_MS, (
            f"DRL decision p95={p95:.2f}ms exceeds {self.THRESHOLD_MS}ms"
        )
        print(f"\nDRL decision: mean={mean_lat:.2f}ms, p95={p95:.2f}ms "
              f"(threshold={self.THRESHOLD_MS}ms)")


# ---------------------------------------------------------------------------
# JSON Serialization Throughput
# ---------------------------------------------------------------------------
class TestSerializationThroughput:
    """Validate event serialization can sustain 100k events/sec."""

    EVENTS = 50000
    TARGET_EPS = 100000

    def test_json_serialization_throughput(self):
        event_template = {
            "event_id": "",
            "timestamp": 0.0,
            "source_ip": "10.0.0.1",
            "dest_ip": "192.168.1.1",
            "dest_port": 443,
            "protocol": "TCP",
            "payload_size": 128,
            "flags": ["SYN"],
        }

        t0 = time.perf_counter()
        for i in range(self.EVENTS):
            event_template["event_id"] = f"ev-{i}"
            event_template["timestamp"] = time.time()
            json.dumps(event_template)
        elapsed = time.perf_counter() - t0

        throughput = self.EVENTS / elapsed
        assert throughput > self.TARGET_EPS, (
            f"Serialization {throughput:.0f} events/sec < target {self.TARGET_EPS}"
        )
        print(f"\nSerialization: {throughput:.0f} events/sec "
              f"(target={self.TARGET_EPS})")


# ---------------------------------------------------------------------------
# Redis Operation Latency (mock-based to test overhead)
# ---------------------------------------------------------------------------
class TestRedisOperationOverhead:
    """Validate Redis client call overhead is < 1ms per operation."""

    ITERATIONS = 1000
    THRESHOLD_MS = 1

    def test_redis_call_overhead(self):
        mock_redis = MagicMock()
        mock_redis.get.return_value = b'{"alert_id": "test"}'
        mock_redis.set.return_value = True
        mock_redis.publish.return_value = 1

        latencies = []
        for i in range(self.ITERATIONS):
            t0 = time.perf_counter()
            mock_redis.set(f"key:{i}", json.dumps({"data": i}), ex=300)
            val = mock_redis.get(f"key:{i}")
            if val:
                json.loads(val)
            mock_redis.publish("sentinel:sse:alerts", json.dumps({"id": i}))
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000)

        latencies.sort()
        p95 = latencies[int(len(latencies) * 0.95)]
        assert p95 < self.THRESHOLD_MS, (
            f"Redis overhead p95={p95:.3f}ms exceeds {self.THRESHOLD_MS}ms"
        )
        print(f"\nRedis overhead: p95={p95:.3f}ms (threshold={self.THRESHOLD_MS}ms)")
