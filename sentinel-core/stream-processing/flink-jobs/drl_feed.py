"""
SENTINEL DRL Feed Stream Job

Aggregates network state from multiple Kafka topics into rolling
state snapshots, periodically submits them to the DRL engine for
policy decisions, and forwards accepted actions to the policy
orchestrator's auto-apply endpoint.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

import numpy as np
import requests

from base_job import BaseStreamJob

logger = logging.getLogger(__name__)

SNAPSHOT_INTERVAL = float(os.environ.get("DRL_SNAPSHOT_INTERVAL", "10.0"))
DECISION_INTERVAL = float(os.environ.get("DRL_DECISION_INTERVAL", "15.0"))
STATE_WINDOW = int(os.environ.get("DRL_STATE_WINDOW", "300"))

INPUT_TOPICS = [
    "sentinel-network-events",
    "extracted_features",
    "sentinel-detections",
    "sentinel-alerts",
]


class NetworkStateAggregator:
    """Thread-safe rolling-window aggregation of network telemetry."""

    def __init__(self, window_seconds: int = STATE_WINDOW):
        self._window = window_seconds
        self._events: deque = deque(maxlen=50_000)
        self._alerts: deque = deque(maxlen=5_000)
        self._detections: deque = deque(maxlen=10_000)
        self._src_scores: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    # ── Ingestion ─────────────────────────────────────────────────────────

    def ingest_event(self, event: Dict[str, Any]):
        with self._lock:
            ts = event.get("timestamp", time.time())
            self._events.append({"ts": ts, "data": event})
            self._evict(ts)

    def ingest_detection(self, det: Dict[str, Any]):
        with self._lock:
            ts = det.get("timestamp", time.time())
            self._detections.append({"ts": ts, "data": det})
            src = det.get("src_ip", "unknown")
            score = det.get("composite_score", 0.0)
            bucket = self._src_scores[src]
            bucket.append(score)
            if len(bucket) > 100:
                bucket[:] = bucket[-100:]

    def ingest_alert(self, alert: Dict[str, Any]):
        with self._lock:
            ts = alert.get("timestamp", time.time())
            self._alerts.append({"ts": ts, "data": alert})

    # ── Snapshot ──────────────────────────────────────────────────────────

    def build_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            self._evict(now)

            event_n = len(self._events)
            alert_n = len(self._alerts)
            det_n = len(self._detections)

            severities: Dict[str, int] = defaultdict(int)
            for a in self._alerts:
                severities[a["data"].get("severity", "low")] += 1

            anomaly_scores = [
                d["data"].get("composite_score", 0.0)
                for d in self._detections
                if d["data"].get("is_anomaly")
            ]

            unique_srcs: set = set()
            total_bytes = 0.0
            protocols: Dict[str, int] = defaultdict(int)
            for e in self._events:
                d = e["data"]
                unique_srcs.add(d.get("src_ip", "unknown"))
                total_bytes += float(
                    d.get("total_bytes") or d.get("bytes_in") or 0,
                )
                protocols[d.get("protocol", "unknown")] += 1

            top_srcs = sorted(
                self._src_scores.items(),
                key=lambda kv: np.mean(kv[1][-10:]) if kv[1] else 0,
                reverse=True,
            )[:10]

            state_vec = self._state_vector(
                event_n,
                alert_n,
                det_n,
                severities,
                anomaly_scores,
                unique_srcs,
                total_bytes,
            )

            return {
                "snapshot_id": str(uuid.uuid4()),
                "timestamp": now,
                "window_seconds": self._window,
                "event_count": event_n,
                "event_rate": event_n / max(self._window, 1),
                "alert_count": alert_n,
                "alert_severities": dict(severities),
                "detection_count": det_n,
                "anomaly_count": len(anomaly_scores),
                "mean_anomaly_score": float(np.mean(anomaly_scores))
                if anomaly_scores
                else 0.0,
                "max_anomaly_score": float(np.max(anomaly_scores))
                if anomaly_scores
                else 0.0,
                "unique_sources": len(unique_srcs),
                "total_bytes": total_bytes,
                "byte_rate": total_bytes / max(self._window, 1),
                "protocol_distribution": dict(protocols),
                "top_threat_sources": [
                    {"src_ip": ip, "mean_score": round(float(np.mean(sc[-10:])), 4)}
                    for ip, sc in top_srcs
                ],
                "state_vector": state_vec,
            }

    @staticmethod
    def _state_vector(
        event_n,
        alert_n,
        det_n,
        severities,
        anomaly_scores,
        unique_srcs,
        total_bytes,
    ) -> List[float]:
        return [
            min(event_n / 10_000, 1.0),
            min(alert_n / 100, 1.0),
            min(det_n / 1_000, 1.0),
            min(severities.get("critical", 0) / 10, 1.0),
            min(severities.get("high", 0) / 50, 1.0),
            float(np.mean(anomaly_scores)) if anomaly_scores else 0.0,
            float(np.max(anomaly_scores)) if anomaly_scores else 0.0,
            min(len(unique_srcs) / 1_000, 1.0),
            min(total_bytes / 1e9, 1.0),
            min(len(anomaly_scores) / max(det_n, 1), 1.0),
            float(np.std(anomaly_scores)) if len(anomaly_scores) > 1 else 0.0,
            min(severities.get("medium", 0) / 100, 1.0),
        ]

    # ── Eviction ──────────────────────────────────────────────────────────

    def _evict(self, now: float):
        cutoff = now - self._window
        for q in (self._events, self._alerts, self._detections):
            while q and q[0]["ts"] < cutoff:
                q.popleft()


class DRLFeedJob(BaseStreamJob):
    def __init__(self):
        super().__init__("drl-feed")
        self.drl_url = os.environ.get("DRL_ENGINE_URL", "http://drl-engine:5005")
        self.policy_url = os.environ.get(
            "POLICY_SERVICE_URL",
            "http://policy-orchestrator:5004",
        )
        self.service_token = os.environ.get("INTERNAL_SERVICE_TOKEN", "")
        self.aggregator = NetworkStateAggregator()
        self._decision_thread: Optional[threading.Thread] = None
        self._processed = 0

        self._session = requests.Session()
        self._session.headers.update(
            {
                "Content-Type": "application/json",
                "User-Agent": "sentinel-drl-feed/1.0",
            }
        )
        if self.service_token:
            self._session.headers["Authorization"] = f"Bearer {self.service_token}"

    def setup(self):
        self.create_consumer(topics=INPUT_TOPICS, group_id="sentinel-drl-feed")
        self.create_producer()

        self._decision_thread = threading.Thread(
            target=self._decision_loop,
            daemon=True,
            name="drl-decision-loop",
        )
        self._decision_thread.start()
        logger.info(
            "DRL feed active: consuming %s, decision interval %.0f s",
            INPUT_TOPICS,
            DECISION_INTERVAL,
        )

    # ── Message routing ───────────────────────────────────────────────────

    def process(self, message: Dict[str, Any]):
        if "alert_id" in message:
            self.aggregator.ingest_alert(message)
        elif "detection_id" in message:
            self.aggregator.ingest_detection(message)
        else:
            self.aggregator.ingest_event(message)

        self._processed += 1
        if self._processed % 5_000 == 0:
            logger.info("DRL feed ingested %d messages", self._processed)

    # ── Background decision loop ──────────────────────────────────────────

    def _decision_loop(self):
        while not self._shutdown:
            time.sleep(DECISION_INTERVAL)
            if self._shutdown:
                break
            try:
                snapshot = self.aggregator.build_snapshot()
                if snapshot["event_count"] == 0:
                    continue

                decision = self._get_decision(snapshot)
                if decision is None:
                    continue

                self._apply_policy(decision, snapshot)

                self.produce(
                    "sentinel-drl-decisions",
                    {
                        "snapshot_id": snapshot["snapshot_id"],
                        "timestamp": time.time(),
                        "decision": decision,
                    },
                )
            except Exception:
                logger.exception("Error in DRL decision cycle")

    def _get_decision(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = f"{self.drl_url}/api/v1/decision"
        payload = {
            "state_vector": snapshot["state_vector"],
            "context": {
                "event_count": snapshot["event_count"],
                "alert_count": snapshot["alert_count"],
                "anomaly_count": snapshot["anomaly_count"],
                "top_threat_sources": snapshot["top_threat_sources"],
            },
        }
        try:
            resp = self._session.post(url, json=payload, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.ConnectionError:
            logger.warning("DRL engine unreachable at %s", url)
        except requests.Timeout:
            logger.warning("DRL engine timed out")
        except requests.HTTPError as exc:
            logger.warning(
                "DRL engine HTTP %d: %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
        except Exception:
            logger.exception("Unexpected error calling DRL engine")
        return None

    def _apply_policy(self, decision: Dict[str, Any], snapshot: Dict[str, Any]):
        actions = decision.get("actions")
        if not actions:
            return

        url = f"{self.policy_url}/api/v1/policies/auto-apply"
        payload = {
            "source": "drl-engine",
            "snapshot_id": snapshot["snapshot_id"],
            "timestamp": time.time(),
            "actions": actions,
            "context": {
                "alert_count": snapshot["alert_count"],
                "anomaly_count": snapshot["anomaly_count"],
                "confidence": decision.get("confidence", 0.0),
            },
        }
        try:
            resp = self._session.post(url, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info(
                "Forwarded %d DRL actions to policy orchestrator (snapshot=%s)",
                len(actions),
                snapshot["snapshot_id"][:8],
            )
        except requests.ConnectionError:
            logger.warning("Policy orchestrator unreachable at %s", url)
        except requests.Timeout:
            logger.warning("Policy orchestrator timed out")
        except requests.HTTPError as exc:
            logger.warning(
                "Policy orchestrator HTTP %d: %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
        except Exception:
            logger.exception("Unexpected error forwarding to policy orchestrator")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    DRLFeedJob().run()


if __name__ == "__main__":
    main()
