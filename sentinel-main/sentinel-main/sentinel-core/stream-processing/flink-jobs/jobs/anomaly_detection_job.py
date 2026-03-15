"""SENTINEL Real-time Anomaly Detection Flink Job

Processes both network-events and host-events from Kafka:
- Statistical threshold-based detection (SYN floods, port scans)
- Pattern matching for known attack signatures
- Host event correlation (privilege escalation, module loads)
- Rate-based anomaly detection

Outputs detected anomalies to sentinel-anomalies Kafka topic for
consumption by the AI Engine and Alert Service.
"""

import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config


class AnomalyDetector:
    """Multi-strategy anomaly detection engine for streaming data."""

    def __init__(self, thresholds: Optional[Dict[str, int]] = None):
        self.thresholds = thresholds or {
            "syn_flood": config.features.syn_flood_threshold,
            "large_payload": config.features.large_payload_threshold,
            "port_scan": config.features.port_scan_threshold,
            "rate_threshold": 1000,
            "priv_escalation_burst": 3,
            "module_load_burst": 5,
        }
        self.syn_counts: Dict[str, int] = defaultdict(int)
        self.port_scan_state: Dict[str, set] = defaultdict(set)
        self.rate_counters: Dict[str, int] = defaultdict(int)
        self.host_priv_counts: Dict[int, int] = defaultdict(int)
        self.host_module_counts: Dict[int, int] = defaultdict(int)

    def detect_network(self, record: Dict[str, Any]) -> List[Dict[str, Any]]:
        anomalies = []
        for fn in (self._detect_syn_flood, self._detect_port_scan, self._detect_large_payload):
            result = fn(record)
            if result:
                anomalies.append(result)
        return anomalies

    def detect_host(self, record: Dict[str, Any]) -> List[Dict[str, Any]]:
        anomalies = []
        event_type = record.get("event_type", "")

        if event_type == "priv_escalation":
            pid = record.get("pid", 0)
            self.host_priv_counts[pid] += 1
            if self.host_priv_counts[pid] >= self.thresholds["priv_escalation_burst"]:
                anomalies.append({
                    "type": "priv_escalation_burst",
                    "severity": "critical",
                    "pid": pid,
                    "uid": record.get("uid"),
                    "target_uid": record.get("target_uid"),
                    "comm": record.get("comm", ""),
                    "count": self.host_priv_counts[pid],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "description": f"Repeated privilege escalation from PID {pid}",
                })

        elif event_type == "module_load":
            uid = record.get("uid", 0)
            self.host_module_counts[uid] += 1
            if self.host_module_counts[uid] >= self.thresholds["module_load_burst"]:
                anomalies.append({
                    "type": "module_load_burst",
                    "severity": "high",
                    "uid": uid,
                    "module": record.get("name", ""),
                    "count": self.host_module_counts[uid],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "description": f"Burst of kernel module loads by UID {uid}",
                })

        elif event_type == "fim_alert":
            anomalies.append({
                "type": "file_integrity_violation",
                "severity": "high",
                "path": record.get("path", ""),
                "change_type": record.get("change_type", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "description": f"File integrity violation: {record.get('path')} {record.get('change_type')}",
            })

        return anomalies

    def _detect_syn_flood(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if record.get("transport", "").upper() != "TCP":
            return None
        tcp_flags = record.get("tcp_flags", 0)
        if not tcp_flags:
            return None
        is_syn = (tcp_flags & 0x02) and not (tcp_flags & 0x10)
        if is_syn:
            src_ip = record.get("src_ip", "unknown")
            self.syn_counts[src_ip] += 1
            if self.syn_counts[src_ip] >= self.thresholds["syn_flood"]:
                return {
                    "type": "syn_flood",
                    "severity": "high",
                    "source_ip": src_ip,
                    "target_ip": record.get("dest_ip"),
                    "target_port": record.get("dest_port"),
                    "syn_count": self.syn_counts[src_ip],
                    "threshold": self.thresholds["syn_flood"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "description": f"Potential SYN flood attack from {src_ip}",
                }
        return None

    def _detect_port_scan(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        src_ip = record.get("src_ip", "unknown")
        dest_port = record.get("dest_port")
        if not dest_port:
            return None
        self.port_scan_state[src_ip].add(dest_port)
        unique_ports = len(self.port_scan_state[src_ip])
        if unique_ports >= self.thresholds["port_scan"]:
            return {
                "type": "port_scan",
                "severity": "medium",
                "source_ip": src_ip,
                "target_ip": record.get("dest_ip"),
                "unique_ports_scanned": unique_ports,
                "ports": sorted(list(self.port_scan_state[src_ip]))[:20],
                "threshold": self.thresholds["port_scan"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "description": f"Port scanning detected from {src_ip}",
            }
        return None

    def _detect_large_payload(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        payload_size = record.get("bytes", 0)
        if payload_size >= self.thresholds["large_payload"]:
            return {
                "type": "large_payload",
                "severity": "low",
                "source_ip": record.get("src_ip"),
                "dest_ip": record.get("dest_ip"),
                "payload_size": payload_size,
                "threshold": self.thresholds["large_payload"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "description": f"Large payload detected: {payload_size} bytes",
            }
        return None

    def reset_state(self, reset_type: str = "all"):
        if reset_type in ["all", "syn"]:
            self.syn_counts.clear()
        if reset_type in ["all", "port_scan"]:
            self.port_scan_state.clear()
        if reset_type in ["all", "rate"]:
            self.rate_counters.clear()
        if reset_type in ["all", "host"]:
            self.host_priv_counts.clear()
            self.host_module_counts.clear()


class AnomalyDetectionJob:
    """Flink streaming job for real-time anomaly detection.

    Consumes from:
    - sentinel-network-events (XDP collector, data-collector)
    - sentinel-host-events (HIDS agent, hardening service)

    Produces to:
    - sentinel-anomalies (AI engine, alert service)
    """

    def __init__(self, kafka_config=None):
        self.kafka_config = kafka_config or config.kafka
        self.detector = AnomalyDetector()
        self.env = None
        self.t_env = None

    def setup_environment(self):
        try:
            from pyflink.datastream import StreamExecutionEnvironment
            from pyflink.table import StreamTableEnvironment, EnvironmentSettings

            self.env = StreamExecutionEnvironment.get_execution_environment()
            self.env.set_parallelism(config.parallelism)
            self.env.enable_checkpointing(config.checkpoint_interval_ms)

            settings = EnvironmentSettings.new_instance().in_streaming_mode().build()
            self.t_env = StreamTableEnvironment.create(self.env, environment_settings=settings)

            logger.info("Flink environment initialized for anomaly detection")
        except ImportError as e:
            logger.error("PyFlink not available: %s", e)
            self.env = None
            self.t_env = None

    def _create_kafka_sources(self):
        """Create Kafka source tables for network and host events."""
        bootstrap = self.kafka_config.bootstrap_servers

        network_ddl = f"""
        CREATE TABLE network_events (
            event_type STRING,
            src_ip STRING,
            dst_ip STRING,
            src_port INT,
            dst_port INT,
            protocol INT,
            packets BIGINT,
            bytes_count BIGINT,
            tcp_flags INT,
            syn_count INT,
            timestamp_ns BIGINT,
            proc_time AS PROCTIME()
        ) WITH (
            'connector' = 'kafka',
            'topic' = 'sentinel-network-events',
            'properties.bootstrap.servers' = '{bootstrap}',
            'properties.group.id' = 'sentinel-anomaly-detection',
            'scan.startup.mode' = 'latest-offset',
            'format' = 'json',
            'json.fail-on-missing-field' = 'false'
        )
        """

        host_ddl = f"""
        CREATE TABLE host_events (
            event_type STRING,
            pid INT,
            uid INT,
            comm STRING,
            filename STRING,
            path STRING,
            name STRING,
            target_uid INT,
            change_type STRING,
            severity STRING,
            timestamp_ns BIGINT,
            proc_time AS PROCTIME()
        ) WITH (
            'connector' = 'kafka',
            'topic' = 'sentinel-host-events',
            'properties.bootstrap.servers' = '{bootstrap}',
            'properties.group.id' = 'sentinel-anomaly-detection',
            'scan.startup.mode' = 'latest-offset',
            'format' = 'json',
            'json.fail-on-missing-field' = 'false'
        )
        """

        anomalies_ddl = f"""
        CREATE TABLE anomalies_sink (
            anomaly_type STRING,
            severity STRING,
            source_ip STRING,
            description STRING,
            details STRING,
            detected_at STRING
        ) WITH (
            'connector' = 'kafka',
            'topic' = 'sentinel-anomalies',
            'properties.bootstrap.servers' = '{bootstrap}',
            'format' = 'json'
        )
        """

        self.t_env.execute_sql(network_ddl)
        self.t_env.execute_sql(host_ddl)
        self.t_env.execute_sql(anomalies_ddl)
        logger.info("Kafka source and sink tables created")

    def _create_detection_queries(self):
        """Create Flink SQL queries for streaming anomaly detection."""

        syn_flood_sql = """
        INSERT INTO anomalies_sink
        SELECT
            'syn_flood' AS anomaly_type,
            'high' AS severity,
            src_ip AS source_ip,
            CONCAT('SYN flood detected from ', src_ip, ': ', CAST(syn_total AS STRING), ' SYN packets') AS description,
            '' AS details,
            CAST(CURRENT_TIMESTAMP AS STRING) AS detected_at
        FROM (
            SELECT
                src_ip,
                SUM(syn_count) AS syn_total,
                TUMBLE_START(proc_time, INTERVAL '1' MINUTE) AS window_start
            FROM network_events
            WHERE tcp_flags > 0
            GROUP BY src_ip, TUMBLE(proc_time, INTERVAL '1' MINUTE)
            HAVING SUM(syn_count) > 100
        )
        """

        port_scan_sql = """
        INSERT INTO anomalies_sink
        SELECT
            'port_scan' AS anomaly_type,
            'medium' AS severity,
            src_ip AS source_ip,
            CONCAT('Port scan from ', src_ip, ': ', CAST(unique_ports AS STRING), ' unique ports') AS description,
            '' AS details,
            CAST(CURRENT_TIMESTAMP AS STRING) AS detected_at
        FROM (
            SELECT
                src_ip,
                COUNT(DISTINCT dst_port) AS unique_ports,
                TUMBLE_START(proc_time, INTERVAL '1' MINUTE) AS window_start
            FROM network_events
            GROUP BY src_ip, TUMBLE(proc_time, INTERVAL '1' MINUTE)
            HAVING COUNT(DISTINCT dst_port) > 50
        )
        """

        host_anomaly_sql = """
        INSERT INTO anomalies_sink
        SELECT
            CONCAT('host_', event_type) AS anomaly_type,
            CASE
                WHEN event_type = 'priv_escalation' THEN 'critical'
                WHEN event_type = 'module_load' THEN 'high'
                WHEN event_type = 'fim_alert' THEN 'high'
                ELSE 'medium'
            END AS severity,
            '' AS source_ip,
            CONCAT('Host event: ', event_type, ' by PID ', CAST(pid AS STRING), ' (', COALESCE(comm, 'unknown'), ')') AS description,
            '' AS details,
            CAST(CURRENT_TIMESTAMP AS STRING) AS detected_at
        FROM host_events
        WHERE event_type IN ('priv_escalation', 'module_load', 'fim_alert')
        """

        self.t_env.execute_sql(syn_flood_sql)
        logger.info("SYN flood detection query submitted")

        self.t_env.execute_sql(port_scan_sql)
        logger.info("Port scan detection query submitted")

        self.t_env.execute_sql(host_anomaly_sql)
        logger.info("Host anomaly detection query submitted")

    def run(self):
        logger.info("Starting SENTINEL Anomaly Detection Job")

        self.setup_environment()

        if self.env and self.t_env:
            logger.info("Running anomaly detection with Flink streaming")
            self._create_kafka_sources()
            self._create_detection_queries()
            logger.info("All detection queries submitted; Flink job running")
        else:
            logger.info("Running anomaly detection in development mode")
            self._run_development_mode()

    def _run_development_mode(self):
        logger.info("Development mode: Simulating anomaly detection")

        test_network_records = [
            {"src_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 443,
             "transport": "TCP", "tcp_flags": 0x10, "bytes": 500},
            *[{"src_ip": "192.168.1.200", "dest_ip": "10.0.0.1", "dest_port": 80,
               "transport": "TCP", "tcp_flags": 0x02, "bytes": 40}
              for _ in range(150)],
            *[{"src_ip": "192.168.1.150", "dest_ip": "10.0.0.1", "dest_port": port,
               "transport": "TCP", "tcp_flags": 0x02, "bytes": 40}
              for port in range(1, 100)],
            {"src_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 443,
             "transport": "TCP", "tcp_flags": 0x18, "bytes": 50000},
        ]

        test_host_records = [
            {"event_type": "priv_escalation", "pid": 4444, "uid": 1000,
             "target_uid": 0, "comm": "sudo"},
            {"event_type": "priv_escalation", "pid": 4444, "uid": 1000,
             "target_uid": 0, "comm": "sudo"},
            {"event_type": "priv_escalation", "pid": 4444, "uid": 1000,
             "target_uid": 0, "comm": "sudo"},
            {"event_type": "module_load", "pid": 1, "uid": 0,
             "name": "suspicious_module"},
            {"event_type": "fim_alert", "path": "/etc/shadow",
             "change_type": "modified"},
        ]

        all_anomalies = []
        for record in test_network_records:
            all_anomalies.extend(self.detector.detect_network(record))
        for record in test_host_records:
            all_anomalies.extend(self.detector.detect_host(record))

        unique_anomalies = {}
        for a in all_anomalies:
            key = f"{a['type']}:{a.get('source_ip', a.get('pid', ''))}"
            if key not in unique_anomalies:
                unique_anomalies[key] = a

        logger.info("Detected %d unique anomalies:", len(unique_anomalies))
        for anomaly in unique_anomalies.values():
            logger.info("  - %s [%s]: %s", anomaly["type"], anomaly["severity"], anomaly["description"])

        return list(unique_anomalies.values())


def main():
    job = AnomalyDetectionJob()
    job.run()


if __name__ == "__main__":
    main()
