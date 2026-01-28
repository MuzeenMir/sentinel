"""
Bridge utilities to reuse CIM normalization and Kafka publishing
logic from the existing data collector in alternative ingestion
paths such as XDP/AF_XDP.

This allows the XDP-based collector to:
- Normalize packets into the same CIM schema as NetworkTrafficCollector
- Publish to the same Kafka topic (`normalized_traffic`)
- Reuse anomaly detection and Redis stats if desired
"""

from typing import Any, Dict, Optional

from .collector import CIMNormalizer, DataSourceType, producer, redis_client, logger  # type: ignore


NORMALIZED_TOPIC = "normalized_traffic"


class XDPBridge:
    """
    Thin wrapper exposing a stable interface for alternative
    ingestion backends (e.g. AF_XDP) to plug into the existing
    SENTINEL data pipeline.
    """

    def __init__(self) -> None:
        self.normalizer = CIMNormalizer()

    def normalize_packet(
        self, raw_packet: Dict[str, Any], source_type: DataSourceType
    ) -> Dict[str, Any]:
        """
        Normalize a raw packet/flow dict into the CIM schema.

        The raw_packet must at least contain:
        - source_ip / dest_ip
        - protocol
        - optional source_port / dest_port
        - bytes / length
        """
        return self.normalizer.normalize(raw_packet, source_type)

    def publish_normalized(self, record: Dict[str, Any]) -> None:
        """
        Publish a normalized record to Kafka and optionally
        update simple Redis traffic statistics.
        """
        try:
            if producer:
                producer.send(NORMALIZED_TOPIC, record)
        except Exception as exc:  # pragma: no cover - best-effort logging
            logger.error(f"XDPBridge Kafka publish error: {exc}")

        # Optionally one could mirror the _update_traffic_stats() logic here.


def build_raw_packet_from_l2_l3_l4(
    src_ip: str,
    dest_ip: str,
    protocol: int,
    src_port: Optional[int] = None,
    dest_port: Optional[int] = None,
    length: int = 0,
) -> Dict[str, Any]:
    """
    Helper to create a minimal raw-packet dict compatible with CIMNormalizer
    from low-level header information produced by an XDP/AF_XDP loop.
    """
    from datetime import datetime

    raw: Dict[str, Any] = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": src_ip,
        "dest_ip": dest_ip,
        "protocol": protocol,
        "length": length,
    }
    if src_port is not None:
        raw["source_port"] = src_port
    if dest_port is not None:
        raw["dest_port"] = dest_port
    return raw

