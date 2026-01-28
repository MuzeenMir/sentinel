"""
SENTINEL XDP Collector

High-speed packet ingestion using XDP/AF_XDP on bare‑metal Linux,
bridged into the existing CIM normalization and Kafka pipeline.

NOTE:
- This service is designed to run on a privileged host or
  privileged Docker container on a bare‑metal Linux kernel
  with XDP-capable NIC drivers.
- The actual AF_XDP loop is implemented in a best-effort,
  portable way; for production, you will likely tune and
  extend it to your specific NIC/driver.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

from flask import Flask, jsonify
from flask_cors import CORS

from backend.data-collector.collector import (  # type: ignore
    TCP_PROTOCOL,
    UDP_PROTOCOL,
    ICMP_PROTOCOL,
    DataSourceType,
)
from backend.data-collector.xdp_bridge import (  # type: ignore
    XDPBridge,
    build_raw_packet_from_l2_l3_l4,
)


app = Flask(__name__)
CORS(app)


# Configuration
app.config["XDP_ENABLED"] = os.environ.get("XDP_ENABLED", "true").lower() == "true"
app.config["XDP_INTERFACE"] = os.environ.get("XDP_INTERFACE", "eth0")
app.config["XDP_QUEUE_COUNT"] = int(os.environ.get("XDP_QUEUE_COUNT", "1"))


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("xdp-collector")


@dataclass
class XDPStats:
    packets_received: int = 0
    packets_dropped: int = 0
    bytes_processed: int = 0
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packets_received": self.packets_received,
            "packets_dropped": self.packets_dropped,
            "bytes_processed": self.bytes_processed,
            "last_error": self.last_error,
        }


class XDPCollectorService:
    """
    User-space side of the XDP/AF_XDP pipeline.

    Responsibilities:
    - Attach XDP program (out of process / via helper script).
    - Receive frames via AF_XDP (or a stub if unsupported).
    - Convert headers to raw packet dicts.
    - Use XDPBridge to normalize + publish to Kafka.
    """

    def __init__(self) -> None:
        self.interface = app.config["XDP_INTERFACE"]
        self.queue_count = app.config["XDP_QUEUE_COUNT"]
        self.enabled = app.config["XDP_ENABLED"]
        self.bridge = XDPBridge()
        self.stats = XDPStats()
        self._running = False

    def start(self) -> None:
        """
        Start the ingestion loop.

        For now this uses a placeholder implementation that can be
        extended to a real AF_XDP loop. The interface and stats
        structure are stable so production code can replace the
        internals without affecting callers.
        """
        if not self.enabled:
            logger.info("XDP collector disabled via XDP_ENABLED=false")
            return

        self._running = True
        logger.info(
            "Starting XDP collector on interface %s (queues=%s)",
            self.interface,
            self.queue_count,
        )

        try:
            # Placeholder loop — in a real implementation, this would:
            # - set up AF_XDP sockets for each queue
            # - mmap the UMEM region
            # - poll RX rings and process frames
            # Here we simply log that the loop would be running.
            logger.warning(
                "XDPCollectorService.start() is currently a stub. "
                "Implement AF_XDP receive loop for production."
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("XDP collector error: %s", exc)
            self.stats.last_error = str(exc)
            self._running = False

    def stop(self) -> None:
        self._running = False

    def process_frame(
        self,
        src_ip: str,
        dest_ip: str,
        protocol: int,
        src_port: Optional[int],
        dest_port: Optional[int],
        length: int,
    ) -> None:
        """
        Process a single decoded frame coming from AF_XDP.

        This method can be called from a real AF_XDP loop once implemented.
        """
        if not self._running:
            return

        try:
            raw_packet = build_raw_packet_from_l2_l3_l4(
                src_ip=src_ip,
                dest_ip=dest_ip,
                protocol=protocol,
                src_port=src_port,
                dest_port=dest_port,
                length=length,
            )

            record = self.bridge.normalize_packet(raw_packet, DataSourceType.PCAP)
            self.bridge.publish_normalized(record)

            self.stats.packets_received += 1
            self.stats.bytes_processed += length
        except Exception as exc:  # pragma: no cover - defensive
            self.stats.packets_dropped += 1
            self.stats.last_error = str(exc)
            logger.error("Error processing XDP frame: %s", exc)


xdp_collector = XDPCollectorService()


@app.route("/health", methods=["GET"])
def health() -> Any:
    return (
        jsonify(
            {
                "status": "healthy" if xdp_collector.enabled else "disabled",
                "interface": xdp_collector.interface,
                "queues": xdp_collector.queue_count,
                "enabled": xdp_collector.enabled,
            }
        ),
        200,
    )


@app.route("/metrics", methods=["GET"])
def metrics() -> Any:
    return jsonify({"xdp": xdp_collector.stats.to_dict()}), 200


if __name__ == "__main__":
    # In production this would typically be run via gunicorn and a
    # separate supervisor starting the AF_XDP loop in a background thread.
    xdp_collector.start()
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5010")),
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )

