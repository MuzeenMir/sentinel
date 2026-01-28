"""
Configuration for SENTINEL Flink Jobs.
"""
import os
from dataclasses import dataclass
from typing import List


@dataclass
class KafkaConfig:
    """Kafka configuration."""
    bootstrap_servers: str = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
    input_topic: str = os.environ.get('KAFKA_INPUT_TOPIC', 'normalized_traffic')
    output_topic: str = os.environ.get('KAFKA_OUTPUT_TOPIC', 'enriched_traffic')
    features_topic: str = os.environ.get('KAFKA_FEATURES_TOPIC', 'extracted_features')
    alerts_topic: str = os.environ.get('KAFKA_ALERTS_TOPIC', 'alerts')
    group_id: str = os.environ.get('KAFKA_GROUP_ID', 'sentinel-flink')


@dataclass
class WindowConfig:
    """Windowing configuration."""
    # Window sizes in seconds
    tumbling_window_1m: int = 60
    tumbling_window_5m: int = 300
    tumbling_window_15m: int = 900
    
    # Sliding window configuration
    sliding_window_size: int = 300  # 5 minutes
    sliding_window_slide: int = 60   # 1 minute
    
    # Session window gap
    session_gap: int = 300  # 5 minutes


@dataclass
class FeatureConfig:
    """Feature extraction configuration."""
    # Statistical features
    compute_packet_stats: bool = True
    compute_byte_stats: bool = True
    compute_iat_stats: bool = True  # Inter-arrival time
    
    # Behavioral features
    compute_entropy: bool = True
    compute_flow_patterns: bool = True
    
    # Anomaly detection thresholds
    syn_flood_threshold: int = 100
    large_payload_threshold: int = 10000
    port_scan_threshold: int = 50


@dataclass
class FlinkConfig:
    """Flink job configuration."""
    job_name: str = "sentinel-feature-extraction"
    parallelism: int = int(os.environ.get('FLINK_PARALLELISM', '4'))
    checkpoint_interval: int = 60000  # 1 minute in ms
    checkpoint_dir: str = os.environ.get('CHECKPOINT_DIR', 'file:///tmp/flink-checkpoints')
    
    kafka: KafkaConfig = None
    windows: WindowConfig = None
    features: FeatureConfig = None
    
    def __post_init__(self):
        if self.kafka is None:
            self.kafka = KafkaConfig()
        if self.windows is None:
            self.windows = WindowConfig()
        if self.features is None:
            self.features = FeatureConfig()


# Global configuration instance
config = FlinkConfig()
