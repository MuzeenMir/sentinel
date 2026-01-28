"""
SENTINEL Feature Extraction Flink Job

Real-time feature extraction from network traffic streams using
tumbling, sliding, and session windows.

This job:
1. Consumes normalized traffic from Kafka
2. Groups by flow keys
3. Computes statistical and behavioral features
4. Outputs enriched features to Kafka for AI engine consumption
"""
import os
import sys
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Iterable

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import config
from utils.feature_functions import (
    compute_statistical_features,
    compute_behavioral_features,
    compute_flow_features,
    aggregate_window_features
)
from utils.serialization import (
    deserialize_traffic,
    serialize_features,
    create_flow_key,
    create_bidirectional_flow_key
)


class FeatureExtractionJob:
    """
    Flink job for real-time feature extraction.
    
    Implements multiple windowing strategies:
    - Tumbling windows (1m, 5m, 15m) for periodic aggregation
    - Sliding windows for overlapping analysis
    - Session windows for flow-based grouping
    """
    
    def __init__(self, kafka_config=None, window_config=None):
        """Initialize the feature extraction job."""
        self.kafka_config = kafka_config or config.kafka
        self.window_config = window_config or config.windows
        
        self.env = None
        self.t_env = None
        
    def setup_environment(self):
        """Set up Flink execution environment."""
        try:
            from pyflink.datastream import StreamExecutionEnvironment
            from pyflink.table import StreamTableEnvironment, EnvironmentSettings
            from pyflink.datastream.checkpointing_mode import CheckpointingMode
            
            # Create streaming environment
            self.env = StreamExecutionEnvironment.get_execution_environment()
            
            # Configure checkpointing
            self.env.enable_checkpointing(config.checkpoint_interval)
            self.env.get_checkpoint_config().set_checkpointing_mode(CheckpointingMode.EXACTLY_ONCE)
            self.env.get_checkpoint_config().set_min_pause_between_checkpoints(500)
            
            # Set parallelism
            self.env.set_parallelism(config.parallelism)
            
            # Create table environment
            settings = EnvironmentSettings.new_instance().in_streaming_mode().build()
            self.t_env = StreamTableEnvironment.create(self.env, environment_settings=settings)
            
            logger.info("Flink environment initialized")
            
        except ImportError as e:
            logger.error(f"PyFlink not available: {e}")
            logger.info("Running in standalone mode for development")
            self.env = None
            self.t_env = None
    
    def create_kafka_source(self):
        """Create Kafka source table."""
        if not self.t_env:
            return
        
        source_ddl = f"""
            CREATE TABLE traffic_source (
                event_id STRING,
                event_time TIMESTAMP(3),
                source_type STRING,
                src_ip STRING,
                dest_ip STRING,
                src_port INT,
                dest_port INT,
                transport STRING,
                bytes BIGINT,
                packets BIGINT,
                direction STRING,
                duration DOUBLE,
                tcp_flags INT,
                is_internal BOOLEAN,
                WATERMARK FOR event_time AS event_time - INTERVAL '5' SECOND
            ) WITH (
                'connector' = 'kafka',
                'topic' = '{self.kafka_config.input_topic}',
                'properties.bootstrap.servers' = '{self.kafka_config.bootstrap_servers}',
                'properties.group.id' = '{self.kafka_config.group_id}',
                'scan.startup.mode' = 'latest-offset',
                'format' = 'json'
            )
        """
        self.t_env.execute_sql(source_ddl)
        logger.info("Kafka source table created")
    
    def create_kafka_sink(self):
        """Create Kafka sink table for features."""
        if not self.t_env:
            return
        
        sink_ddl = f"""
            CREATE TABLE features_sink (
                feature_id STRING,
                window_start TIMESTAMP(3),
                window_end TIMESTAMP(3),
                window_type STRING,
                src_ip STRING,
                dest_ip STRING,
                transport STRING,
                packet_count BIGINT,
                total_bytes BIGINT,
                packet_size_mean DOUBLE,
                byte_rate DOUBLE,
                src_ip_entropy DOUBLE,
                dst_ip_entropy DOUBLE,
                unique_src_ips BIGINT,
                unique_dst_ips BIGINT,
                tcp_ratio DOUBLE,
                syn_ratio DOUBLE
            ) WITH (
                'connector' = 'kafka',
                'topic' = '{self.kafka_config.features_topic}',
                'properties.bootstrap.servers' = '{self.kafka_config.bootstrap_servers}',
                'format' = 'json'
            )
        """
        self.t_env.execute_sql(sink_ddl)
        logger.info("Kafka sink table created")
    
    def run_tumbling_window_aggregation(self, window_size_minutes: int):
        """
        Run tumbling window aggregation.
        
        Args:
            window_size_minutes: Window size in minutes
        """
        if not self.t_env:
            logger.info(f"Simulating {window_size_minutes}m tumbling window aggregation")
            return
        
        aggregation_sql = f"""
            INSERT INTO features_sink
            SELECT
                CONCAT('feat_', CAST(TUMBLE_START(event_time, INTERVAL '{window_size_minutes}' MINUTE) AS STRING)) as feature_id,
                TUMBLE_START(event_time, INTERVAL '{window_size_minutes}' MINUTE) as window_start,
                TUMBLE_END(event_time, INTERVAL '{window_size_minutes}' MINUTE) as window_end,
                'tumbling_{window_size_minutes}m' as window_type,
                src_ip,
                dest_ip,
                transport,
                COUNT(*) as packet_count,
                SUM(bytes) as total_bytes,
                AVG(CAST(bytes AS DOUBLE)) as packet_size_mean,
                CASE 
                    WHEN TIMESTAMPDIFF(SECOND, MIN(event_time), MAX(event_time)) > 0 
                    THEN CAST(SUM(bytes) AS DOUBLE) / TIMESTAMPDIFF(SECOND, MIN(event_time), MAX(event_time))
                    ELSE 0
                END as byte_rate,
                0.0 as src_ip_entropy,
                0.0 as dst_ip_entropy,
                COUNT(DISTINCT src_ip) as unique_src_ips,
                COUNT(DISTINCT dest_ip) as unique_dst_ips,
                CAST(SUM(CASE WHEN transport = 'TCP' THEN 1 ELSE 0 END) AS DOUBLE) / COUNT(*) as tcp_ratio,
                CAST(SUM(CASE WHEN tcp_flags IS NOT NULL AND tcp_flags & 2 > 0 THEN 1 ELSE 0 END) AS DOUBLE) / 
                    NULLIF(SUM(CASE WHEN transport = 'TCP' THEN 1 ELSE 0 END), 0) as syn_ratio
            FROM traffic_source
            GROUP BY 
                TUMBLE(event_time, INTERVAL '{window_size_minutes}' MINUTE),
                src_ip,
                dest_ip,
                transport
        """
        
        self.t_env.execute_sql(aggregation_sql)
        logger.info(f"Started {window_size_minutes}m tumbling window aggregation")
    
    def run(self):
        """Run the feature extraction job."""
        logger.info("Starting SENTINEL Feature Extraction Job")
        
        # Setup environment
        self.setup_environment()
        
        if self.env and self.t_env:
            # Create sources and sinks
            self.create_kafka_source()
            self.create_kafka_sink()
            
            # Run window aggregations
            self.run_tumbling_window_aggregation(1)   # 1 minute
            self.run_tumbling_window_aggregation(5)   # 5 minutes
            self.run_tumbling_window_aggregation(15)  # 15 minutes
            
            logger.info("Feature extraction job running")
        else:
            logger.info("Running in development mode (no Flink)")
            self._run_development_mode()
    
    def _run_development_mode(self):
        """Run in development mode without Flink."""
        import time
        
        logger.info("Development mode: Simulating feature extraction")
        
        # Simulate processing
        sample_records = [
            {
                'event_id': f'evt_{i}',
                'event_time': datetime.utcnow().isoformat(),
                'src_ip': f'192.168.1.{i % 255}',
                'dest_ip': f'10.0.0.{i % 255}',
                'src_port': 50000 + i,
                'dest_port': 443,
                'transport': 'TCP',
                'bytes': 1000 + i * 100,
                'packets': 1,
                'direction': 'outbound',
                'tcp_flags': 0x02 if i % 5 == 0 else 0x10
            }
            for i in range(100)
        ]
        
        # Compute features
        stats = compute_statistical_features(sample_records)
        behavioral = compute_behavioral_features(sample_records)
        
        features = {
            **stats.to_dict(),
            **behavioral.to_dict(),
            'window_type': 'development',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Computed features: {json.dumps(features, indent=2)}")
        
        return features


def main():
    """Main entry point for the feature extraction job."""
    job = FeatureExtractionJob()
    job.run()


if __name__ == '__main__':
    main()
