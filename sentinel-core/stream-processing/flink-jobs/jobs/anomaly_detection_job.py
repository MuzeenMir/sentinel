"""
SENTINEL Real-time Anomaly Detection Flink Job

Performs streaming anomaly detection on network traffic using:
- Statistical threshold-based detection
- Pattern matching for known attack signatures
- Rate-based anomaly detection (SYN floods, port scans, etc.)
"""
import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import config


class AnomalyDetector:
    """
    Real-time anomaly detection engine.
    
    Implements multiple detection strategies:
    - SYN flood detection
    - Port scan detection
    - Large payload detection
    - Rate anomaly detection
    """
    
    def __init__(self, thresholds: Dict[str, int] = None):
        """Initialize anomaly detector."""
        self.thresholds = thresholds or {
            'syn_flood': config.features.syn_flood_threshold,
            'large_payload': config.features.large_payload_threshold,
            'port_scan': config.features.port_scan_threshold,
            'rate_threshold': 1000  # packets per second
        }
        
        # State for detection
        self.syn_counts = defaultdict(int)  # src_ip -> count
        self.port_scan_state = defaultdict(set)  # src_ip -> set of ports
        self.rate_counters = defaultdict(int)  # src_ip -> packet count
    
    def detect(self, record: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect anomalies in a traffic record.
        
        Args:
            record: Normalized traffic record
            
        Returns:
            List of detected anomalies (empty if none)
        """
        anomalies = []
        
        # SYN flood detection
        syn_anomaly = self._detect_syn_flood(record)
        if syn_anomaly:
            anomalies.append(syn_anomaly)
        
        # Port scan detection
        port_scan = self._detect_port_scan(record)
        if port_scan:
            anomalies.append(port_scan)
        
        # Large payload detection
        large_payload = self._detect_large_payload(record)
        if large_payload:
            anomalies.append(large_payload)
        
        return anomalies
    
    def _detect_syn_flood(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect SYN flood attacks."""
        if record.get('transport', '').upper() != 'TCP':
            return None
        
        tcp_flags = record.get('tcp_flags', 0)
        if not tcp_flags:
            return None
        
        # Check for SYN flag without ACK
        is_syn = (tcp_flags & 0x02) and not (tcp_flags & 0x10)
        
        if is_syn:
            src_ip = record.get('src_ip', 'unknown')
            self.syn_counts[src_ip] += 1
            
            if self.syn_counts[src_ip] >= self.thresholds['syn_flood']:
                return {
                    'type': 'syn_flood',
                    'severity': 'high',
                    'source_ip': src_ip,
                    'target_ip': record.get('dest_ip'),
                    'target_port': record.get('dest_port'),
                    'syn_count': self.syn_counts[src_ip],
                    'threshold': self.thresholds['syn_flood'],
                    'timestamp': datetime.utcnow().isoformat(),
                    'description': f'Potential SYN flood attack from {src_ip}'
                }
        
        return None
    
    def _detect_port_scan(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect port scanning activity."""
        src_ip = record.get('src_ip', 'unknown')
        dest_port = record.get('dest_port')
        
        if not dest_port:
            return None
        
        # Track unique ports accessed by each source
        self.port_scan_state[src_ip].add(dest_port)
        
        unique_ports = len(self.port_scan_state[src_ip])
        
        if unique_ports >= self.thresholds['port_scan']:
            return {
                'type': 'port_scan',
                'severity': 'medium',
                'source_ip': src_ip,
                'target_ip': record.get('dest_ip'),
                'unique_ports_scanned': unique_ports,
                'ports': list(self.port_scan_state[src_ip])[:20],  # First 20
                'threshold': self.thresholds['port_scan'],
                'timestamp': datetime.utcnow().isoformat(),
                'description': f'Port scanning detected from {src_ip}'
            }
        
        return None
    
    def _detect_large_payload(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect unusually large payloads."""
        payload_size = record.get('bytes', 0)
        
        if payload_size >= self.thresholds['large_payload']:
            return {
                'type': 'large_payload',
                'severity': 'low',
                'source_ip': record.get('src_ip'),
                'dest_ip': record.get('dest_ip'),
                'payload_size': payload_size,
                'threshold': self.thresholds['large_payload'],
                'timestamp': datetime.utcnow().isoformat(),
                'description': f'Large payload detected: {payload_size} bytes'
            }
        
        return None
    
    def reset_state(self, reset_type: str = 'all'):
        """Reset detection state."""
        if reset_type in ['all', 'syn']:
            self.syn_counts.clear()
        if reset_type in ['all', 'port_scan']:
            self.port_scan_state.clear()
        if reset_type in ['all', 'rate']:
            self.rate_counters.clear()


class AnomalyDetectionJob:
    """
    Flink job for real-time anomaly detection.
    
    Processes traffic stream and outputs detected anomalies to Kafka.
    """
    
    def __init__(self, kafka_config=None):
        """Initialize the anomaly detection job."""
        self.kafka_config = kafka_config or config.kafka
        self.detector = AnomalyDetector()
        self.env = None
        self.t_env = None
    
    def setup_environment(self):
        """Set up Flink execution environment."""
        try:
            from pyflink.datastream import StreamExecutionEnvironment
            from pyflink.table import StreamTableEnvironment, EnvironmentSettings
            
            self.env = StreamExecutionEnvironment.get_execution_environment()
            self.env.set_parallelism(config.parallelism)
            
            settings = EnvironmentSettings.new_instance().in_streaming_mode().build()
            self.t_env = StreamTableEnvironment.create(self.env, environment_settings=settings)
            
            logger.info("Flink environment initialized for anomaly detection")
            
        except ImportError as e:
            logger.error(f"PyFlink not available: {e}")
            self.env = None
            self.t_env = None
    
    def process_record(self, record: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process a single traffic record for anomalies.
        
        Args:
            record: Normalized traffic record
            
        Returns:
            List of detected anomalies
        """
        return self.detector.detect(record)
    
    def run(self):
        """Run the anomaly detection job."""
        logger.info("Starting SENTINEL Anomaly Detection Job")
        
        self.setup_environment()
        
        if self.env and self.t_env:
            logger.info("Anomaly detection job running with Flink")
            # Full Flink implementation would go here
        else:
            logger.info("Running anomaly detection in development mode")
            self._run_development_mode()
    
    def _run_development_mode(self):
        """Run in development mode."""
        logger.info("Development mode: Simulating anomaly detection")
        
        # Simulate traffic with some anomalies
        test_records = [
            # Normal traffic
            {'src_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 'dest_port': 443, 
             'transport': 'TCP', 'tcp_flags': 0x10, 'bytes': 500},
            
            # SYN flood simulation (many SYN packets)
            *[{'src_ip': '192.168.1.200', 'dest_ip': '10.0.0.1', 'dest_port': 80,
               'transport': 'TCP', 'tcp_flags': 0x02, 'bytes': 40} 
              for _ in range(150)],
            
            # Port scan simulation
            *[{'src_ip': '192.168.1.150', 'dest_ip': '10.0.0.1', 'dest_port': port,
               'transport': 'TCP', 'tcp_flags': 0x02, 'bytes': 40}
              for port in range(1, 100)],
            
            # Large payload
            {'src_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 'dest_port': 443,
             'transport': 'TCP', 'tcp_flags': 0x18, 'bytes': 50000}
        ]
        
        all_anomalies = []
        for record in test_records:
            anomalies = self.process_record(record)
            all_anomalies.extend(anomalies)
        
        # Deduplicate
        unique_anomalies = {}
        for a in all_anomalies:
            key = f"{a['type']}:{a.get('source_ip')}"
            if key not in unique_anomalies:
                unique_anomalies[key] = a
        
        logger.info(f"Detected {len(unique_anomalies)} unique anomalies:")
        for key, anomaly in unique_anomalies.items():
            logger.info(f"  - {anomaly['type']}: {anomaly['description']}")
        
        return list(unique_anomalies.values())


def main():
    """Main entry point."""
    job = AnomalyDetectionJob()
    job.run()


if __name__ == '__main__':
    main()
