"""
Behavioral feature extraction for network traffic.

Extracts session-level and behavioral patterns including:
- Session entropy
- Protocol deviation scores
- Connection patterns
- Flow characteristics
"""
import logging
from typing import Dict, List, Any, Optional
import numpy as np
from collections import Counter, defaultdict
import math

logger = logging.getLogger(__name__)


class BehavioralFeatureExtractor:
    """
    Extract behavioral features from network sessions and flows.
    
    Features extracted:
    - Session entropy (measure of randomness)
    - Protocol deviation (deviation from normal patterns)
    - Connection patterns (repeated connections, fan-out)
    - Temporal patterns (burst detection, periodicity)
    """
    
    FEATURE_NAMES = [
        # Entropy features
        'src_ip_entropy', 'dst_ip_entropy', 'src_port_entropy', 
        'dst_port_entropy', 'payload_entropy',
        
        # Connection pattern features
        'unique_dst_ips', 'unique_dst_ports', 'unique_src_ports',
        'connection_fan_out', 'connection_fan_in',
        'avg_connections_per_dst', 'max_connections_per_dst',
        
        # Flow features
        'flow_duration_mean', 'flow_duration_std',
        'flows_per_minute', 'concurrent_flows',
        
        # Temporal features
        'burst_score', 'periodicity_score', 'time_variance',
        'off_hours_ratio', 'weekend_ratio',
        
        # Protocol deviation features
        'protocol_anomaly_score', 'port_anomaly_score',
        'size_anomaly_score', 'behavior_deviation_score',
        
        # Session features
        'session_count', 'avg_session_duration',
        'failed_connection_ratio', 'retransmission_ratio',
        
        # Payload features
        'payload_size_variance', 'small_payload_ratio',
        'large_payload_ratio', 'zero_payload_ratio'
    ]
    
    def __init__(self):
        self.n_features = len(self.FEATURE_NAMES)
        
        # Baseline statistics for deviation calculation
        self._baselines = {
            'normal_ports': {80, 443, 22, 21, 25, 53, 110, 143, 993, 995},
            'expected_protocol_dist': {'TCP': 0.7, 'UDP': 0.25, 'ICMP': 0.05},
            'normal_packet_size_mean': 500,
            'normal_packet_size_std': 300
        }
    
    def extract(self, data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract behavioral features from traffic data.
        
        Args:
            data: Dictionary containing session/flow data
            
        Returns:
            Dictionary of feature name -> value
        """
        try:
            features = {}
            
            # Extract from packets if available
            packets = data.get('packets', [])
            if packets:
                features.update(self._extract_entropy_features(packets))
                features.update(self._extract_connection_features(packets))
                features.update(self._extract_temporal_features(packets))
                features.update(self._extract_deviation_features(packets))
                features.update(self._extract_payload_features(packets))
            
            # Extract from flows if available
            flows = data.get('flows', [])
            if flows:
                features.update(self._extract_flow_features(flows))
            
            # Extract from session data
            session = data.get('session', {})
            if session:
                features.update(self._extract_session_features(session))
            
            # Fill missing features
            for name in self.FEATURE_NAMES:
                if name not in features:
                    features[name] = 0.0
            
            return features
            
        except Exception as e:
            logger.error(f"Behavioral feature extraction error: {e}")
            return self._get_default_features()
    
    def extract_array(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract features as numpy array."""
        features = self.extract(data)
        return np.array([features.get(name, 0.0) for name in self.FEATURE_NAMES])
    
    def _extract_entropy_features(self, packets: List[Dict]) -> Dict[str, float]:
        """Calculate entropy-based features."""
        features = {}
        
        # Source IP entropy
        src_ips = [p.get('source_ip', p.get('src_ip', '')) for p in packets]
        features['src_ip_entropy'] = self._calculate_entropy(src_ips)
        
        # Destination IP entropy
        dst_ips = [p.get('dest_ip', p.get('destination_ip', '')) for p in packets]
        features['dst_ip_entropy'] = self._calculate_entropy(dst_ips)
        
        # Port entropy
        src_ports = [str(p.get('source_port', p.get('src_port', 0))) for p in packets]
        dst_ports = [str(p.get('dest_port', p.get('destination_port', 0))) for p in packets]
        features['src_port_entropy'] = self._calculate_entropy(src_ports)
        features['dst_port_entropy'] = self._calculate_entropy(dst_ports)
        
        # Payload entropy (if payload hash is available)
        payloads = [p.get('payload_hash', '') for p in packets if p.get('payload_hash')]
        features['payload_entropy'] = self._calculate_entropy(payloads) if payloads else 0.0
        
        return features
    
    def _extract_connection_features(self, packets: List[Dict]) -> Dict[str, float]:
        """Extract connection pattern features."""
        features = {}
        
        # Unique destinations
        dst_ips = set(p.get('dest_ip', p.get('destination_ip', '')) for p in packets)
        dst_ports = set(p.get('dest_port', p.get('destination_port', 0)) for p in packets)
        src_ports = set(p.get('source_port', p.get('src_port', 0)) for p in packets)
        
        features['unique_dst_ips'] = len(dst_ips)
        features['unique_dst_ports'] = len(dst_ports)
        features['unique_src_ports'] = len(src_ports)
        
        # Connection fan-out (unique destinations per source)
        src_to_dst = defaultdict(set)
        for p in packets:
            src = p.get('source_ip', p.get('src_ip', ''))
            dst = p.get('dest_ip', p.get('destination_ip', ''))
            if src and dst:
                src_to_dst[src].add(dst)
        
        if src_to_dst:
            fan_outs = [len(dsts) for dsts in src_to_dst.values()]
            features['connection_fan_out'] = float(np.mean(fan_outs))
        else:
            features['connection_fan_out'] = 0.0
        
        # Connection fan-in (unique sources per destination)
        dst_to_src = defaultdict(set)
        for p in packets:
            src = p.get('source_ip', p.get('src_ip', ''))
            dst = p.get('dest_ip', p.get('destination_ip', ''))
            if src and dst:
                dst_to_src[dst].add(src)
        
        if dst_to_src:
            fan_ins = [len(srcs) for srcs in dst_to_src.values()]
            features['connection_fan_in'] = float(np.mean(fan_ins))
        else:
            features['connection_fan_in'] = 0.0
        
        # Connections per destination
        dst_counts = Counter(p.get('dest_ip', p.get('destination_ip', '')) for p in packets)
        if dst_counts:
            features['avg_connections_per_dst'] = float(np.mean(list(dst_counts.values())))
            features['max_connections_per_dst'] = float(max(dst_counts.values()))
        
        return features
    
    def _extract_temporal_features(self, packets: List[Dict]) -> Dict[str, float]:
        """Extract temporal pattern features."""
        features = {}
        
        # Get timestamps
        timestamps = []
        for p in packets:
            ts = p.get('timestamp')
            if ts:
                if isinstance(ts, str):
                    from datetime import datetime
                    try:
                        ts = datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp()
                    except:
                        continue
                timestamps.append(ts)
        
        if len(timestamps) < 2:
            return features
        
        timestamps = sorted(timestamps)
        
        # Time variance
        features['time_variance'] = float(np.var(timestamps))
        
        # Burst detection (high activity in short time)
        intervals = np.diff(timestamps)
        if len(intervals) > 0:
            # Burst score: ratio of very short intervals
            short_intervals = sum(1 for i in intervals if i < 0.1)  # < 100ms
            features['burst_score'] = short_intervals / len(intervals)
        
        # Periodicity detection
        if len(intervals) > 5:
            # Check for regular patterns using autocorrelation
            features['periodicity_score'] = self._calculate_periodicity(intervals)
        else:
            features['periodicity_score'] = 0.0
        
        # Time of day analysis
        from datetime import datetime
        hours = [datetime.fromtimestamp(ts).hour for ts in timestamps]
        
        # Off-hours ratio (outside 9am-6pm)
        off_hours = sum(1 for h in hours if h < 9 or h > 18)
        features['off_hours_ratio'] = off_hours / len(hours) if hours else 0.0
        
        # Weekend ratio
        days = [datetime.fromtimestamp(ts).weekday() for ts in timestamps]
        weekend = sum(1 for d in days if d >= 5)
        features['weekend_ratio'] = weekend / len(days) if days else 0.0
        
        return features
    
    def _extract_deviation_features(self, packets: List[Dict]) -> Dict[str, float]:
        """Calculate deviation from normal behavior."""
        features = {}
        
        # Protocol anomaly
        protocols = [str(p.get('protocol', 'unknown')).upper() for p in packets]
        protocol_dist = Counter(protocols)
        total = sum(protocol_dist.values())
        
        if total > 0:
            observed = {k: v/total for k, v in protocol_dist.items()}
            expected = self._baselines['expected_protocol_dist']
            
            # KL divergence-like score
            anomaly = 0
            for proto, exp_ratio in expected.items():
                obs_ratio = observed.get(proto, 0)
                if exp_ratio > 0:
                    anomaly += abs(obs_ratio - exp_ratio)
            features['protocol_anomaly_score'] = min(anomaly, 1.0)
        
        # Port anomaly
        dst_ports = [p.get('dest_port', p.get('destination_port', 0)) for p in packets]
        normal_ports = self._baselines['normal_ports']
        
        if dst_ports:
            abnormal = sum(1 for p in dst_ports if p and p not in normal_ports)
            features['port_anomaly_score'] = abnormal / len(dst_ports)
        
        # Size anomaly
        sizes = [p.get('length', p.get('packet_size', 0)) for p in packets]
        sizes = [s for s in sizes if s > 0]
        
        if sizes:
            mean_size = np.mean(sizes)
            expected_mean = self._baselines['normal_packet_size_mean']
            expected_std = self._baselines['normal_packet_size_std']
            
            # Z-score based anomaly
            z_score = abs(mean_size - expected_mean) / max(expected_std, 1)
            features['size_anomaly_score'] = min(z_score / 3, 1.0)  # Normalize to 0-1
        
        # Overall behavior deviation
        deviation_scores = [
            features.get('protocol_anomaly_score', 0),
            features.get('port_anomaly_score', 0),
            features.get('size_anomaly_score', 0)
        ]
        features['behavior_deviation_score'] = float(np.mean(deviation_scores))
        
        return features
    
    def _extract_flow_features(self, flows: List[Dict]) -> Dict[str, float]:
        """Extract features from flow data."""
        features = {}
        
        if not flows:
            return features
        
        # Flow durations
        durations = [f.get('duration', 0) for f in flows]
        durations = [d for d in durations if d > 0]
        
        if durations:
            features['flow_duration_mean'] = float(np.mean(durations))
            features['flow_duration_std'] = float(np.std(durations))
        
        features['concurrent_flows'] = len(flows)
        
        return features
    
    def _extract_session_features(self, session: Dict) -> Dict[str, float]:
        """Extract session-level features."""
        features = {}
        
        features['session_count'] = session.get('session_count', 1)
        features['avg_session_duration'] = session.get('avg_duration', 0)
        features['failed_connection_ratio'] = session.get('failed_ratio', 0)
        features['retransmission_ratio'] = session.get('retransmission_ratio', 0)
        
        return features
    
    def _extract_payload_features(self, packets: List[Dict]) -> Dict[str, float]:
        """Extract payload-related features."""
        features = {}
        
        payload_sizes = [p.get('payload_length', 0) for p in packets]
        
        if payload_sizes:
            features['payload_size_variance'] = float(np.var(payload_sizes))
            
            total = len(payload_sizes)
            features['small_payload_ratio'] = sum(1 for s in payload_sizes if 0 < s < 100) / total
            features['large_payload_ratio'] = sum(1 for s in payload_sizes if s > 1000) / total
            features['zero_payload_ratio'] = sum(1 for s in payload_sizes if s == 0) / total
        
        return features
    
    def _calculate_entropy(self, values: List[str]) -> float:
        """Calculate Shannon entropy of a list of values."""
        if not values:
            return 0.0
        
        counter = Counter(values)
        total = len(values)
        
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_periodicity(self, intervals: np.ndarray) -> float:
        """Calculate periodicity score from inter-arrival intervals."""
        if len(intervals) < 5:
            return 0.0
        
        # Simple autocorrelation at lag 1
        mean = np.mean(intervals)
        var = np.var(intervals)
        
        if var < 1e-10:
            return 1.0  # Perfect regularity
        
        autocorr = np.correlate(intervals - mean, intervals - mean, mode='full')
        autocorr = autocorr[len(autocorr)//2:]
        autocorr = autocorr / (var * len(intervals))
        
        # Return max autocorrelation (excluding lag 0)
        if len(autocorr) > 1:
            return float(np.max(np.abs(autocorr[1:min(10, len(autocorr))])))
        return 0.0
    
    def _get_default_features(self) -> Dict[str, float]:
        """Get default feature values."""
        return {name: 0.0 for name in self.FEATURE_NAMES}
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return self.FEATURE_NAMES.copy()
