"""
Statistical feature extraction for network traffic.

Extracts packet-level statistical features including:
- Packet size distribution
- Inter-arrival times
- Byte rates
- Protocol statistics
"""
import logging
from typing import Dict, List, Any, Optional
import numpy as np
from collections import defaultdict

logger = logging.getLogger(__name__)


class StatisticalFeatureExtractor:
    """
    Extract statistical features from network traffic data.
    
    Features extracted:
    - Packet size statistics (mean, std, min, max, quartiles)
    - Inter-arrival time statistics
    - Byte rate and packet rate
    - Protocol distribution
    - Port statistics
    - TCP flag statistics
    """
    
    # Feature names for reference
    FEATURE_NAMES = [
        # Packet size features
        'packet_size_mean', 'packet_size_std', 'packet_size_min', 
        'packet_size_max', 'packet_size_q25', 'packet_size_q50', 
        'packet_size_q75', 'packet_size_iqr',
        
        # Inter-arrival time features
        'iat_mean', 'iat_std', 'iat_min', 'iat_max',
        'iat_q25', 'iat_q50', 'iat_q75',
        
        # Rate features
        'byte_rate', 'packet_rate', 'bytes_per_packet',
        
        # Protocol features
        'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'other_proto_ratio',
        
        # Port features
        'src_port_mean', 'src_port_std', 'dst_port_mean', 'dst_port_std',
        'well_known_port_ratio', 'ephemeral_port_ratio',
        
        # TCP flag features
        'syn_ratio', 'ack_ratio', 'fin_ratio', 'rst_ratio',
        'psh_ratio', 'urg_ratio',
        
        # Flow direction features
        'fwd_packet_ratio', 'bwd_packet_ratio',
        'fwd_byte_ratio', 'bwd_byte_ratio',
        
        # Additional statistical features
        'packet_count', 'total_bytes', 'duration'
    ]
    
    def __init__(self):
        self.n_features = len(self.FEATURE_NAMES)
    
    def extract(self, data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract statistical features from traffic data.
        
        Args:
            data: Dictionary containing traffic data with fields:
                - packets: List of packet info dicts
                - or individual packet fields (packet_size, timestamp, etc.)
                
        Returns:
            Dictionary of feature name -> value
        """
        try:
            # Handle different input formats
            if 'packets' in data:
                return self._extract_from_packets(data['packets'])
            elif 'flow' in data:
                return self._extract_from_flow(data['flow'])
            else:
                return self._extract_from_single(data)
                
        except Exception as e:
            logger.error(f"Statistical feature extraction error: {e}")
            return self._get_default_features()
    
    def extract_array(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract features as numpy array."""
        features = self.extract(data)
        return np.array([features.get(name, 0.0) for name in self.FEATURE_NAMES])
    
    def _extract_from_packets(self, packets: List[Dict]) -> Dict[str, float]:
        """Extract features from a list of packets."""
        if not packets:
            return self._get_default_features()
        
        features = {}
        
        # Extract packet sizes
        sizes = [p.get('length', p.get('packet_size', 0)) for p in packets]
        sizes = [s for s in sizes if s > 0]
        
        if sizes:
            features.update(self._calculate_distribution_stats(sizes, 'packet_size'))
        
        # Extract inter-arrival times
        timestamps = [p.get('timestamp', 0) for p in packets]
        if len(timestamps) > 1:
            # Convert timestamps if needed
            if isinstance(timestamps[0], str):
                from datetime import datetime
                timestamps = [datetime.fromisoformat(t.replace('Z', '+00:00')).timestamp() 
                             for t in timestamps if t]
            
            timestamps = sorted(timestamps)
            iats = np.diff(timestamps)
            iats = iats[iats >= 0]  # Filter negative values
            
            if len(iats) > 0:
                features.update(self._calculate_distribution_stats(iats, 'iat'))
        
        # Calculate rates
        if timestamps and len(timestamps) > 1:
            duration = max(timestamps) - min(timestamps)
            if duration > 0:
                features['duration'] = duration
                features['byte_rate'] = sum(sizes) / duration if sizes else 0
                features['packet_rate'] = len(packets) / duration
            else:
                features['duration'] = 0
                features['byte_rate'] = 0
                features['packet_rate'] = 0
        
        features['packet_count'] = len(packets)
        features['total_bytes'] = sum(sizes) if sizes else 0
        features['bytes_per_packet'] = features['total_bytes'] / max(len(packets), 1)
        
        # Protocol distribution
        protocols = [p.get('protocol', 'unknown') for p in packets]
        features.update(self._calculate_protocol_stats(protocols))
        
        # Port statistics
        src_ports = [p.get('source_port', p.get('src_port', 0)) for p in packets]
        dst_ports = [p.get('dest_port', p.get('destination_port', 0)) for p in packets]
        features.update(self._calculate_port_stats(src_ports, dst_ports))
        
        # TCP flag statistics
        flags = [p.get('flags', p.get('tcp_flags', 0)) for p in packets]
        features.update(self._calculate_flag_stats(flags))
        
        # Fill missing features with defaults
        for name in self.FEATURE_NAMES:
            if name not in features:
                features[name] = 0.0
        
        return features
    
    def _extract_from_flow(self, flow: Dict) -> Dict[str, float]:
        """Extract features from flow summary data."""
        features = {}
        
        # Direct flow statistics
        features['packet_size_mean'] = flow.get('packet_size_mean', 0)
        features['packet_size_std'] = flow.get('packet_size_std', 0)
        features['packet_size_min'] = flow.get('packet_size_min', 0)
        features['packet_size_max'] = flow.get('packet_size_max', 0)
        
        features['iat_mean'] = flow.get('iat_mean', 0)
        features['iat_std'] = flow.get('iat_std', 0)
        
        features['byte_rate'] = flow.get('byte_rate', flow.get('bytes_per_second', 0))
        features['packet_rate'] = flow.get('packet_rate', flow.get('packets_per_second', 0))
        
        features['packet_count'] = flow.get('packet_count', flow.get('total_packets', 0))
        features['total_bytes'] = flow.get('total_bytes', 0)
        features['duration'] = flow.get('duration', 0)
        
        # Protocol
        protocol = flow.get('protocol', 'unknown').upper()
        features['tcp_ratio'] = 1.0 if protocol == 'TCP' else 0.0
        features['udp_ratio'] = 1.0 if protocol == 'UDP' else 0.0
        features['icmp_ratio'] = 1.0 if protocol == 'ICMP' else 0.0
        
        # Ports
        features['src_port_mean'] = float(flow.get('source_port', 0))
        features['dst_port_mean'] = float(flow.get('dest_port', flow.get('destination_port', 0)))
        
        # Fill defaults
        for name in self.FEATURE_NAMES:
            if name not in features:
                features[name] = 0.0
        
        return features
    
    def _extract_from_single(self, packet: Dict) -> Dict[str, float]:
        """Extract features from a single packet."""
        features = {}
        
        # Single packet features
        size = packet.get('length', packet.get('packet_size', 0))
        features['packet_size_mean'] = size
        features['packet_size_std'] = 0
        features['packet_size_min'] = size
        features['packet_size_max'] = size
        
        features['packet_count'] = 1
        features['total_bytes'] = size
        features['bytes_per_packet'] = size
        
        # Protocol
        protocol = str(packet.get('protocol', 'unknown')).upper()
        features['tcp_ratio'] = 1.0 if protocol == 'TCP' else 0.0
        features['udp_ratio'] = 1.0 if protocol == 'UDP' else 0.0
        features['icmp_ratio'] = 1.0 if protocol == 'ICMP' else 0.0
        
        # Ports
        features['src_port_mean'] = float(packet.get('source_port', packet.get('src_port', 0)))
        features['dst_port_mean'] = float(packet.get('dest_port', packet.get('destination_port', 0)))
        
        # TCP flags
        flags = packet.get('flags', packet.get('tcp_flags', 0))
        if isinstance(flags, int):
            features['syn_ratio'] = 1.0 if flags & 0x02 else 0.0
            features['ack_ratio'] = 1.0 if flags & 0x10 else 0.0
            features['fin_ratio'] = 1.0 if flags & 0x01 else 0.0
            features['rst_ratio'] = 1.0 if flags & 0x04 else 0.0
            features['psh_ratio'] = 1.0 if flags & 0x08 else 0.0
        
        # Fill defaults
        for name in self.FEATURE_NAMES:
            if name not in features:
                features[name] = 0.0
        
        return features
    
    def _calculate_distribution_stats(self, values: List[float], 
                                      prefix: str) -> Dict[str, float]:
        """Calculate distribution statistics."""
        if not values:
            return {}
        
        arr = np.array(values)
        stats = {
            f'{prefix}_mean': float(np.mean(arr)),
            f'{prefix}_std': float(np.std(arr)),
            f'{prefix}_min': float(np.min(arr)),
            f'{prefix}_max': float(np.max(arr)),
            f'{prefix}_q25': float(np.percentile(arr, 25)),
            f'{prefix}_q50': float(np.percentile(arr, 50)),
            f'{prefix}_q75': float(np.percentile(arr, 75)),
        }
        stats[f'{prefix}_iqr'] = stats[f'{prefix}_q75'] - stats[f'{prefix}_q25']
        
        return stats
    
    def _calculate_protocol_stats(self, protocols: List[str]) -> Dict[str, float]:
        """Calculate protocol distribution."""
        if not protocols:
            return {}
        
        total = len(protocols)
        proto_counts = defaultdict(int)
        for proto in protocols:
            proto_counts[str(proto).upper()] += 1
        
        return {
            'tcp_ratio': proto_counts.get('TCP', 0) / total,
            'udp_ratio': proto_counts.get('UDP', 0) / total,
            'icmp_ratio': proto_counts.get('ICMP', 0) / total,
            'other_proto_ratio': sum(c for p, c in proto_counts.items() 
                                     if p not in ['TCP', 'UDP', 'ICMP']) / total
        }
    
    def _calculate_port_stats(self, src_ports: List[int], 
                              dst_ports: List[int]) -> Dict[str, float]:
        """Calculate port statistics."""
        stats = {}
        
        # Source ports
        src_ports = [p for p in src_ports if p and p > 0]
        if src_ports:
            stats['src_port_mean'] = float(np.mean(src_ports))
            stats['src_port_std'] = float(np.std(src_ports))
        
        # Destination ports
        dst_ports = [p for p in dst_ports if p and p > 0]
        if dst_ports:
            stats['dst_port_mean'] = float(np.mean(dst_ports))
            stats['dst_port_std'] = float(np.std(dst_ports))
        
        # Port ranges
        all_ports = src_ports + dst_ports
        if all_ports:
            well_known = sum(1 for p in all_ports if p < 1024)
            ephemeral = sum(1 for p in all_ports if p >= 49152)
            total = len(all_ports)
            
            stats['well_known_port_ratio'] = well_known / total
            stats['ephemeral_port_ratio'] = ephemeral / total
        
        return stats
    
    def _calculate_flag_stats(self, flags: List[int]) -> Dict[str, float]:
        """Calculate TCP flag statistics."""
        if not flags:
            return {}
        
        total = len(flags)
        flag_counts = {
            'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0, 'psh': 0, 'urg': 0
        }
        
        for f in flags:
            if isinstance(f, int):
                if f & 0x02: flag_counts['syn'] += 1
                if f & 0x10: flag_counts['ack'] += 1
                if f & 0x01: flag_counts['fin'] += 1
                if f & 0x04: flag_counts['rst'] += 1
                if f & 0x08: flag_counts['psh'] += 1
                if f & 0x20: flag_counts['urg'] += 1
        
        return {
            'syn_ratio': flag_counts['syn'] / total,
            'ack_ratio': flag_counts['ack'] / total,
            'fin_ratio': flag_counts['fin'] / total,
            'rst_ratio': flag_counts['rst'] / total,
            'psh_ratio': flag_counts['psh'] / total,
            'urg_ratio': flag_counts['urg'] / total
        }
    
    def _get_default_features(self) -> Dict[str, float]:
        """Get default feature values."""
        return {name: 0.0 for name in self.FEATURE_NAMES}
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return self.FEATURE_NAMES.copy()
