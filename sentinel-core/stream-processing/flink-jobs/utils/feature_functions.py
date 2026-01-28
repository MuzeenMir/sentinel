"""
Feature extraction functions for Flink stream processing.

These functions compute statistical, behavioral, and flow-based
features from network traffic data.
"""
import math
from typing import Dict, List, Any, Optional
from collections import Counter
from dataclasses import dataclass, field
import json


@dataclass
class StatisticalFeatures:
    """Container for statistical features."""
    # Packet size statistics
    packet_count: int = 0
    total_bytes: int = 0
    packet_size_mean: float = 0.0
    packet_size_std: float = 0.0
    packet_size_min: float = 0.0
    packet_size_max: float = 0.0
    packet_size_q25: float = 0.0
    packet_size_q50: float = 0.0
    packet_size_q75: float = 0.0
    
    # Inter-arrival time statistics
    iat_mean: float = 0.0
    iat_std: float = 0.0
    iat_min: float = 0.0
    iat_max: float = 0.0
    
    # Rate statistics
    byte_rate: float = 0.0
    packet_rate: float = 0.0
    
    # Duration
    duration: float = 0.0
    
    def to_dict(self) -> Dict[str, float]:
        return {
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'packet_size_mean': self.packet_size_mean,
            'packet_size_std': self.packet_size_std,
            'packet_size_min': self.packet_size_min,
            'packet_size_max': self.packet_size_max,
            'packet_size_q25': self.packet_size_q25,
            'packet_size_q50': self.packet_size_q50,
            'packet_size_q75': self.packet_size_q75,
            'iat_mean': self.iat_mean,
            'iat_std': self.iat_std,
            'iat_min': self.iat_min,
            'iat_max': self.iat_max,
            'byte_rate': self.byte_rate,
            'packet_rate': self.packet_rate,
            'duration': self.duration
        }


@dataclass
class BehavioralFeatures:
    """Container for behavioral features."""
    # Entropy features
    src_ip_entropy: float = 0.0
    dst_ip_entropy: float = 0.0
    src_port_entropy: float = 0.0
    dst_port_entropy: float = 0.0
    
    # Connection features
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_src_ports: int = 0
    unique_dst_ports: int = 0
    
    # Pattern features
    connection_fan_out: float = 0.0
    connection_fan_in: float = 0.0
    
    # Protocol distribution
    tcp_ratio: float = 0.0
    udp_ratio: float = 0.0
    icmp_ratio: float = 0.0
    
    # TCP flag ratios
    syn_ratio: float = 0.0
    ack_ratio: float = 0.0
    fin_ratio: float = 0.0
    rst_ratio: float = 0.0
    
    def to_dict(self) -> Dict[str, float]:
        return {
            'src_ip_entropy': self.src_ip_entropy,
            'dst_ip_entropy': self.dst_ip_entropy,
            'src_port_entropy': self.src_port_entropy,
            'dst_port_entropy': self.dst_port_entropy,
            'unique_src_ips': self.unique_src_ips,
            'unique_dst_ips': self.unique_dst_ips,
            'unique_src_ports': self.unique_src_ports,
            'unique_dst_ports': self.unique_dst_ports,
            'connection_fan_out': self.connection_fan_out,
            'connection_fan_in': self.connection_fan_in,
            'tcp_ratio': self.tcp_ratio,
            'udp_ratio': self.udp_ratio,
            'icmp_ratio': self.icmp_ratio,
            'syn_ratio': self.syn_ratio,
            'ack_ratio': self.ack_ratio,
            'fin_ratio': self.fin_ratio,
            'rst_ratio': self.rst_ratio
        }


def compute_statistical_features(records: List[Dict[str, Any]]) -> StatisticalFeatures:
    """
    Compute statistical features from a list of traffic records.
    
    Args:
        records: List of CIM-normalized traffic records
        
    Returns:
        StatisticalFeatures object
    """
    features = StatisticalFeatures()
    
    if not records:
        return features
    
    # Extract packet sizes
    sizes = [r.get('bytes', 0) for r in records if r.get('bytes', 0) > 0]
    
    if sizes:
        features.packet_count = len(sizes)
        features.total_bytes = sum(sizes)
        features.packet_size_mean = features.total_bytes / features.packet_count
        
        # Calculate standard deviation
        if len(sizes) > 1:
            variance = sum((s - features.packet_size_mean) ** 2 for s in sizes) / len(sizes)
            features.packet_size_std = math.sqrt(variance)
        
        features.packet_size_min = min(sizes)
        features.packet_size_max = max(sizes)
        
        # Calculate quartiles
        sorted_sizes = sorted(sizes)
        n = len(sorted_sizes)
        features.packet_size_q25 = sorted_sizes[n // 4] if n >= 4 else sorted_sizes[0]
        features.packet_size_q50 = sorted_sizes[n // 2] if n >= 2 else sorted_sizes[0]
        features.packet_size_q75 = sorted_sizes[3 * n // 4] if n >= 4 else sorted_sizes[-1]
    
    # Extract timestamps and compute inter-arrival times
    timestamps = []
    for r in records:
        ts = r.get('event_time') or r.get('timestamp')
        if ts:
            if isinstance(ts, str):
                # Parse ISO format timestamp
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    timestamps.append(dt.timestamp())
                except:
                    pass
            elif isinstance(ts, (int, float)):
                timestamps.append(ts)
    
    if len(timestamps) > 1:
        timestamps = sorted(timestamps)
        iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        iats = [iat for iat in iats if iat >= 0]
        
        if iats:
            features.iat_mean = sum(iats) / len(iats)
            if len(iats) > 1:
                variance = sum((iat - features.iat_mean) ** 2 for iat in iats) / len(iats)
                features.iat_std = math.sqrt(variance)
            features.iat_min = min(iats)
            features.iat_max = max(iats)
        
        # Calculate duration and rates
        features.duration = timestamps[-1] - timestamps[0]
        if features.duration > 0:
            features.byte_rate = features.total_bytes / features.duration
            features.packet_rate = features.packet_count / features.duration
    
    return features


def compute_entropy(values: List[Any]) -> float:
    """
    Compute Shannon entropy of a list of values.
    
    Args:
        values: List of values
        
    Returns:
        Shannon entropy value
    """
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


def compute_behavioral_features(records: List[Dict[str, Any]]) -> BehavioralFeatures:
    """
    Compute behavioral features from a list of traffic records.
    
    Args:
        records: List of CIM-normalized traffic records
        
    Returns:
        BehavioralFeatures object
    """
    features = BehavioralFeatures()
    
    if not records:
        return features
    
    # Extract field values
    src_ips = [r.get('src_ip', '') for r in records if r.get('src_ip')]
    dst_ips = [r.get('dest_ip', '') for r in records if r.get('dest_ip')]
    src_ports = [r.get('src_port', 0) for r in records if r.get('src_port')]
    dst_ports = [r.get('dest_port', 0) for r in records if r.get('dest_port')]
    protocols = [r.get('transport', 'unknown').upper() for r in records]
    tcp_flags = [r.get('tcp_flags', 0) for r in records if r.get('transport', '').upper() == 'TCP']
    
    # Compute entropy features
    features.src_ip_entropy = compute_entropy(src_ips)
    features.dst_ip_entropy = compute_entropy(dst_ips)
    features.src_port_entropy = compute_entropy(src_ports)
    features.dst_port_entropy = compute_entropy(dst_ports)
    
    # Compute unique counts
    features.unique_src_ips = len(set(src_ips))
    features.unique_dst_ips = len(set(dst_ips))
    features.unique_src_ports = len(set(src_ports))
    features.unique_dst_ports = len(set(dst_ports))
    
    # Compute connection patterns
    src_to_dst = {}
    dst_to_src = {}
    for r in records:
        src = r.get('src_ip', '')
        dst = r.get('dest_ip', '')
        if src and dst:
            if src not in src_to_dst:
                src_to_dst[src] = set()
            src_to_dst[src].add(dst)
            
            if dst not in dst_to_src:
                dst_to_src[dst] = set()
            dst_to_src[dst].add(src)
    
    if src_to_dst:
        fan_outs = [len(dsts) for dsts in src_to_dst.values()]
        features.connection_fan_out = sum(fan_outs) / len(fan_outs)
    
    if dst_to_src:
        fan_ins = [len(srcs) for srcs in dst_to_src.values()]
        features.connection_fan_in = sum(fan_ins) / len(fan_ins)
    
    # Compute protocol distribution
    total = len(protocols)
    if total > 0:
        proto_counts = Counter(protocols)
        features.tcp_ratio = proto_counts.get('TCP', 0) / total
        features.udp_ratio = proto_counts.get('UDP', 0) / total
        features.icmp_ratio = proto_counts.get('ICMP', 0) / total
    
    # Compute TCP flag ratios
    if tcp_flags:
        total_tcp = len(tcp_flags)
        syn_count = sum(1 for f in tcp_flags if f and f & 0x02)
        ack_count = sum(1 for f in tcp_flags if f and f & 0x10)
        fin_count = sum(1 for f in tcp_flags if f and f & 0x01)
        rst_count = sum(1 for f in tcp_flags if f and f & 0x04)
        
        features.syn_ratio = syn_count / total_tcp
        features.ack_ratio = ack_count / total_tcp
        features.fin_ratio = fin_count / total_tcp
        features.rst_ratio = rst_count / total_tcp
    
    return features


def compute_flow_features(records: List[Dict[str, Any]], 
                         key_fields: List[str] = None) -> Dict[str, Any]:
    """
    Compute flow-level features for a grouped set of records.
    
    Args:
        records: List of records belonging to the same flow
        key_fields: Fields used to group the flow
        
    Returns:
        Dictionary of flow features
    """
    if not records:
        return {}
    
    if key_fields is None:
        key_fields = ['src_ip', 'dest_ip', 'src_port', 'dest_port', 'transport']
    
    # Get flow key
    first_record = records[0]
    flow_key = {field: first_record.get(field) for field in key_fields}
    
    # Compute statistical features
    stats = compute_statistical_features(records)
    
    # Compute behavioral features
    behavioral = compute_behavioral_features(records)
    
    # Combine into flow features
    flow_features = {
        'flow_key': flow_key,
        'record_count': len(records),
        **stats.to_dict(),
        **behavioral.to_dict(),
        
        # Flow-specific features
        'first_seen': min(r.get('event_time', '') for r in records),
        'last_seen': max(r.get('event_time', '') for r in records),
        
        # Direction analysis
        'inbound_bytes': sum(r.get('bytes', 0) for r in records if r.get('direction') == 'inbound'),
        'outbound_bytes': sum(r.get('bytes', 0) for r in records if r.get('direction') == 'outbound'),
        'internal_bytes': sum(r.get('bytes', 0) for r in records if r.get('direction') == 'internal'),
    }
    
    return flow_features


def aggregate_window_features(feature_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate features across multiple flows in a window.
    
    Args:
        feature_list: List of flow feature dictionaries
        
    Returns:
        Aggregated window-level features
    """
    if not feature_list:
        return {}
    
    aggregated = {
        'window_flow_count': len(feature_list),
        'window_total_packets': sum(f.get('packet_count', 0) for f in feature_list),
        'window_total_bytes': sum(f.get('total_bytes', 0) for f in feature_list),
        
        # Aggregate statistical features
        'window_avg_packet_size': 0.0,
        'window_avg_byte_rate': 0.0,
        'window_avg_packet_rate': 0.0,
        
        # Aggregate behavioral features
        'window_avg_entropy': 0.0,
        'window_unique_src_ips': 0,
        'window_unique_dst_ips': 0,
        
        # Protocol distribution
        'window_tcp_flow_ratio': 0.0,
        'window_udp_flow_ratio': 0.0,
    }
    
    # Calculate averages
    total_packets = aggregated['window_total_packets']
    total_bytes = aggregated['window_total_bytes']
    n_flows = len(feature_list)
    
    if total_packets > 0:
        aggregated['window_avg_packet_size'] = total_bytes / total_packets
    
    byte_rates = [f.get('byte_rate', 0) for f in feature_list if f.get('byte_rate', 0) > 0]
    if byte_rates:
        aggregated['window_avg_byte_rate'] = sum(byte_rates) / len(byte_rates)
    
    packet_rates = [f.get('packet_rate', 0) for f in feature_list if f.get('packet_rate', 0) > 0]
    if packet_rates:
        aggregated['window_avg_packet_rate'] = sum(packet_rates) / len(packet_rates)
    
    # Aggregate entropy
    entropies = [f.get('src_ip_entropy', 0) + f.get('dst_ip_entropy', 0) for f in feature_list]
    if entropies:
        aggregated['window_avg_entropy'] = sum(entropies) / (2 * len(entropies))
    
    # Count unique IPs across all flows
    all_src_ips = set()
    all_dst_ips = set()
    tcp_flows = 0
    udp_flows = 0
    
    for f in feature_list:
        flow_key = f.get('flow_key', {})
        if flow_key.get('src_ip'):
            all_src_ips.add(flow_key['src_ip'])
        if flow_key.get('dest_ip'):
            all_dst_ips.add(flow_key['dest_ip'])
        
        transport = flow_key.get('transport', '').upper()
        if transport == 'TCP':
            tcp_flows += 1
        elif transport == 'UDP':
            udp_flows += 1
    
    aggregated['window_unique_src_ips'] = len(all_src_ips)
    aggregated['window_unique_dst_ips'] = len(all_dst_ips)
    
    if n_flows > 0:
        aggregated['window_tcp_flow_ratio'] = tcp_flows / n_flows
        aggregated['window_udp_flow_ratio'] = udp_flows / n_flows
    
    return aggregated
