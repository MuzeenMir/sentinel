"""
Serialization utilities for Flink stream processing.
"""
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class TrafficRecordSchema:
    """Schema for incoming traffic records."""
    event_id: str
    event_time: str
    source_type: str
    src_ip: str
    dest_ip: str
    src_port: Optional[int]
    dest_port: Optional[int]
    transport: str
    bytes: int
    packets: int
    direction: str
    duration: float = 0.0
    tcp_flags: Optional[int] = None
    is_internal: bool = False
    raw_hash: str = ""
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TrafficRecordSchema':
        """Create from dictionary."""
        return cls(
            event_id=data.get('event_id', ''),
            event_time=data.get('event_time', datetime.utcnow().isoformat()),
            source_type=data.get('source_type', 'unknown'),
            src_ip=data.get('src_ip', ''),
            dest_ip=data.get('dest_ip', ''),
            src_port=data.get('src_port'),
            dest_port=data.get('dest_port'),
            transport=data.get('transport', 'unknown'),
            bytes=data.get('bytes', 0),
            packets=data.get('packets', 1),
            direction=data.get('direction', 'unknown'),
            duration=data.get('duration', 0.0),
            tcp_flags=data.get('tcp_flags'),
            is_internal=data.get('is_internal', False),
            raw_hash=data.get('raw_hash', '')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class FeatureRecordSchema:
    """Schema for extracted feature records."""
    feature_id: str
    window_start: str
    window_end: str
    window_type: str  # tumbling_1m, tumbling_5m, sliding, session
    
    # Key fields
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    transport: Optional[str] = None
    
    # Statistical features
    packet_count: int = 0
    total_bytes: int = 0
    packet_size_mean: float = 0.0
    packet_size_std: float = 0.0
    byte_rate: float = 0.0
    packet_rate: float = 0.0
    
    # Behavioral features
    src_ip_entropy: float = 0.0
    dst_ip_entropy: float = 0.0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    tcp_ratio: float = 0.0
    syn_ratio: float = 0.0
    
    # Aggregated window features
    window_flow_count: int = 0
    window_total_packets: int = 0
    window_total_bytes: int = 0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FeatureRecordSchema':
        """Create from dictionary."""
        return cls(
            feature_id=data.get('feature_id', ''),
            window_start=data.get('window_start', ''),
            window_end=data.get('window_end', ''),
            window_type=data.get('window_type', 'unknown'),
            src_ip=data.get('src_ip'),
            dest_ip=data.get('dest_ip'),
            transport=data.get('transport'),
            packet_count=data.get('packet_count', 0),
            total_bytes=data.get('total_bytes', 0),
            packet_size_mean=data.get('packet_size_mean', 0.0),
            packet_size_std=data.get('packet_size_std', 0.0),
            byte_rate=data.get('byte_rate', 0.0),
            packet_rate=data.get('packet_rate', 0.0),
            src_ip_entropy=data.get('src_ip_entropy', 0.0),
            dst_ip_entropy=data.get('dst_ip_entropy', 0.0),
            unique_src_ips=data.get('unique_src_ips', 0),
            unique_dst_ips=data.get('unique_dst_ips', 0),
            tcp_ratio=data.get('tcp_ratio', 0.0),
            syn_ratio=data.get('syn_ratio', 0.0),
            window_flow_count=data.get('window_flow_count', 0),
            window_total_packets=data.get('window_total_packets', 0),
            window_total_bytes=data.get('window_total_bytes', 0)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


def serialize_features(features: Dict[str, Any]) -> bytes:
    """
    Serialize feature dictionary to JSON bytes.
    
    Args:
        features: Feature dictionary
        
    Returns:
        JSON-encoded bytes
    """
    return json.dumps(features, default=str).encode('utf-8')


def deserialize_traffic(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Deserialize traffic record from JSON bytes.
    
    Args:
        data: JSON-encoded bytes
        
    Returns:
        Parsed dictionary or None if parsing fails
    """
    try:
        return json.loads(data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def create_flow_key(record: Dict[str, Any]) -> str:
    """
    Create a unique flow key from a traffic record.
    
    Args:
        record: Traffic record dictionary
        
    Returns:
        String flow key
    """
    parts = [
        str(record.get('src_ip', '')),
        str(record.get('dest_ip', '')),
        str(record.get('src_port', '')),
        str(record.get('dest_port', '')),
        str(record.get('transport', '')).upper()
    ]
    return ':'.join(parts)


def create_bidirectional_flow_key(record: Dict[str, Any]) -> str:
    """
    Create a bidirectional flow key (same key for both directions).
    
    Args:
        record: Traffic record dictionary
        
    Returns:
        String flow key (normalized)
    """
    src_ip = str(record.get('src_ip', ''))
    dest_ip = str(record.get('dest_ip', ''))
    src_port = str(record.get('src_port', ''))
    dest_port = str(record.get('dest_port', ''))
    transport = str(record.get('transport', '')).upper()
    
    # Sort endpoints to create consistent key regardless of direction
    endpoint1 = f"{src_ip}:{src_port}"
    endpoint2 = f"{dest_ip}:{dest_port}"
    
    if endpoint1 < endpoint2:
        return f"{endpoint1}|{endpoint2}|{transport}"
    else:
        return f"{endpoint2}|{endpoint1}|{transport}"
