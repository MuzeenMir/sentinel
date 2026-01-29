"""
SENTINEL Enhanced Data Collector

Enterprise-grade network traffic collection with support for:
- Raw packet capture (PCAP)
- NetFlow v5/v9 protocol parsing
- sFlow protocol parsing
- CIM (Common Information Model) normalization
"""
import os
import json
import time
import threading
import socket
import struct
from flask import Flask, request, jsonify
from kafka import KafkaProducer
from datetime import datetime, timedelta
import logging
import re
from collections import defaultdict, deque
import redis
from typing import Dict, List, Any, Optional, Tuple
import hashlib
from functools import wraps
from enum import Enum
import ipaddress

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['KAFKA_BOOTSTRAP_SERVERS'] = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')
app.config['NETFLOW_PORT'] = int(os.environ.get('NETFLOW_PORT', '2055'))
app.config['SFLOW_PORT'] = int(os.environ.get('SFLOW_PORT', '6343'))
app.config['AI_ENGINE_URL'] = os.environ.get('AI_ENGINE_URL', 'http://ai-engine:5003')

# Initialize Kafka producer with error handling
try:
    producer = KafkaProducer(
        bootstrap_servers=app.config['KAFKA_BOOTSTRAP_SERVERS'],
        value_serializer=lambda x: json.dumps(x, default=str).encode('utf-8'),
        compression_type='gzip',
        acks='all',
        retries=3
    )
except Exception as e:
    logging.warning(f"Kafka producer init failed: {e}. Running in standalone mode.")
    producer = None

# Initialize Redis
redis_client = redis.from_url(app.config['REDIS_URL'])

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Protocol Constants
TCP_PROTOCOL = 6
UDP_PROTOCOL = 17
ICMP_PROTOCOL = 1

# NetFlow versions
NETFLOW_V5 = 5
NETFLOW_V9 = 9


class DataSourceType(Enum):
    """Data source types."""
    PCAP = "pcap"
    NETFLOW_V5 = "netflow_v5"
    NETFLOW_V9 = "netflow_v9"
    SFLOW = "sflow"
    API = "api"


class CIMNormalizer:
    """
    Common Information Model (CIM) normalizer for network traffic.
    
    Converts heterogeneous network data into a unified schema
    compatible with enterprise SIEM systems.
    """
    
    # CIM field mappings
    CIM_SCHEMA = {
        # Timestamp fields
        'timestamp': 'event_time',
        'start_time': 'flow_start_time',
        'end_time': 'flow_end_time',
        
        # Network fields
        'source_ip': 'src_ip',
        'dest_ip': 'dest_ip',
        'source_port': 'src_port',
        'dest_port': 'dest_port',
        'protocol': 'transport',
        
        # Traffic metrics
        'bytes': 'bytes',
        'packets': 'packets',
        'bytes_in': 'bytes_in',
        'bytes_out': 'bytes_out',
        
        # Identity fields
        'source_mac': 'src_mac',
        'dest_mac': 'dest_mac',
        'vlan': 'vlan_id',
        
        # Application fields
        'app': 'app',
        'application': 'app',
        
        # Action fields
        'action': 'action',
        'result': 'action'
    }
    
    # Protocol number to name mapping
    PROTOCOL_MAP = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
        89: 'OSPF',
        132: 'SCTP'
    }
    
    def __init__(self):
        self._field_cache = {}
    
    def normalize(self, data: Dict[str, Any], source_type: DataSourceType) -> Dict[str, Any]:
        """
        Normalize data to CIM format.
        
        Args:
            data: Raw data dict
            source_type: Type of data source
            
        Returns:
            CIM-compliant normalized data
        """
        normalized = {
            # Required CIM fields
            'event_id': self._generate_event_id(data),
            'event_time': self._normalize_timestamp(data),
            'source_type': source_type.value,
            'vendor': 'sentinel',
            'product': 'data_collector',
            
            # Network fields
            'src_ip': self._normalize_ip(data.get('source_ip') or data.get('src_ip')),
            'dest_ip': self._normalize_ip(data.get('dest_ip') or data.get('destination_ip')),
            'src_port': self._normalize_port(data.get('source_port') or data.get('src_port')),
            'dest_port': self._normalize_port(data.get('dest_port') or data.get('destination_port')),
            'transport': self._normalize_protocol(data.get('protocol')),
            
            # Traffic metrics
            'bytes': int(data.get('bytes', data.get('length', 0))),
            'packets': int(data.get('packets', 1)),
            'bytes_in': int(data.get('bytes_in', 0)),
            'bytes_out': int(data.get('bytes_out', 0)),
            
            # Direction
            'direction': self._determine_direction(data),
            
            # Additional fields
            'duration': float(data.get('duration', 0)),
            'tcp_flags': data.get('flags', data.get('tcp_flags')),
            
            # Raw data hash for deduplication
            'raw_hash': self._hash_data(data)
        }
        
        # Add optional fields if present
        optional_fields = [
            ('src_mac', 'source_mac', 'src_mac'),
            ('dest_mac', 'dest_mac', 'destination_mac'),
            ('vlan_id', 'vlan', 'vlan_id'),
            ('app', 'application', 'app'),
            ('user', 'user', 'src_user'),
            ('interface', 'interface', 'input_interface'),
            ('icmp_type', 'icmp_type'),
            ('icmp_code', 'icmp_code'),
            ('payload_length', 'payload_length'),
            ('payload_hash', 'payload_hash'),
            ('is_malformed', 'is_malformed'),
        ]
        
        for cim_field, *source_fields in optional_fields:
            for sf in source_fields:
                if sf in data and data[sf] is not None:
                    normalized[cim_field] = data[sf]
                    break
        
        # Add enrichment fields
        normalized['is_internal'] = self._is_internal_traffic(
            normalized['src_ip'], normalized['dest_ip']
        )
        
        return normalized
    
    def _generate_event_id(self, data: Dict) -> str:
        """Generate unique event ID."""
        components = [
            str(data.get('source_ip', '')),
            str(data.get('dest_ip', '')),
            str(data.get('source_port', '')),
            str(data.get('dest_port', '')),
            str(time.time_ns())
        ]
        hash_str = hashlib.sha256(':'.join(components).encode()).hexdigest()[:16]
        return f"evt_{hash_str}"
    
    def _normalize_timestamp(self, data: Dict) -> str:
        """Normalize timestamp to ISO format."""
        ts = data.get('timestamp') or data.get('time') or data.get('start_time')
        
        if ts is None:
            return datetime.utcnow().isoformat() + 'Z'
        
        if isinstance(ts, str):
            return ts
        elif isinstance(ts, (int, float)):
            return datetime.utcfromtimestamp(ts).isoformat() + 'Z'
        elif isinstance(ts, datetime):
            return ts.isoformat() + 'Z'
        
        return datetime.utcnow().isoformat() + 'Z'
    
    def _normalize_ip(self, ip: Any) -> Optional[str]:
        """Normalize IP address."""
        if ip is None:
            return None
        
        if isinstance(ip, bytes):
            try:
                if len(ip) == 4:
                    return socket.inet_ntoa(ip)
                elif len(ip) == 16:
                    return socket.inet_ntop(socket.AF_INET6, ip)
            except:
                return None
        
        if isinstance(ip, int):
            try:
                return str(ipaddress.ip_address(ip))
            except:
                return None
        
        return str(ip)
    
    def _normalize_port(self, port: Any) -> Optional[int]:
        """Normalize port number."""
        if port is None:
            return None
        try:
            return int(port)
        except:
            return None
    
    def _normalize_protocol(self, protocol: Any) -> str:
        """Normalize protocol to name."""
        if protocol is None:
            return 'unknown'
        
        if isinstance(protocol, str):
            return protocol.upper()
        
        if isinstance(protocol, int):
            return self.PROTOCOL_MAP.get(protocol, f'proto_{protocol}')
        
        return str(protocol).upper()
    
    def _determine_direction(self, data: Dict) -> str:
        """Determine traffic direction."""
        src_ip = data.get('source_ip') or data.get('src_ip')
        dst_ip = data.get('dest_ip') or data.get('destination_ip')
        
        src_internal = self._is_internal_ip(src_ip)
        dst_internal = self._is_internal_ip(dst_ip)
        
        if src_internal and not dst_internal:
            return 'outbound'
        elif not src_internal and dst_internal:
            return 'inbound'
        elif src_internal and dst_internal:
            return 'internal'
        else:
            return 'external'
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback
        except:
            return False
    
    def _is_internal_traffic(self, src_ip: str, dst_ip: str) -> bool:
        """Check if traffic is between internal hosts."""
        return self._is_internal_ip(src_ip) and self._is_internal_ip(dst_ip)
    
    def _hash_data(self, data: Dict) -> str:
        """Generate hash of data for deduplication."""
        key_fields = ['source_ip', 'dest_ip', 'source_port', 'dest_port', 'protocol']
        values = [str(data.get(f, '')) for f in key_fields]
        return hashlib.md5(':'.join(values).encode()).hexdigest()


class NetFlowParser:
    """
    NetFlow v5 and v9 protocol parser.
    
    Supports parsing NetFlow packets from network devices
    and converting to normalized format.
    """
    
    # NetFlow v5 header format (24 bytes)
    V5_HEADER_FORMAT = '!HHIIIIBBH'
    V5_HEADER_SIZE = 24
    
    # NetFlow v5 record format (48 bytes)
    V5_RECORD_FORMAT = '!IIIHHIIIIHHBBBBHHBBH'
    V5_RECORD_SIZE = 48
    
    def __init__(self, normalizer: CIMNormalizer):
        self.normalizer = normalizer
        self._template_cache = {}  # For NetFlow v9 templates
    
    def parse(self, data: bytes, source_addr: Tuple[str, int]) -> List[Dict]:
        """
        Parse NetFlow packet.
        
        Args:
            data: Raw NetFlow packet bytes
            source_addr: (ip, port) tuple of the exporter
            
        Returns:
            List of normalized flow records
        """
        if len(data) < 4:
            return []
        
        version = struct.unpack('!H', data[:2])[0]
        
        if version == NETFLOW_V5:
            return self._parse_v5(data, source_addr)
        elif version == NETFLOW_V9:
            return self._parse_v9(data, source_addr)
        else:
            logger.warning(f"Unsupported NetFlow version: {version}")
            return []
    
    def _parse_v5(self, data: bytes, source_addr: Tuple[str, int]) -> List[Dict]:
        """Parse NetFlow v5 packet."""
        records = []
        
        if len(data) < self.V5_HEADER_SIZE:
            return records
        
        # Parse header
        header = struct.unpack(self.V5_HEADER_FORMAT, data[:self.V5_HEADER_SIZE])
        version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling = header
        
        # Parse records
        offset = self.V5_HEADER_SIZE
        for i in range(count):
            if offset + self.V5_RECORD_SIZE > len(data):
                break
            
            record_data = data[offset:offset + self.V5_RECORD_SIZE]
            record = struct.unpack(self.V5_RECORD_FORMAT, record_data)
            
            # Extract fields
            src_ip = socket.inet_ntoa(struct.pack('!I', record[0]))
            dst_ip = socket.inet_ntoa(struct.pack('!I', record[1]))
            next_hop = socket.inet_ntoa(struct.pack('!I', record[2]))
            
            flow_record = {
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'next_hop': next_hop,
                'input_interface': record[3],
                'output_interface': record[4],
                'packets': record[5],
                'bytes': record[6],
                'start_time': unix_secs - (sys_uptime - record[7]) / 1000,
                'end_time': unix_secs - (sys_uptime - record[8]) / 1000,
                'source_port': record[9],
                'dest_port': record[10],
                'tcp_flags': record[12],
                'protocol': record[13],
                'tos': record[14],
                'src_as': record[15],
                'dst_as': record[16],
                'src_mask': record[17],
                'dst_mask': record[18],
                'exporter': source_addr[0],
                'flow_sequence': flow_seq
            }
            
            # Calculate duration
            flow_record['duration'] = flow_record['end_time'] - flow_record['start_time']
            
            # Normalize and add
            normalized = self.normalizer.normalize(flow_record, DataSourceType.NETFLOW_V5)
            records.append(normalized)
            
            offset += self.V5_RECORD_SIZE
        
        return records
    
    def _parse_v9(self, data: bytes, source_addr: Tuple[str, int]) -> List[Dict]:
        """Parse NetFlow v9 packet (simplified)."""
        # NetFlow v9 requires template handling
        # This is a simplified implementation
        records = []
        
        if len(data) < 20:
            return records
        
        # Parse header
        header_format = '!HHIIII'
        version, count, sys_uptime, unix_secs, seq_num, source_id = struct.unpack(
            header_format, data[:20]
        )
        
        # For now, return basic info
        # Full v9 parsing requires template management
        logger.debug(f"NetFlow v9 packet: {count} flowsets from {source_addr}")
        
        return records


class SFlowParser:
    """
    sFlow protocol parser.
    
    Parses sFlow v5 datagrams containing sampled flow
    and counter records.
    """
    
    def __init__(self, normalizer: CIMNormalizer):
        self.normalizer = normalizer
    
    def parse(self, data: bytes, source_addr: Tuple[str, int]) -> List[Dict]:
        """
        Parse sFlow datagram.
        
        Args:
            data: Raw sFlow datagram bytes
            source_addr: (ip, port) tuple of the agent
            
        Returns:
            List of normalized flow samples
        """
        records = []
        
        if len(data) < 28:
            return records
        
        try:
            # Parse sFlow header
            version = struct.unpack('!I', data[:4])[0]
            
            if version != 5:
                logger.warning(f"Unsupported sFlow version: {version}")
                return records
            
            # Parse v5 header
            header_format = '!IIIIII'
            version, agent_type, agent_addr, sub_agent, seq_num, uptime = struct.unpack(
                header_format, data[:24]
            )
            
            num_samples = struct.unpack('!I', data[24:28])[0]
            
            # Parse samples (simplified)
            offset = 28
            for i in range(min(num_samples, 100)):  # Limit samples
                if offset + 8 > len(data):
                    break
                
                sample_type, sample_len = struct.unpack('!II', data[offset:offset+8])
                offset += 8
                
                if sample_type == 1:  # Flow sample
                    sample = self._parse_flow_sample(data[offset:offset+sample_len], source_addr)
                    if sample:
                        normalized = self.normalizer.normalize(sample, DataSourceType.SFLOW)
                        records.append(normalized)
                
                offset += sample_len
        
        except Exception as e:
            logger.error(f"sFlow parsing error: {e}")
        
        return records
    
    def _parse_flow_sample(self, data: bytes, source_addr: Tuple[str, int]) -> Optional[Dict]:
        """Parse sFlow flow sample (simplified)."""
        if len(data) < 32:
            return None
        
        try:
            # Parse basic flow sample header
            seq_num, source_id, sampling_rate, sample_pool, drops, input_if, output_if, num_records = struct.unpack(
                '!IIIIIIII', data[:32]
            )
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': source_addr[0],
                'sampling_rate': sampling_rate,
                'input_interface': input_if,
                'output_interface': output_if,
                'exporter': source_addr[0]
            }
        
        except Exception as e:
            logger.error(f"Flow sample parsing error: {e}")
            return None


class NetworkTrafficCollector:
    """
    Enhanced network traffic collector with multi-source support.
    """
    
    def __init__(self, interface='any', buffer_size=65565):
        self.interface = interface
        self.buffer_size = buffer_size
        self.running = False
        self.sock = None
        self.netflow_sock = None
        self.sflow_sock = None
        
        self.packet_queue = deque(maxlen=10000)
        self.stats = {
            'packets_processed': 0,
            'bytes_processed': 0,
            'netflow_records': 0,
            'sflow_records': 0,
            'start_time': time.time()
        }
        
        # Initialize parsers
        self.normalizer = CIMNormalizer()
        self.netflow_parser = NetFlowParser(self.normalizer)
        self.sflow_parser = SFlowParser(self.normalizer)
    
    def start_capture(self):
        """Start network traffic capture."""
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            if self.interface != 'any':
                self.sock.bind((self.interface, 0))
            
            self.running = True
            logger.info(f"Started packet capture on interface: {self.interface}")
            
            while self.running:
                try:
                    packet = self.sock.recvfrom(self.buffer_size)[0]
                    parsed_packet = self.parse_packet(packet)
                    
                    if parsed_packet:
                        self.process_packet(parsed_packet)
                
                except socket.error as e:
                    if self.running:
                        logger.error(f"Socket error during capture: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error starting packet capture: {e}")
        finally:
            if self.sock:
                self.sock.close()
    
    def start_netflow_listener(self):
        """Start NetFlow listener."""
        try:
            self.netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.netflow_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.netflow_sock.bind(('0.0.0.0', app.config['NETFLOW_PORT']))
            
            logger.info(f"Started NetFlow listener on port {app.config['NETFLOW_PORT']}")
            
            while self.running:
                try:
                    data, addr = self.netflow_sock.recvfrom(65535)
                    records = self.netflow_parser.parse(data, addr)
                    
                    for record in records:
                        self.process_normalized_record(record)
                        self.stats['netflow_records'] += 1
                
                except socket.error as e:
                    if self.running:
                        logger.error(f"NetFlow socket error: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"NetFlow listener error: {e}")
        finally:
            if self.netflow_sock:
                self.netflow_sock.close()
    
    def start_sflow_listener(self):
        """Start sFlow listener."""
        try:
            self.sflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sflow_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sflow_sock.bind(('0.0.0.0', app.config['SFLOW_PORT']))
            
            logger.info(f"Started sFlow listener on port {app.config['SFLOW_PORT']}")
            
            while self.running:
                try:
                    data, addr = self.sflow_sock.recvfrom(65535)
                    records = self.sflow_parser.parse(data, addr)
                    
                    for record in records:
                        self.process_normalized_record(record)
                        self.stats['sflow_records'] += 1
                
                except socket.error as e:
                    if self.running:
                        logger.error(f"sFlow socket error: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"sFlow listener error: {e}")
        finally:
            if self.sflow_sock:
                self.sflow_sock.close()
    
    def stop_capture(self):
        """Stop all capture threads."""
        self.running = False
        for sock in [self.sock, self.netflow_sock, self.sflow_sock]:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        logger.info("All capture stopped")
    
    def parse_packet(self, packet: bytes) -> Optional[Dict[str, Any]]:
        """Parse raw packet and extract relevant information."""
        try:
            eth_length = 14
            eth_header = packet[:eth_length]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])
            
            if eth_protocol == 8:  # IPv4
                ip_header = packet[eth_length:eth_length + 20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                version_ihl = iph[0]
                ihl = (version_ihl & 0xF) * 4
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])
                
                raw_data = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': s_addr,
                    'dest_ip': d_addr,
                    'protocol': protocol,
                    'length': len(packet)
                }
                
                if protocol == TCP_PROTOCOL:
                    tcp_start = eth_length + ihl
                    tcp_header = packet[tcp_start:tcp_start + 20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    
                    raw_data.update({
                        'source_port': tcph[0],
                        'dest_port': tcph[1],
                        'sequence': tcph[2],
                        'acknowledgment': tcph[3],
                        'flags': tcph[5],
                        'payload_length': len(packet) - tcp_start - 20
                    })
                
                elif protocol == UDP_PROTOCOL:
                    udp_start = eth_length + ihl
                    udp_header = packet[udp_start:udp_start + 8]
                    udph = struct.unpack('!HHHH', udp_header)
                    
                    raw_data.update({
                        'source_port': udph[0],
                        'dest_port': udph[1],
                        'udp_length': udph[2],
                        'payload_length': len(packet) - udp_start - 8
                    })
                
                elif protocol == ICMP_PROTOCOL:
                    icmp_start = eth_length + ihl
                    icmp_header = packet[icmp_start:icmp_start + 8]
                    icmph = struct.unpack('!BBHHH', icmp_header)
                    
                    raw_data.update({
                        'icmp_type': icmph[0],
                        'icmp_code': icmph[1]
                    })
                
                # Normalize to CIM format
                return self.normalizer.normalize(raw_data, DataSourceType.PCAP)
        
        except Exception as e:
            logger.error(f"Packet parsing error: {e}")
            return None
        
        return None
    
    def process_packet(self, packet_data: Dict[str, Any]):
        """Process parsed packet."""
        self.process_normalized_record(packet_data)
        self.stats['packets_processed'] += 1
        self.stats['bytes_processed'] += packet_data.get('bytes', 0)
    
    def process_normalized_record(self, record: Dict[str, Any]):
        """Process a normalized CIM record."""
        try:
            # Send to Kafka
            if producer:
                producer.send('normalized_traffic', record)
            
            # Store in Redis for real-time analytics
            self._update_traffic_stats(record)
            
            # Check for anomalies
            if self._detect_anomaly(record):
                self._create_alert(record)
        
        except Exception as e:
            logger.error(f"Record processing error: {e}")
    
    def _update_traffic_stats(self, record: Dict):
        """Update traffic statistics in Redis."""
        try:
            pipe = redis_client.pipeline()
            
            # Source IP stats
            src_key = f"traffic:src:{record.get('src_ip', 'unknown')}"
            pipe.hincrby(src_key, 'count', 1)
            pipe.hincrby(src_key, 'bytes', record.get('bytes', 0))
            pipe.expire(src_key, 3600)
            
            # Destination IP stats
            dst_key = f"traffic:dst:{record.get('dest_ip', 'unknown')}"
            pipe.hincrby(dst_key, 'count', 1)
            pipe.hincrby(dst_key, 'bytes', record.get('bytes', 0))
            pipe.expire(dst_key, 3600)
            
            # Protocol stats
            proto_key = f"traffic:proto:{record.get('transport', 'unknown')}"
            pipe.incr(proto_key)
            pipe.expire(proto_key, 3600)
            
            # Direction stats
            dir_key = f"traffic:direction:{record.get('direction', 'unknown')}"
            pipe.incr(dir_key)
            pipe.expire(dir_key, 3600)
            
            pipe.execute()
        
        except Exception as e:
            logger.error(f"Stats update error: {e}")
    
    def _detect_anomaly(self, record: Dict) -> bool:
        """Basic anomaly detection."""
        try:
            # SYN flood detection
            if record.get('transport') == 'TCP' and record.get('tcp_flags'):
                if record['tcp_flags'] & 0x02 and not record['tcp_flags'] & 0x10:
                    key = f"syn_count:{record.get('src_ip')}"
                    count = redis_client.incr(key)
                    redis_client.expire(key, 60)
                    if count > 100:
                        return True
            
            # Large payload detection
            if record.get('bytes', 0) > 10000:
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return False
    
    def _create_alert(self, record: Dict):
        """Create alert for anomalous traffic."""
        try:
            alert = {
                'type': 'network_anomaly',
                'severity': 'medium',
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': record.get('src_ip'),
                'dest_ip': record.get('dest_ip'),
                'description': 'Anomalous network traffic detected',
                'details': record
            }
            
            if producer:
                producer.send('alerts', alert)
            
            # Store in Redis
            alert_key = f"alert:{alert['timestamp']}:{record.get('event_id')}"
            redis_client.hmset(alert_key, {
                'type': alert['type'],
                'severity': alert['severity'],
                'timestamp': alert['timestamp'],
                'details': json.dumps(alert['details'], default=str)
            })
            redis_client.expire(alert_key, 86400)
        
        except Exception as e:
            logger.error(f"Alert creation error: {e}")


# Authentication decorators
def require_auth(f):
    """Mock authentication decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function

def require_role(role):
    """Mock role requirement decorator."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Initialize collector
collector = NetworkTrafficCollector()

def start_background_collection():
    """Start all background collection threads."""
    collector.running = True
    
    # Packet capture thread
    pcap_thread = threading.Thread(target=collector.start_capture, daemon=True)
    pcap_thread.start()
    
    # NetFlow listener thread
    netflow_thread = threading.Thread(target=collector.start_netflow_listener, daemon=True)
    netflow_thread.start()
    
    # sFlow listener thread
    sflow_thread = threading.Thread(target=collector.start_sflow_listener, daemon=True)
    sflow_thread.start()
    
    logger.info("All background collection threads started")

# Start collection on app startup
start_background_collection()


# Flask routes
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'stats': collector.stats,
        'collectors': {
            'pcap': collector.running,
            'netflow_port': app.config['NETFLOW_PORT'],
            'sflow_port': app.config['SFLOW_PORT']
        }
    }), 200


@app.route('/api/v1/traffic', methods=['GET'])
@require_auth
def get_traffic():
    """Get traffic statistics."""
    try:
        stats = {
            'sources': {},
            'destinations': {},
            'protocols': {},
            'directions': {}
        }
        
        # Get source stats
        for key in redis_client.scan_iter('traffic:src:*'):
            ip = key.decode().split(':')[-1]
            stats['sources'][ip] = {
                k.decode(): int(v) for k, v in redis_client.hgetall(key).items()
            }
        
        # Get destination stats
        for key in redis_client.scan_iter('traffic:dst:*'):
            ip = key.decode().split(':')[-1]
            stats['destinations'][ip] = {
                k.decode(): int(v) for k, v in redis_client.hgetall(key).items()
            }
        
        # Get protocol stats
        for key in redis_client.scan_iter('traffic:proto:*'):
            proto = key.decode().split(':')[-1]
            stats['protocols'][proto] = int(redis_client.get(key) or 0)
        
        # Get direction stats
        for key in redis_client.scan_iter('traffic:direction:*'):
            direction = key.decode().split(':')[-1]
            stats['directions'][direction] = int(redis_client.get(key) or 0)
        
        return jsonify(stats), 200
    
    except Exception as e:
        logger.error(f"Traffic stats error: {e}")
        return jsonify({'error': 'Failed to retrieve traffic statistics'}), 500


@app.route('/api/v1/ingest', methods=['POST'])
@require_auth
def ingest_data():
    """Ingest traffic data via API."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Handle single record or batch
        records = data if isinstance(data, list) else [data]
        processed = 0
        
        for record in records:
            normalized = collector.normalizer.normalize(record, DataSourceType.API)
            collector.process_normalized_record(normalized)
            processed += 1
        
        return jsonify({
            'message': 'Data ingested successfully',
            'processed': processed
        }), 200
    
    except Exception as e:
        logger.error(f"Ingest error: {e}")
        return jsonify({'error': 'Failed to ingest data'}), 500


@app.route('/api/v1/threats', methods=['GET'])
@require_auth
def get_threats():
    """Get detected threats."""
    try:
        threats = []
        
        for key in redis_client.scan_iter('alert:*'):
            data = redis_client.hgetall(key)
            if data:
                threats.append({
                    k.decode(): v.decode() if isinstance(v, bytes) else v
                    for k, v in data.items()
                })
        
        return jsonify({
            'threats': threats,
            'total': len(threats)
        }), 200
    
    except Exception as e:
        logger.error(f"Threat retrieval error: {e}")
        return jsonify({'error': 'Failed to retrieve threats'}), 500


@app.route('/api/v1/collector/status', methods=['GET'])
@require_auth
def get_collector_status():
    """Get collector status."""
    return jsonify({
        'running': collector.running,
        'stats': collector.stats,
        'uptime': time.time() - collector.stats['start_time'],
        'netflow_port': app.config['NETFLOW_PORT'],
        'sflow_port': app.config['SFLOW_PORT']
    }), 200


@app.route('/api/v1/collector/start', methods=['POST'])
@require_role('admin')
def start_collector_endpoint():
    """Start collector."""
    if collector.running:
        return jsonify({'message': 'Collector already running'}), 200
    
    start_background_collection()
    return jsonify({'message': 'Collector started'}), 200


@app.route('/api/v1/collector/stop', methods=['POST'])
@require_role('admin')
def stop_collector_endpoint():
    """Stop collector."""
    collector.stop_capture()
    return jsonify({'message': 'Collector stopped'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')
