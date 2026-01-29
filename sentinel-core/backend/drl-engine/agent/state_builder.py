"""
State Builder for constructing state vectors from threat detections.
"""
import logging
from typing import Dict, List, Any
import numpy as np

logger = logging.getLogger(__name__)


class StateBuilder:
    """
    Build state vectors from threat detection data.
    
    State space includes:
    - Threat score (0-1)
    - Source reputation (0-1)
    - Asset criticality (1-5)
    - Traffic volume (normalized)
    - Protocol risk (0-1)
    - Time risk (0-1)
    - Historical alerts (count, normalized)
    - And additional contextual features
    """
    
    # State feature definitions
    FEATURES = [
        ('threat_score', 0.0, 1.0, 'Threat detection confidence'),
        ('src_reputation', 0.0, 1.0, 'Source IP reputation score'),
        ('asset_criticality', 0.0, 1.0, 'Target asset criticality (normalized)'),
        ('traffic_volume', 0.0, 1.0, 'Current traffic volume (normalized)'),
        ('protocol_risk', 0.0, 1.0, 'Protocol risk score'),
        ('time_risk', 0.0, 1.0, 'Time-of-day risk factor'),
        ('historical_alerts', 0.0, 1.0, 'Historical alert count (normalized)'),
        ('is_internal', 0.0, 1.0, 'Is internal traffic'),
        ('port_sensitivity', 0.0, 1.0, 'Target port sensitivity'),
        ('connection_freq', 0.0, 1.0, 'Connection frequency'),
        ('payload_anomaly', 0.0, 1.0, 'Payload anomaly score'),
        ('geo_risk', 0.0, 1.0, 'Geographic risk score'),
    ]
    
    def __init__(self):
        self.state_dim = len(self.FEATURES)
        
        # Port sensitivity mapping
        self.sensitive_ports = {
            22: 0.9,   # SSH
            23: 1.0,   # Telnet
            3389: 0.9, # RDP
            3306: 0.8, # MySQL
            5432: 0.8, # PostgreSQL
            27017: 0.8,# MongoDB
            6379: 0.7, # Redis
            445: 0.9,  # SMB
        }
        
        # Protocol risk scores
        self.protocol_risks = {
            'TCP': 0.3,
            'UDP': 0.4,
            'ICMP': 0.5,
        }
    
    def build_state(self, data: Dict[str, Any]) -> np.ndarray:
        """
        Build state vector from detection/context data.
        
        Args:
            data: Dictionary containing threat and context information
            
        Returns:
            Normalized state vector
        """
        state = np.zeros(self.state_dim)
        
        # 1. Threat score
        state[0] = self._normalize(data.get('threat_score', 0.5), 0, 1)
        
        # 2. Source reputation
        state[1] = self._normalize(data.get('src_reputation', 0.5), 0, 1)
        
        # 3. Asset criticality (1-5 -> 0-1)
        criticality = data.get('asset_criticality', 3)
        state[2] = self._normalize(criticality, 1, 5)
        
        # 4. Traffic volume
        volume = data.get('traffic_volume', 0)
        state[3] = self._normalize(volume, 0, 10000, clip=True)
        
        # 5. Protocol risk
        protocol = str(data.get('protocol', 'TCP')).upper()
        state[4] = self.protocol_risks.get(protocol, 0.3)
        
        # 6. Time risk
        state[5] = self._calculate_time_risk(data)
        
        # 7. Historical alerts
        alert_count = data.get('historical_alert_count', 0)
        state[6] = self._normalize(alert_count, 0, 100, clip=True)
        
        # 8. Is internal traffic
        state[7] = 1.0 if data.get('is_internal', False) else 0.0
        
        # 9. Port sensitivity
        port = data.get('dest_port', 0)
        state[8] = self.sensitive_ports.get(port, 0.2)
        
        # 10. Connection frequency
        freq = data.get('connection_frequency', 0)
        state[9] = self._normalize(freq, 0, 1000, clip=True)
        
        # 11. Payload anomaly
        state[10] = self._normalize(data.get('payload_anomaly_score', 0), 0, 1)
        
        # 12. Geographic risk
        state[11] = self._normalize(data.get('geo_risk', 0.2), 0, 1)
        
        return state.astype(np.float32)
    
    def _normalize(self, value: float, min_val: float, max_val: float, 
                   clip: bool = False) -> float:
        """Normalize value to 0-1 range."""
        if max_val == min_val:
            return 0.5
        
        normalized = (value - min_val) / (max_val - min_val)
        
        if clip:
            return max(0.0, min(1.0, normalized))
        return normalized
    
    def _calculate_time_risk(self, data: Dict) -> float:
        """Calculate time-based risk factor."""
        # Check for pre-computed time risk
        if 'time_risk' in data:
            return data['time_risk']
        
        # Calculate from timestamp
        timestamp = data.get('timestamp')
        if not timestamp:
            return 0.5
        
        try:
            from datetime import datetime
            
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = datetime.fromtimestamp(timestamp)
            
            hour = dt.hour
            weekday = dt.weekday()
            
            # Higher risk outside business hours
            if 9 <= hour <= 18 and weekday < 5:
                return 0.2  # Business hours
            elif weekday >= 5:
                return 0.6  # Weekend
            elif 0 <= hour < 6:
                return 0.8  # Late night
            else:
                return 0.4  # Evening/early morning
        
        except:
            return 0.5
    
    def get_feature_descriptions(self) -> List[Dict[str, Any]]:
        """Get descriptions of all state features."""
        return [
            {
                'index': i,
                'name': f[0],
                'min': f[1],
                'max': f[2],
                'description': f[3]
            }
            for i, f in enumerate(self.FEATURES)
        ]
