"""
Contextual feature extraction for threat assessment.

Enriches network data with contextual information:
- Asset criticality
- User role and privileges
- Time-based risk factors
- Reputation scores
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)


class ContextualFeatureExtractor:
    """
    Extract contextual features for risk assessment.
    
    Features extracted:
    - Asset criticality and sensitivity
    - User role and access level
    - Time-based risk factors
    - IP reputation
    - Historical behavior
    """
    
    FEATURE_NAMES = [
        # Asset features
        'asset_criticality', 'asset_sensitivity', 'asset_exposure',
        'is_production_asset', 'is_data_store', 'is_internet_facing',
        
        # User features
        'user_privilege_level', 'is_admin_user', 'is_service_account',
        'user_risk_score', 'auth_failure_count', 'session_anomaly_score',
        
        # Time features
        'time_risk_score', 'is_business_hours', 'is_weekend',
        'day_of_week', 'hour_of_day', 'minutes_since_midnight',
        
        # Reputation features
        'src_ip_reputation', 'dst_ip_reputation', 'domain_reputation',
        'is_known_bad_ip', 'is_known_good_ip', 'geo_risk_score',
        
        # Historical features
        'historical_alert_count', 'historical_threat_score',
        'days_since_last_alert', 'connection_frequency_score',
        
        # Network context
        'is_internal_traffic', 'is_cross_zone', 'zone_trust_level',
        'network_segment_risk'
    ]
    
    # Risk mappings
    CRITICALITY_LEVELS = {
        'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'minimal': 1
    }
    
    PRIVILEGE_LEVELS = {
        'root': 5, 'admin': 4, 'power_user': 3, 'user': 2, 'guest': 1
    }
    
    # High-risk geo regions (example)
    HIGH_RISK_COUNTRIES = {'CN', 'RU', 'KP', 'IR'}
    
    def __init__(self):
        self.n_features = len(self.FEATURE_NAMES)
        
        # Cache for reputation lookups
        self._ip_reputation_cache: Dict[str, float] = {}
        self._domain_reputation_cache: Dict[str, float] = {}
    
    def extract(self, data: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, float]:
        """
        Extract contextual features.
        
        Args:
            data: Traffic data
            context: Additional context (asset info, user info, etc.)
            
        Returns:
            Dictionary of feature name -> value
        """
        try:
            features = {}
            context = context or {}
            
            # Asset context
            features.update(self._extract_asset_features(context.get('asset', {})))
            
            # User context
            features.update(self._extract_user_features(context.get('user', {})))
            
            # Time context
            timestamp = data.get('timestamp') or context.get('timestamp')
            features.update(self._extract_time_features(timestamp))
            
            # Reputation context
            features.update(self._extract_reputation_features(data, context))
            
            # Historical context
            features.update(self._extract_historical_features(context.get('history', {})))
            
            # Network context
            features.update(self._extract_network_context(data, context))
            
            # Fill missing features
            for name in self.FEATURE_NAMES:
                if name not in features:
                    features[name] = 0.0
            
            return features
            
        except Exception as e:
            logger.error(f"Contextual feature extraction error: {e}")
            return self._get_default_features()
    
    def extract_array(self, data: Dict[str, Any], context: Dict[str, Any] = None) -> np.ndarray:
        """Extract features as numpy array."""
        features = self.extract(data, context)
        return np.array([features.get(name, 0.0) for name in self.FEATURE_NAMES])
    
    def _extract_asset_features(self, asset: Dict) -> Dict[str, float]:
        """Extract asset-related features."""
        features = {}
        
        # Criticality level
        criticality = asset.get('criticality', 'medium')
        if isinstance(criticality, str):
            features['asset_criticality'] = float(self.CRITICALITY_LEVELS.get(
                criticality.lower(), 3
            ))
        else:
            features['asset_criticality'] = float(criticality)
        
        # Sensitivity
        sensitivity = asset.get('sensitivity', 'medium')
        if isinstance(sensitivity, str):
            features['asset_sensitivity'] = float(self.CRITICALITY_LEVELS.get(
                sensitivity.lower(), 3
            ))
        else:
            features['asset_sensitivity'] = float(sensitivity)
        
        # Exposure
        features['asset_exposure'] = float(asset.get('exposure_score', 0.5))
        
        # Boolean flags
        features['is_production_asset'] = 1.0 if asset.get('is_production', False) else 0.0
        features['is_data_store'] = 1.0 if asset.get('is_data_store', False) else 0.0
        features['is_internet_facing'] = 1.0 if asset.get('is_internet_facing', False) else 0.0
        
        return features
    
    def _extract_user_features(self, user: Dict) -> Dict[str, float]:
        """Extract user-related features."""
        features = {}
        
        # Privilege level
        role = user.get('role', 'user')
        if isinstance(role, str):
            features['user_privilege_level'] = float(self.PRIVILEGE_LEVELS.get(
                role.lower(), 2
            ))
        else:
            features['user_privilege_level'] = float(role)
        
        # Admin flag
        is_admin = user.get('is_admin', False) or role.lower() in ['admin', 'root', 'administrator']
        features['is_admin_user'] = 1.0 if is_admin else 0.0
        
        # Service account
        features['is_service_account'] = 1.0 if user.get('is_service_account', False) else 0.0
        
        # User risk score
        features['user_risk_score'] = float(user.get('risk_score', 0.5))
        
        # Auth failures
        features['auth_failure_count'] = float(user.get('auth_failure_count', 0))
        
        # Session anomaly
        features['session_anomaly_score'] = float(user.get('session_anomaly_score', 0))
        
        return features
    
    def _extract_time_features(self, timestamp: Any) -> Dict[str, float]:
        """Extract time-based features."""
        features = {}
        
        # Parse timestamp
        if timestamp is None:
            dt = datetime.utcnow()
        elif isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                dt = datetime.utcnow()
        elif isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(timestamp)
        else:
            dt = datetime.utcnow()
        
        # Time of day
        features['hour_of_day'] = float(dt.hour) / 24.0  # Normalized
        features['day_of_week'] = float(dt.weekday()) / 6.0  # Normalized
        features['minutes_since_midnight'] = (dt.hour * 60 + dt.minute) / 1440.0
        
        # Business hours (9 AM - 6 PM, Monday-Friday)
        is_business_hours = (
            9 <= dt.hour <= 18 and 
            dt.weekday() < 5
        )
        features['is_business_hours'] = 1.0 if is_business_hours else 0.0
        
        # Weekend
        features['is_weekend'] = 1.0 if dt.weekday() >= 5 else 0.0
        
        # Time risk score
        # Higher risk outside business hours and on weekends
        time_risk = 0.0
        if not is_business_hours:
            time_risk += 0.3
        if dt.weekday() >= 5:
            time_risk += 0.2
        if 0 <= dt.hour < 6:  # Late night / early morning
            time_risk += 0.3
        
        features['time_risk_score'] = min(time_risk, 1.0)
        
        return features
    
    def _extract_reputation_features(self, data: Dict, context: Dict) -> Dict[str, float]:
        """Extract reputation-based features."""
        features = {}
        
        # Source IP reputation
        src_ip = data.get('source_ip', data.get('src_ip', ''))
        features['src_ip_reputation'] = self._get_ip_reputation(src_ip, context)
        
        # Destination IP reputation
        dst_ip = data.get('dest_ip', data.get('destination_ip', ''))
        features['dst_ip_reputation'] = self._get_ip_reputation(dst_ip, context)
        
        # Domain reputation
        domain = data.get('domain', context.get('domain', ''))
        features['domain_reputation'] = self._get_domain_reputation(domain, context)
        
        # Known bad/good IP flags
        bad_ips = context.get('known_bad_ips', set())
        good_ips = context.get('known_good_ips', set())
        
        features['is_known_bad_ip'] = 1.0 if src_ip in bad_ips or dst_ip in bad_ips else 0.0
        features['is_known_good_ip'] = 1.0 if dst_ip in good_ips else 0.0
        
        # Geo risk
        geo_info = context.get('geo', {})
        country = geo_info.get('country_code', '')
        features['geo_risk_score'] = 0.8 if country in self.HIGH_RISK_COUNTRIES else 0.2
        
        return features
    
    def _extract_historical_features(self, history: Dict) -> Dict[str, float]:
        """Extract features from historical data."""
        features = {}
        
        # Alert history
        features['historical_alert_count'] = float(history.get('alert_count', 0))
        features['historical_threat_score'] = float(history.get('threat_score', 0))
        
        # Days since last alert
        last_alert = history.get('last_alert_timestamp')
        if last_alert:
            try:
                if isinstance(last_alert, str):
                    last_dt = datetime.fromisoformat(last_alert.replace('Z', '+00:00'))
                else:
                    last_dt = datetime.fromtimestamp(last_alert)
                days = (datetime.utcnow() - last_dt).days
                features['days_since_last_alert'] = float(min(days, 365))  # Cap at 1 year
            except:
                features['days_since_last_alert'] = 365.0
        else:
            features['days_since_last_alert'] = 365.0
        
        # Connection frequency
        features['connection_frequency_score'] = float(history.get('connection_frequency', 0.5))
        
        return features
    
    def _extract_network_context(self, data: Dict, context: Dict) -> Dict[str, float]:
        """Extract network topology context."""
        features = {}
        
        src_ip = data.get('source_ip', data.get('src_ip', ''))
        dst_ip = data.get('dest_ip', data.get('destination_ip', ''))
        
        # Internal vs external traffic
        is_internal = self._is_internal_ip(src_ip) and self._is_internal_ip(dst_ip)
        features['is_internal_traffic'] = 1.0 if is_internal else 0.0
        
        # Cross-zone traffic
        src_zone = context.get('source_zone', 'unknown')
        dst_zone = context.get('dest_zone', 'unknown')
        features['is_cross_zone'] = 0.0 if src_zone == dst_zone else 1.0
        
        # Zone trust level
        zone_trust = context.get('zone_trust_levels', {})
        dst_trust = zone_trust.get(dst_zone, 0.5)
        features['zone_trust_level'] = float(dst_trust)
        
        # Network segment risk
        segment_risks = context.get('segment_risks', {})
        segment = context.get('network_segment', 'default')
        features['network_segment_risk'] = float(segment_risks.get(segment, 0.5))
        
        return features
    
    def _get_ip_reputation(self, ip: str, context: Dict) -> float:
        """Get IP reputation score (0=bad, 1=good)."""
        if not ip:
            return 0.5
        
        # Check cache
        if ip in self._ip_reputation_cache:
            return self._ip_reputation_cache[ip]
        
        # Check context for pre-computed reputation
        reputations = context.get('ip_reputations', {})
        if ip in reputations:
            score = reputations[ip]
            self._ip_reputation_cache[ip] = score
            return score
        
        # Default reputation based on IP type
        if self._is_internal_ip(ip):
            return 0.8  # Internal IPs are generally trusted
        
        # External IPs default to neutral
        return 0.5
    
    def _get_domain_reputation(self, domain: str, context: Dict) -> float:
        """Get domain reputation score."""
        if not domain:
            return 0.5
        
        # Check cache
        if domain in self._domain_reputation_cache:
            return self._domain_reputation_cache[domain]
        
        # Check context
        reputations = context.get('domain_reputations', {})
        if domain in reputations:
            score = reputations[domain]
            self._domain_reputation_cache[domain] = score
            return score
        
        return 0.5
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private."""
        if not ip:
            return False
        
        try:
            # Simple check for private IP ranges
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.0.0.0/8
            if first == 10:
                return True
            
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            
            # 127.0.0.0/8 (loopback)
            if first == 127:
                return True
            
            return False
            
        except:
            return False
    
    def _get_default_features(self) -> Dict[str, float]:
        """Get default feature values."""
        defaults = {name: 0.0 for name in self.FEATURE_NAMES}
        
        # Set reasonable defaults
        defaults['asset_criticality'] = 3.0
        defaults['user_privilege_level'] = 2.0
        defaults['zone_trust_level'] = 0.5
        defaults['src_ip_reputation'] = 0.5
        defaults['dst_ip_reputation'] = 0.5
        defaults['domain_reputation'] = 0.5
        
        return defaults
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return self.FEATURE_NAMES.copy()
    
    def update_reputation_cache(self, ip_reputations: Dict[str, float] = None,
                                domain_reputations: Dict[str, float] = None):
        """Update reputation caches."""
        if ip_reputations:
            self._ip_reputation_cache.update(ip_reputations)
        if domain_reputations:
            self._domain_reputation_cache.update(domain_reputations)
