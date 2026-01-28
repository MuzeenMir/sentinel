"""
Network Security Gym Environment for DRL training.
"""
import logging
from typing import Dict, Tuple, Any, Optional
import numpy as np

logger = logging.getLogger(__name__)

try:
    import gymnasium as gym
    from gymnasium import spaces
    HAS_GYM = True
except ImportError:
    HAS_GYM = False
    logger.warning("Gymnasium not available")


class NetworkSecurityEnv:
    """
    Gym-compatible environment for network security policy learning.
    
    Simulates network traffic scenarios for DRL agent training.
    """
    
    def __init__(self, state_dim: int = 12, action_dim: int = 8):
        """
        Initialize environment.
        
        Args:
            state_dim: Dimension of observation space
            action_dim: Dimension of action space
        """
        self.state_dim = state_dim
        self.action_dim = action_dim
        
        # Environment state
        self._current_state = np.zeros(state_dim)
        self._episode_step = 0
        self._max_steps = 1000
        
        # Statistics
        self._total_reward = 0.0
        self._blocked_threats = 0
        self._false_positives = 0
        
        # Scenario generator
        self._scenario_index = 0
        self._scenarios = self._generate_scenarios()
        
        if HAS_GYM:
            self.observation_space = spaces.Box(
                low=0.0, high=1.0, shape=(state_dim,), dtype=np.float32
            )
            self.action_space = spaces.Discrete(action_dim)
    
    def reset(self) -> np.ndarray:
        """
        Reset the environment.
        
        Returns:
            Initial observation
        """
        self._episode_step = 0
        self._total_reward = 0.0
        self._blocked_threats = 0
        self._false_positives = 0
        
        # Generate initial state
        self._current_state = self._generate_observation()
        
        return self._current_state
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict]:
        """
        Execute one step in the environment.
        
        Args:
            action: Action to take
            
        Returns:
            observation, reward, done, info
        """
        self._episode_step += 1
        
        # Simulate outcome based on action and current state
        reward, info = self._simulate_outcome(action)
        
        self._total_reward += reward
        
        # Generate next state
        self._current_state = self._generate_observation()
        
        # Check if episode is done
        done = self._episode_step >= self._max_steps
        
        info.update({
            'episode_step': self._episode_step,
            'total_reward': self._total_reward,
            'blocked_threats': self._blocked_threats,
            'false_positives': self._false_positives
        })
        
        return self._current_state, reward, done, info
    
    def _generate_observation(self) -> np.ndarray:
        """Generate a state observation."""
        # Use scenarios for structured training
        scenario = self._get_next_scenario()
        
        state = np.zeros(self.state_dim, dtype=np.float32)
        
        # Threat score
        state[0] = scenario.get('threat_score', np.random.random())
        
        # Source reputation
        state[1] = scenario.get('src_reputation', np.random.random())
        
        # Asset criticality
        state[2] = scenario.get('asset_criticality', np.random.uniform(0.2, 0.8))
        
        # Traffic volume
        state[3] = scenario.get('traffic_volume', np.random.random())
        
        # Protocol risk
        state[4] = scenario.get('protocol_risk', np.random.uniform(0.2, 0.6))
        
        # Time risk
        state[5] = scenario.get('time_risk', np.random.uniform(0.1, 0.5))
        
        # Historical alerts
        state[6] = scenario.get('historical_alerts', np.random.uniform(0, 0.5))
        
        # Is internal
        state[7] = scenario.get('is_internal', float(np.random.random() > 0.7))
        
        # Port sensitivity
        state[8] = scenario.get('port_sensitivity', np.random.uniform(0.1, 0.9))
        
        # Connection frequency
        state[9] = scenario.get('connection_freq', np.random.random())
        
        # Payload anomaly
        state[10] = scenario.get('payload_anomaly', np.random.uniform(0, 0.3))
        
        # Geo risk
        state[11] = scenario.get('geo_risk', np.random.uniform(0.1, 0.5))
        
        return state
    
    def _simulate_outcome(self, action: int) -> Tuple[float, Dict]:
        """
        Simulate the outcome of an action.
        
        Returns:
            reward, info dict
        """
        threat_score = self._current_state[0]
        is_internal = self._current_state[7] > 0.5
        
        # Determine if this is actually a threat
        is_threat = np.random.random() < threat_score
        
        # Action effects
        # 0: ALLOW, 1: DENY, 2-4: RATE_LIMIT, 5-6: QUARANTINE, 7: MONITOR
        blocked = action in [1, 5, 6]  # DENY or QUARANTINE
        
        # Calculate reward
        if blocked:
            if is_threat:
                # Correctly blocked threat
                reward = 1.0
                self._blocked_threats += 1
                outcome = 'blocked_threat'
            else:
                # False positive
                reward = -2.0 if not is_internal else -1.0  # Less penalty for internal
                self._false_positives += 1
                outcome = 'false_positive'
        else:
            if is_threat:
                # Missed threat
                reward = -1.5
                outcome = 'missed_threat'
            else:
                # Correct allow
                reward = 0.2
                outcome = 'correct_allow'
        
        # Rate limiting partial credit
        if action in [2, 3, 4] and is_threat:
            reward = 0.5  # Partial mitigation
            outcome = 'mitigated'
        
        # Monitor bonus for low threats
        if action == 7 and threat_score < 0.3:
            reward = 0.3
            outcome = 'appropriate_monitor'
        
        info = {
            'is_threat': is_threat,
            'blocked': blocked,
            'outcome': outcome,
            'action': action
        }
        
        return reward, info
    
    def _generate_scenarios(self) -> list:
        """Generate training scenarios."""
        scenarios = []
        
        # High threat scenarios
        for _ in range(20):
            scenarios.append({
                'threat_score': np.random.uniform(0.8, 1.0),
                'src_reputation': np.random.uniform(0.0, 0.3),
                'asset_criticality': np.random.uniform(0.6, 1.0),
                'geo_risk': np.random.uniform(0.6, 1.0)
            })
        
        # Medium threat scenarios
        for _ in range(30):
            scenarios.append({
                'threat_score': np.random.uniform(0.4, 0.7),
                'src_reputation': np.random.uniform(0.3, 0.6),
                'asset_criticality': np.random.uniform(0.3, 0.7)
            })
        
        # Low threat scenarios
        for _ in range(30):
            scenarios.append({
                'threat_score': np.random.uniform(0.0, 0.3),
                'src_reputation': np.random.uniform(0.7, 1.0),
                'is_internal': 1.0
            })
        
        # Edge cases
        for _ in range(20):
            scenarios.append({
                'threat_score': np.random.uniform(0.45, 0.55),  # Borderline
                'asset_criticality': np.random.uniform(0.8, 1.0),  # Critical asset
                'time_risk': np.random.uniform(0.7, 1.0)  # Off-hours
            })
        
        np.random.shuffle(scenarios)
        return scenarios
    
    def _get_next_scenario(self) -> Dict:
        """Get next scenario from the pool."""
        if not self._scenarios:
            self._scenarios = self._generate_scenarios()
        
        scenario = self._scenarios[self._scenario_index % len(self._scenarios)]
        self._scenario_index += 1
        
        return scenario
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get environment statistics."""
        return {
            'episode_step': self._episode_step,
            'total_reward': self._total_reward,
            'blocked_threats': self._blocked_threats,
            'false_positives': self._false_positives,
            'fp_rate': self._false_positives / max(self._episode_step, 1)
        }
