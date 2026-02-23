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
    
    def reset(self, *, seed=None, options=None) -> Tuple[np.ndarray, Dict]:
        """
        Reset the environment.
        
        Returns:
            (observation, info)
        """
        self._episode_step = 0
        self._total_reward = 0.0
        self._blocked_threats = 0
        self._false_positives = 0
        
        # Generate initial state
        self._current_state = self._generate_observation()
        
        return self._current_state, {}
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """
        Execute one step in the environment.
        
        Args:
            action: Action to take
            
        Returns:
            observation, reward, terminated, truncated, info
        """
        self._episode_step += 1
        
        # Simulate outcome based on action and current state
        reward, info = self._simulate_outcome(action)
        
        self._total_reward += reward
        
        # Generate next state
        self._current_state = self._generate_observation()
        
        # Check if episode is done
        terminated = False
        truncated = self._episode_step >= self._max_steps
        
        info.update({
            'episode_step': self._episode_step,
            'total_reward': self._total_reward,
            'blocked_threats': self._blocked_threats,
            'false_positives': self._false_positives
        })
        
        return self._current_state, reward, terminated, truncated, info
    
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
        
        Uses a probabilistic threat model: the true threat probability is
        derived from the threat score with noise, so the agent cannot simply
        threshold a single feature.
        
        Returns:
            reward, info dict
        """
        threat_score = self._current_state[0]
        asset_criticality = self._current_state[2]
        
        # Probabilistic threat: add noise so the relationship is not trivial
        noise = np.random.normal(0, 0.15)
        is_threat = (threat_score + noise) > 0.5
        
        # 0: ALLOW, 1: DENY, 2-4: RATE_LIMIT, 5-6: QUARANTINE, 7: MONITOR
        blocked = action in [1, 5, 6]
        
        if is_threat:
            if blocked:
                reward = 1.0
                self._blocked_threats += 1
                outcome = 'blocked_threat'
            elif action in [2, 3, 4]:
                reward = 0.4
                outcome = 'mitigated'
            elif action == 7:
                reward = -0.5
                outcome = 'monitored_threat'
            else:
                reward = -1.0 - asset_criticality
                outcome = 'missed_threat'
        else:
            if action == 0:
                reward = 0.3
                outcome = 'correct_allow'
            elif action == 7:
                reward = 0.1
                outcome = 'appropriate_monitor'
            elif action in [2, 3, 4]:
                reward = -0.2
                self._false_positives += 1
                outcome = 'unnecessary_rate_limit'
            else:
                reward = -1.0
                self._false_positives += 1
                outcome = 'false_positive'
        
        info = {
            'is_threat': bool(is_threat),
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
