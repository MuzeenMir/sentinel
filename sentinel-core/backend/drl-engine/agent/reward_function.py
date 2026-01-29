"""
Reward Function for DRL policy learning.
"""
import logging
from typing import Dict, Any, Optional
import redis

logger = logging.getLogger(__name__)


class RewardFunction:
    """
    Calculate rewards for DRL policy decisions.
    
    Reward formula:
    R = α(blocked_threats) - β(false_positives) - γ(latency_impact) + δ(compliance_score)
    
    Where:
    - blocked_threats: Successfully blocked actual threats (+)
    - false_positives: Incorrectly blocked legitimate traffic (-)
    - latency_impact: Performance impact from security measures (-)
    - compliance_score: Alignment with security policies (+)
    """
    
    # Reward weights (configurable)
    DEFAULT_WEIGHTS = {
        'alpha': 1.0,    # Blocked threat weight
        'beta': 2.0,     # False positive penalty (higher to discourage FPs)
        'gamma': 0.5,    # Latency impact penalty
        'delta': 0.3,    # Compliance bonus
        'epsilon': 0.1   # Action consistency bonus
    }
    
    # Action-specific rewards
    ACTION_REWARDS = {
        'ALLOW': {
            'threat_blocked': -1.0,   # Missed threat (bad)
            'no_threat': 0.3,         # Correct allow (good)
            'false_positive': 0.0     # N/A
        },
        'DENY': {
            'threat_blocked': 1.0,    # Correct block (good)
            'no_threat': -0.5,        # Unnecessary block (bad)
            'false_positive': -2.0    # Blocked legitimate (very bad)
        },
        'RATE_LIMIT': {
            'threat_blocked': 0.7,    # Mitigated threat
            'no_threat': -0.2,        # Slight overhead
            'false_positive': -1.0    # Impacted legitimate
        },
        'QUARANTINE': {
            'threat_blocked': 1.2,    # Strong response to threat
            'no_threat': -0.8,        # Overly aggressive
            'false_positive': -2.5    # Very disruptive
        },
        'MONITOR': {
            'threat_blocked': 0.0,    # N/A (no action)
            'no_threat': 0.1,         # Good for low threats
            'false_positive': 0.0     # N/A
        }
    }
    
    def __init__(self, redis_client: Optional[redis.Redis] = None,
                 weights: Dict[str, float] = None):
        """
        Initialize reward function.
        
        Args:
            redis_client: Redis client for storing reward history
            weights: Custom reward weights
        """
        self.redis = redis_client
        self.weights = {**self.DEFAULT_WEIGHTS, **(weights or {})}
        
        # Running statistics for reward normalization
        self._reward_sum = 0.0
        self._reward_count = 0
        self._reward_max = 1.0
        self._reward_min = -1.0
    
    def calculate_reward(self, action: int, 
                        blocked_threat: bool = False,
                        false_positive: bool = False,
                        latency_impact: float = 0.0,
                        compliance_score: float = 1.0,
                        action_name: str = None) -> float:
        """
        Calculate reward for a policy decision.
        
        Args:
            action: Action index that was taken
            blocked_threat: Whether a real threat was blocked
            false_positive: Whether the action caused a false positive
            latency_impact: Impact on network latency (0-1)
            compliance_score: Alignment with compliance policies (0-1)
            action_name: Optional action name for lookup
            
        Returns:
            Calculated reward value
        """
        # Map action to name if not provided
        if action_name is None:
            action_names = ['ALLOW', 'DENY', 'RATE_LIMIT', 'RATE_LIMIT', 
                           'RATE_LIMIT', 'QUARANTINE', 'QUARANTINE', 'MONITOR']
            action_name = action_names[min(action, len(action_names) - 1)]
        
        # Get base action reward
        action_rewards = self.ACTION_REWARDS.get(action_name, self.ACTION_REWARDS['MONITOR'])
        
        # Calculate outcome-based reward
        if blocked_threat:
            base_reward = action_rewards['threat_blocked']
            outcome = 'blocked_threat'
        elif false_positive:
            base_reward = action_rewards['false_positive']
            outcome = 'false_positive'
        else:
            base_reward = action_rewards['no_threat']
            outcome = 'no_threat'
        
        # Apply weights
        reward = self.weights['alpha'] * base_reward
        
        # False positive penalty
        if false_positive:
            reward -= self.weights['beta'] * abs(action_rewards['false_positive'])
        
        # Latency impact penalty
        reward -= self.weights['gamma'] * latency_impact
        
        # Compliance bonus
        reward += self.weights['delta'] * (compliance_score - 0.5)
        
        # Update statistics
        self._update_stats(reward)
        
        # Log reward for analysis
        self._log_reward(action, action_name, outcome, reward)
        
        return float(reward)
    
    def calculate_advantage(self, rewards: list, values: list, 
                           gamma: float = 0.99, 
                           gae_lambda: float = 0.95) -> list:
        """
        Calculate Generalized Advantage Estimation (GAE).
        
        Args:
            rewards: List of rewards
            values: List of value estimates
            gamma: Discount factor
            gae_lambda: GAE lambda parameter
            
        Returns:
            List of advantage estimates
        """
        advantages = []
        gae = 0
        
        for t in reversed(range(len(rewards))):
            if t == len(rewards) - 1:
                next_value = 0
            else:
                next_value = values[t + 1]
            
            delta = rewards[t] + gamma * next_value - values[t]
            gae = delta + gamma * gae_lambda * gae
            advantages.insert(0, gae)
        
        return advantages
    
    def get_reward_statistics(self) -> Dict[str, float]:
        """Get reward statistics."""
        avg_reward = self._reward_sum / max(self._reward_count, 1)
        
        return {
            'average_reward': avg_reward,
            'max_reward': self._reward_max,
            'min_reward': self._reward_min,
            'total_count': self._reward_count
        }
    
    def _update_stats(self, reward: float):
        """Update running reward statistics."""
        self._reward_sum += reward
        self._reward_count += 1
        self._reward_max = max(self._reward_max, reward)
        self._reward_min = min(self._reward_min, reward)
    
    def _log_reward(self, action: int, action_name: str, 
                    outcome: str, reward: float):
        """Log reward for analysis."""
        if self.redis:
            try:
                self.redis.lpush('drl:reward_history', f"{action}:{action_name}:{outcome}:{reward}")
                self.redis.ltrim('drl:reward_history', 0, 10000)
            except Exception as e:
                logger.warning(f"Failed to log reward: {e}")
    
    def update_weights(self, new_weights: Dict[str, float]):
        """Update reward weights."""
        self.weights.update(new_weights)
        logger.info(f"Reward weights updated: {self.weights}")
    
    def normalize_reward(self, reward: float) -> float:
        """Normalize reward to [-1, 1] range."""
        if self._reward_max == self._reward_min:
            return 0.0
        
        normalized = 2 * (reward - self._reward_min) / (self._reward_max - self._reward_min) - 1
        return max(-1.0, min(1.0, normalized))
