"""
DRL Trainer for SENTINEL policy learning.
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np
import json

logger = logging.getLogger(__name__)


class DRLTrainer:
    """
    Trainer for DRL-based policy learning.
    
    Supports:
    - Online learning from real experiences
    - Curriculum learning for gradual difficulty
    - Experience replay
    """
    
    def __init__(self, agent, state_builder, action_space, reward_function,
                 redis_client=None):
        """
        Initialize trainer.
        
        Args:
            agent: PPO agent
            state_builder: State builder
            action_space: Action space
            reward_function: Reward function
            redis_client: Redis client for experience storage
        """
        self.agent = agent
        self.state_builder = state_builder
        self.action_space = action_space
        self.reward_function = reward_function
        self.redis = redis_client
        
        # Training statistics
        self._training_history = []
        self._total_episodes = 0
        self._total_steps = 0
    
    def train_on_experiences(self, experiences: List[Dict], 
                             epochs: int = 10) -> Dict[str, float]:
        """
        Train on a batch of experiences.
        
        Args:
            experiences: List of experience dicts
            epochs: Number of training epochs
            
        Returns:
            Training metrics
        """
        if len(experiences) < 32:
            return {'error': 'Insufficient experiences'}
        
        # Prepare training data
        states = []
        actions = []
        rewards = []
        old_log_probs = []
        
        for exp in experiences:
            state = exp.get('state')
            if state is None:
                continue
            
            state = np.array(state, dtype=np.float32)
            states.append(state)
            actions.append(exp.get('action', 0))
            rewards.append(exp.get('reward', 0.0))
            
            # Get old log prob
            _, probs = self.agent.select_action(state)
            action = exp.get('action', 0)
            old_log_probs.append(np.log(probs[action] + 1e-8))
        
        if len(states) < 32:
            return {'error': 'Insufficient valid experiences'}
        
        states = np.array(states)
        actions = np.array(actions)
        rewards = np.array(rewards)
        old_log_probs = np.array(old_log_probs)
        
        # Calculate values and advantages
        values = np.array([self.agent.get_value(s) for s in states])
        advantages = self.reward_function.calculate_advantage(
            rewards.tolist(), values.tolist()
        )
        advantages = np.array(advantages)
        
        # Calculate returns
        returns = advantages + values
        
        # Train agent
        metrics = self.agent.update(
            states, actions, returns, old_log_probs, advantages, epochs
        )
        
        # Update statistics
        self._total_episodes += 1
        self._total_steps += len(states)
        
        self._training_history.append({
            'timestamp': datetime.utcnow().isoformat(),
            'experiences': len(experiences),
            'epochs': epochs,
            **metrics
        })
        
        # Keep only last 100 entries
        self._training_history = self._training_history[-100:]
        
        logger.info(f"Training completed: {metrics}")
        return metrics
    
    def train_online(self, state: np.ndarray, action: int, 
                     reward: float, next_state: np.ndarray,
                     done: bool) -> Optional[Dict]:
        """
        Online training from single experience.
        
        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Episode done flag
            
        Returns:
            Training metrics if update occurred
        """
        # Store experience
        experience = {
            'state': state.tolist(),
            'action': action,
            'reward': reward,
            'next_state': next_state.tolist(),
            'done': done,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if self.redis:
            self.redis.lpush('drl:online_experiences', json.dumps(experience))
            self.redis.ltrim('drl:online_experiences', 0, 10000)
        
        # Trigger update every N experiences
        self._total_steps += 1
        
        if self._total_steps % 100 == 0:
            # Get recent experiences
            if self.redis:
                recent = self.redis.lrange('drl:online_experiences', 0, 100)
                experiences = [json.loads(e) for e in recent]
                
                if len(experiences) >= 64:
                    return self.train_on_experiences(experiences, epochs=5)
        
        return None
    
    def get_training_history(self) -> List[Dict]:
        """Get training history."""
        return self._training_history.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get trainer statistics."""
        return {
            'total_episodes': self._total_episodes,
            'total_steps': self._total_steps,
            'history_length': len(self._training_history),
            'agent_ready': self.agent.is_ready()
        }
