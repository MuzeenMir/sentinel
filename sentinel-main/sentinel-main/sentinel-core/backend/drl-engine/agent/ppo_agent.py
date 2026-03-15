"""
Proximal Policy Optimization (PPO) Agent for firewall policy generation.
"""
import os
import json
import logging
from typing import Dict, Tuple, Optional, List
from datetime import datetime
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.distributions import Categorical
except ImportError:
    torch = None

logger = logging.getLogger(__name__)


class PolicyNetwork(nn.Module):
    """Neural network for policy (actor)."""
    
    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 256):
        super().__init__()
        
        self.network = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim),
            nn.Softmax(dim=-1)
        )
    
    def forward(self, state: torch.Tensor) -> torch.Tensor:
        return self.network(state)


class ValueNetwork(nn.Module):
    """Neural network for value function (critic)."""
    
    def __init__(self, state_dim: int, hidden_dim: int = 256):
        super().__init__()
        
        self.network = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1)
        )
    
    def forward(self, state: torch.Tensor) -> torch.Tensor:
        return self.network(state)


class PPOAgent:
    """
    PPO Agent for autonomous firewall policy generation.
    
    Uses the PPO algorithm with clipped surrogate objective
    to learn optimal security policies.
    """
    
    def __init__(self, state_dim: int, action_dim: int,
                 model_path: str = '/models/drl',
                 learning_rate: float = 3e-4,
                 gamma: float = 0.99,
                 epsilon_clip: float = 0.2,
                 entropy_coef: float = 0.01,
                 value_coef: float = 0.5):
        """
        Initialize PPO agent.
        
        Args:
            state_dim: Dimension of state space
            action_dim: Dimension of action space
            model_path: Path to save/load models
            learning_rate: Learning rate
            gamma: Discount factor
            epsilon_clip: PPO clipping parameter
            entropy_coef: Entropy bonus coefficient
            value_coef: Value loss coefficient
        """
        if torch is None:
            raise ImportError("PyTorch is required for PPO agent")
        
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.model_path = model_path
        self.gamma = gamma
        self.epsilon_clip = epsilon_clip
        self.entropy_coef = entropy_coef
        self.value_coef = value_coef
        
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Initialize networks
        self.policy_net = PolicyNetwork(state_dim, action_dim).to(self.device)
        self.value_net = ValueNetwork(state_dim).to(self.device)
        
        # Optimizers
        self.policy_optimizer = optim.Adam(self.policy_net.parameters(), lr=learning_rate)
        self.value_optimizer = optim.Adam(self.value_net.parameters(), lr=learning_rate)
        
        # Metadata
        self._version = "1.0.0"
        self._is_ready = True
        self._training_steps = 0
        self._last_updated = datetime.utcnow().isoformat()
        
        logger.info(f"PPO Agent initialized on {self.device}")
    
    def is_ready(self) -> bool:
        """Check if agent is ready."""
        return self._is_ready
    
    def get_version(self) -> str:
        """Get model version."""
        return self._version
    
    def select_action(self, state: np.ndarray, deterministic: bool = False) -> Tuple[int, np.ndarray]:
        """
        Select an action given the current state.
        
        Args:
            state: Current state vector
            deterministic: If True, select most probable action
            
        Returns:
            action: Selected action index
            action_probs: Action probability distribution
        """
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        
        self.policy_net.eval()
        with torch.no_grad():
            action_probs = self.policy_net(state_tensor).cpu().numpy()[0]
        
        if deterministic:
            action = np.argmax(action_probs)
        else:
            action = np.random.choice(len(action_probs), p=action_probs)
        
        return int(action), action_probs
    
    def get_value(self, state: np.ndarray) -> float:
        """Get value estimate for a state."""
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        
        self.value_net.eval()
        with torch.no_grad():
            value = self.value_net(state_tensor).cpu().numpy()[0, 0]
        
        return float(value)
    
    def update(self, states: np.ndarray, actions: np.ndarray,
               rewards: np.ndarray, old_log_probs: np.ndarray,
               advantages: np.ndarray, epochs: int = 10) -> Dict[str, float]:
        """
        Update policy and value networks using PPO.
        
        Args:
            states: Batch of states
            actions: Batch of actions
            rewards: Batch of returns
            old_log_probs: Log probabilities from old policy
            advantages: Advantage estimates
            epochs: Number of update epochs
            
        Returns:
            Training metrics
        """
        states_tensor = torch.FloatTensor(states).to(self.device)
        actions_tensor = torch.LongTensor(actions).to(self.device)
        returns_tensor = torch.FloatTensor(rewards).to(self.device)
        old_log_probs_tensor = torch.FloatTensor(old_log_probs).to(self.device)
        advantages_tensor = torch.FloatTensor(advantages).to(self.device)
        
        # Normalize advantages
        advantages_tensor = (advantages_tensor - advantages_tensor.mean()) / (advantages_tensor.std() + 1e-8)
        
        total_policy_loss = 0
        total_value_loss = 0
        total_entropy = 0
        
        for _ in range(epochs):
            # Get new action probabilities
            self.policy_net.train()
            action_probs = self.policy_net(states_tensor)
            dist = Categorical(action_probs)
            new_log_probs = dist.log_prob(actions_tensor)
            entropy = dist.entropy().mean()
            
            # Calculate ratio
            ratio = torch.exp(new_log_probs - old_log_probs_tensor)
            
            # Clipped surrogate objective
            surr1 = ratio * advantages_tensor
            surr2 = torch.clamp(ratio, 1 - self.epsilon_clip, 1 + self.epsilon_clip) * advantages_tensor
            policy_loss = -torch.min(surr1, surr2).mean() - self.entropy_coef * entropy
            
            # Update policy
            self.policy_optimizer.zero_grad()
            policy_loss.backward()
            torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), 0.5)
            self.policy_optimizer.step()
            
            # Update value function
            self.value_net.train()
            values = self.value_net(states_tensor).squeeze()
            value_loss = self.value_coef * nn.MSELoss()(values, returns_tensor)
            
            self.value_optimizer.zero_grad()
            value_loss.backward()
            torch.nn.utils.clip_grad_norm_(self.value_net.parameters(), 0.5)
            self.value_optimizer.step()
            
            total_policy_loss += policy_loss.item()
            total_value_loss += value_loss.item()
            total_entropy += entropy.item()
        
        self._training_steps += epochs
        self._last_updated = datetime.utcnow().isoformat()
        
        return {
            'policy_loss': total_policy_loss / epochs,
            'value_loss': total_value_loss / epochs,
            'entropy': total_entropy / epochs,
            'training_steps': self._training_steps
        }
    
    def save_model(self, path: str = None) -> bool:
        """Save model to disk."""
        try:
            save_path = path or self.model_path
            os.makedirs(save_path, exist_ok=True)
            
            # Save networks
            torch.save(self.policy_net.state_dict(), os.path.join(save_path, 'policy_net.pt'))
            torch.save(self.value_net.state_dict(), os.path.join(save_path, 'value_net.pt'))
            
            # Save metadata
            meta = {
                'version': self._version,
                'state_dim': self.state_dim,
                'action_dim': self.action_dim,
                'training_steps': self._training_steps,
                'last_updated': self._last_updated,
                'gamma': self.gamma,
                'epsilon_clip': self.epsilon_clip
            }
            with open(os.path.join(save_path, 'meta.json'), 'w') as f:
                json.dump(meta, f, indent=2)
            
            logger.info(f"Model saved to {save_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False
    
    def load_model(self, path: str = None) -> bool:
        """Load model from disk."""
        try:
            load_path = path or self.model_path
            
            policy_path = os.path.join(load_path, 'policy_net.pt')
            value_path = os.path.join(load_path, 'value_net.pt')
            meta_path = os.path.join(load_path, 'meta.json')
            
            if not os.path.exists(policy_path):
                logger.warning("No saved model found")
                return False
            
            # Load networks
            self.policy_net.load_state_dict(torch.load(policy_path, map_location=self.device))
            self.value_net.load_state_dict(torch.load(value_path, map_location=self.device))
            
            # Load metadata
            if os.path.exists(meta_path):
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                    self._version = meta.get('version', self._version)
                    self._training_steps = meta.get('training_steps', 0)
                    self._last_updated = meta.get('last_updated')
            
            self.policy_net.eval()
            self.value_net.eval()
            
            logger.info(f"Model loaded from {load_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
