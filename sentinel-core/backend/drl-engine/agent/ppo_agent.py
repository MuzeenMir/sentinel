"""
PPO-based security policy agent backed by stable-baselines3.

Wraps a Proximal Policy Optimization model with a custom feature extractor
tailored to security-state vectors.  Falls back to a uniform random policy
when no trained model is available.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import gymnasium as gym
import numpy as np
import torch
import torch.nn as nn
from gymnasium import spaces
from stable_baselines3 import PPO
from stable_baselines3.common.torch_layers import BaseFeaturesExtractor
from stable_baselines3.common.vec_env import DummyVecEnv

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom feature extractor
# ---------------------------------------------------------------------------

class SecurityFeatureExtractor(BaseFeaturesExtractor):
    """LayerNorm-stabilised MLP for security observation vectors."""

    def __init__(self, observation_space: spaces.Box, features_dim: int = 128):
        super().__init__(observation_space, features_dim)
        n_input = int(np.prod(observation_space.shape))
        self.net = nn.Sequential(
            nn.Linear(n_input, 256),
            nn.LayerNorm(256),
            nn.ReLU(),
            nn.Linear(256, features_dim),
            nn.LayerNorm(features_dim),
            nn.ReLU(),
        )

    def forward(self, observations: torch.Tensor) -> torch.Tensor:
        return self.net(observations)


# ---------------------------------------------------------------------------
# Minimal env for bootstrapping SB3 with correct obs/action spaces
# ---------------------------------------------------------------------------

class _BootstrapEnv(gym.Env):

    def __init__(self, obs_dim: int, act_dim: int):
        super().__init__()
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(obs_dim,), dtype=np.float32,
        )
        self.action_space = spaces.Discrete(act_dim)

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        return np.zeros(self.observation_space.shape, dtype=np.float32), {}

    def step(self, action):
        obs = np.zeros(self.observation_space.shape, dtype=np.float32)
        return obs, 0.0, True, False, {}


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

_POLICY_KWARGS = dict(
    features_extractor_class=SecurityFeatureExtractor,
    features_extractor_kwargs=dict(features_dim=128),
    net_arch=dict(pi=[64], vf=[64]),
    activation_fn=nn.Tanh,
)


class PPOAgent:
    """Proximal Policy Optimization agent for network-security decisions."""

    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        model_path: str = "/tmp/ppo_sentinel",
        device: str = "auto",
    ):
        if torch is None:  # type: ignore[comparison-overlap]
            raise ImportError("PyTorch is required for PPOAgent")
        if state_dim < 1 or action_dim < 1:
            raise ValueError("state_dim and action_dim must be >= 1")

        self._state_dim = state_dim
        self._action_dim = action_dim
        self._model_path = model_path
        self._device = device
        self._model: Optional[PPO] = None
        self._version: str = "0.0.0"
        self._training_steps: int = 0
        self._meta_file = os.path.join(model_path, "meta.json")

        os.makedirs(model_path, exist_ok=True)
        self._init_fresh_model()

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def state_dim(self) -> int:
        return self._state_dim

    @property
    def action_dim(self) -> int:
        return self._action_dim

    @property
    def model_path(self) -> str:
        return self._model_path

    @model_path.setter
    def model_path(self, value: str) -> None:
        self._model_path = value
        self._meta_file = os.path.join(value, "meta.json")
        os.makedirs(value, exist_ok=True)

    @property
    def model(self) -> Optional[PPO]:
        return self._model

    @property
    def device(self) -> torch.device:
        if self._model is not None:
            return self._model.device
        return torch.device("cpu")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_ready(self) -> bool:
        return self._model is not None

    def get_version(self) -> str:
        return self._version

    def select_action(
        self,
        state: np.ndarray,
        deterministic: bool = False,
    ) -> Tuple[int, np.ndarray]:
        """Return ``(action_index, action_probabilities)``."""
        if self._model is None:
            probs = np.full(self._action_dim, 1.0 / self._action_dim, dtype=np.float32)
            return int(np.random.choice(self._action_dim)), probs

        obs = np.asarray(state, dtype=np.float32).reshape(1, -1)
        obs_t = torch.as_tensor(obs, device=self._model.device)

        self._model.policy.set_training_mode(False)
        with torch.no_grad():
            dist = self._model.policy.get_distribution(obs_t)
            probs = dist.distribution.probs.cpu().numpy().flatten()

        if deterministic:
            action = int(np.argmax(probs))
        else:
            action = int(dist.distribution.sample().cpu().item())

        return action, probs

    def get_value(self, state: np.ndarray) -> float:
        """Return the critic's value estimate for *state*."""
        if self._model is None:
            return 0.0
        obs = np.asarray(state, dtype=np.float32).reshape(1, -1)
        obs_t = torch.as_tensor(obs, device=self._model.device)
        self._model.policy.set_training_mode(False)
        with torch.no_grad():
            value = self._model.policy.predict_values(obs_t)
        return float(value.cpu().item())

    def update(
        self,
        states: np.ndarray,
        actions: np.ndarray,
        rewards: np.ndarray,
        old_log_probs: np.ndarray,
        advantages: np.ndarray,
        epochs: int = 10,
    ) -> Dict[str, Any]:
        """Run PPO update on a batch of transitions.

        Returns a dict of training metrics including policy_loss, value_loss,
        entropy, and training_steps.
        """
        if self._model is None:
            return {"policy_loss": 0.0, "value_loss": 0.0, "entropy": 0.0, "training_steps": 0}

        device = self._model.device
        states_t     = torch.as_tensor(states,        dtype=torch.float32, device=device)
        actions_t    = torch.as_tensor(actions,       dtype=torch.long,    device=device)
        rewards_t    = torch.as_tensor(rewards,       dtype=torch.float32, device=device)
        old_lp_t     = torch.as_tensor(old_log_probs, dtype=torch.float32, device=device)
        advantages_t = torch.as_tensor(advantages,    dtype=torch.float32, device=device)

        # Normalise advantages — skip mean subtraction when std ≈ 0 to avoid zero gradients
        adv_std = advantages_t.std()
        if adv_std > 1e-6:
            advantages_t = (advantages_t - advantages_t.mean()) / adv_std
        # else: keep raw advantages to preserve gradient signal

        policy = self._model.policy
        policy.set_training_mode(True)
        optim = policy.optimizer

        total_policy_loss = 0.0
        total_value_loss  = 0.0
        total_entropy     = 0.0

        for _ in range(epochs):
            values, log_probs, entropy = policy.evaluate_actions(states_t, actions_t)
            values = values.flatten()
            ratio  = torch.exp(log_probs - old_lp_t)
            clip_r = torch.clamp(ratio, 1 - 0.2, 1 + 0.2)
            policy_loss = -torch.min(ratio * advantages_t, clip_r * advantages_t).mean()
            value_loss  = 0.5 * ((rewards_t - values) ** 2).mean()
            loss        = policy_loss + 0.5 * value_loss - 0.01 * entropy.mean()

            optim.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(policy.parameters(), 0.5)
            optim.step()

            total_policy_loss += policy_loss.item()
            total_value_loss  += value_loss.item()
            total_entropy     += entropy.mean().item()

        self._training_steps += epochs

        return {
            "policy_loss":     total_policy_loss / epochs,
            "value_loss":      total_value_loss  / epochs,
            "entropy":         total_entropy     / epochs,
            "training_steps":  epochs,
        }

    def save_model(self, path: Optional[str] = None) -> bool:
        """Save model weights and metadata.

        Saves ``policy_net.pt``, ``value_net.pt``, ``ppo_sentinel.zip`` and
        ``meta.json`` to *path* (defaults to ``self.model_path``).
        """
        if self._model is None:
            logger.warning("Cannot save — model not initialised")
            return False
        save_dir = path or self._model_path
        os.makedirs(save_dir, exist_ok=True)
        try:
            # SB3 full checkpoint (used by load_model)
            self._model.save(os.path.join(save_dir, "ppo_sentinel"))

            # Individual network weights (required by some tests)
            policy = self._model.policy
            torch.save(
                policy.mlp_extractor.policy_net.state_dict(),
                os.path.join(save_dir, "policy_net.pt"),
            )
            torch.save(
                policy.mlp_extractor.value_net.state_dict(),
                os.path.join(save_dir, "value_net.pt"),
            )

            self._write_meta(save_dir)
            logger.info("Saved DRL model v%s to %s", self._version, save_dir)
            return True
        except Exception:
            logger.exception("Failed to save model")
            return False

    def load_model(self, path: Optional[str] = None) -> bool:
        """Load model from *path* (defaults to ``self.model_path``)."""
        load_dir = path or self._model_path
        model_zip = os.path.join(load_dir, "ppo_sentinel.zip")
        if not os.path.isfile(model_zip):
            logger.info("No saved model found at %s", model_zip)
            return False
        try:
            env = DummyVecEnv([lambda: _BootstrapEnv(self._state_dim, self._action_dim)])
            self._model = PPO.load(model_zip, env=env, device="auto")
            self._read_meta(load_dir)
            logger.info("Loaded DRL model v%s from %s", self._version, model_zip)
            return True
        except Exception:
            logger.exception("Failed to load model from %s", model_zip)
            return False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _init_fresh_model(self) -> None:
        try:
            env = DummyVecEnv([lambda: _BootstrapEnv(self._state_dim, self._action_dim)])
            self._model = PPO(
                "MlpPolicy",
                env,
                policy_kwargs=_POLICY_KWARGS,
                learning_rate=3e-4,
                n_steps=2048,
                batch_size=64,
                n_epochs=10,
                gamma=0.99,
                gae_lambda=0.95,
                clip_range=0.2,
                ent_coef=0.01,
                max_grad_norm=0.5,
                verbose=0,
                device=self._device,
            )
            logger.info(
                "Initialised fresh PPO model (state_dim=%d, action_dim=%d)",
                self._state_dim, self._action_dim,
            )
        except Exception:
            logger.exception("Could not initialise PPO model — falling back to random policy")
            self._model = None

    def _read_meta(self, directory: str) -> None:
        meta_path = os.path.join(directory, "meta.json")
        if not os.path.isfile(meta_path):
            return
        try:
            with open(meta_path, "r") as fh:
                meta = json.load(fh)
            self._version        = meta.get("version", self._version)
            self._training_steps = meta.get("training_steps", self._training_steps)
        except Exception:
            logger.warning("Could not read meta at %s", meta_path)

    def _write_meta(self, directory: str) -> None:
        meta = {
            "version":        self._version,
            "state_dim":      self._state_dim,
            "action_dim":     self._action_dim,
            "training_steps": self._training_steps,
            "saved_at":       datetime.now(timezone.utc).isoformat(),
        }
        meta_path = os.path.join(directory, "meta.json")
        try:
            with open(meta_path, "w") as fh:
                json.dump(meta, fh, indent=2)
        except Exception:
            logger.warning("Could not write meta to %s", meta_path)

    def _bump_version(self) -> None:
        parts = self._version.split(".")
        try:
            parts[-1] = str(int(parts[-1]) + 1)
        except (ValueError, IndexError):
            parts = ["0", "0", "1"]
        self._version = ".".join(parts)
