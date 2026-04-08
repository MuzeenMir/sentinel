"""
Offline PPO trainer that learns from experience tuples collected via the
production feedback loop.

Each experience is a single-step (state, action, reward) tuple — essentially
a contextual-bandit sample.  The trainer runs a clipped-surrogate PPO update
using the current policy as the reference distribution.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import numpy as np
import redis as _redis_mod
import torch
import torch.nn.functional as F

from agent.action_space import ActionSpace
from agent.ppo_agent import PPOAgent
from agent.reward_function import RewardFunction
from agent.state_builder import StateBuilder

logger = logging.getLogger(__name__)

_CLIP_RANGE = 0.2
_VALUE_COEF = 0.5
_ENTROPY_COEF = 0.01
_MAX_GRAD_NORM = 0.5
_DEFAULT_BATCH_SIZE = 64


class DRLTrainer:
    """Trains the PPO agent from asynchronously-collected experience dicts."""

    def __init__(
        self,
        agent: PPOAgent,
        state_builder: StateBuilder,
        action_space: ActionSpace,
        reward_function: RewardFunction,
        redis_client: _redis_mod.Redis,
    ) -> None:
        self.agent = agent
        self.state_builder = state_builder
        self.action_space = action_space
        self.reward_function = reward_function
        self.redis = redis_client

    def train_on_experiences(
        self,
        experiences: List[Dict[str, Any]],
        epochs: int = 10,
        batch_size: int = _DEFAULT_BATCH_SIZE,
    ) -> Dict[str, Any]:
        model = self.agent.model
        if model is None:
            raise RuntimeError("Agent model is not initialised — cannot train")

        valid = self._validate_experiences(experiences)
        if len(valid) < 2:
            raise ValueError(f"Need at least 2 valid experiences, got {len(valid)}")

        states = np.array([e["state"] for e in valid], dtype=np.float32)
        actions = np.array([e["action"] for e in valid], dtype=np.int64)
        rewards = np.array([e["reward"] for e in valid], dtype=np.float32)

        device = self.agent.device
        states_t = torch.as_tensor(states, device=device)
        actions_t = torch.as_tensor(actions, device=device)
        returns_t = torch.as_tensor(rewards, device=device)

        policy = model.policy
        policy.set_training_mode(False)

        with torch.no_grad():
            old_dist = policy.get_distribution(states_t)
            old_log_probs = old_dist.log_prob(actions_t)
            old_values = policy.predict_values(states_t).squeeze(-1)

        advantages = returns_t - old_values
        adv_std = advantages.std()
        if adv_std > 1e-8:
            advantages = (advantages - advantages.mean()) / adv_std

        n_samples = len(valid)
        batch_size = min(batch_size, n_samples)

        epoch_policy_losses: list[float] = []
        epoch_value_losses: list[float] = []
        epoch_entropies: list[float] = []

        t0 = time.monotonic()
        policy.set_training_mode(True)
        optimizer = policy.optimizer

        for _epoch in range(epochs):
            indices = np.random.permutation(n_samples)
            for start in range(0, n_samples, batch_size):
                idx = indices[start : start + batch_size]
                idx_t = torch.as_tensor(idx, dtype=torch.long, device=device)

                mb_states = states_t[idx_t]
                mb_actions = actions_t[idx_t]
                mb_adv = advantages[idx_t]
                mb_returns = returns_t[idx_t]
                mb_old_lp = old_log_probs[idx_t]

                dist = policy.get_distribution(mb_states)
                new_log_probs = dist.log_prob(mb_actions)
                entropy = dist.entropy().mean()
                values = policy.predict_values(mb_states).squeeze(-1)

                ratio = torch.exp(new_log_probs - mb_old_lp)
                surr1 = ratio * mb_adv
                surr2 = torch.clamp(ratio, 1.0 - _CLIP_RANGE, 1.0 + _CLIP_RANGE) * mb_adv
                policy_loss = -torch.min(surr1, surr2).mean()

                value_loss = F.mse_loss(values, mb_returns)

                loss = policy_loss + _VALUE_COEF * value_loss - _ENTROPY_COEF * entropy

                optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(policy.parameters(), _MAX_GRAD_NORM)
                optimizer.step()

                epoch_policy_losses.append(policy_loss.item())
                epoch_value_losses.append(value_loss.item())
                epoch_entropies.append(entropy.item())

        elapsed = time.monotonic() - t0

        metrics = {
            "policy_loss": float(np.mean(epoch_policy_losses)),
            "value_loss": float(np.mean(epoch_value_losses)),
            "entropy": float(np.mean(epoch_entropies)),
            "reward_mean": float(rewards.mean()),
            "reward_std": float(rewards.std()),
            "advantage_mean": float(advantages.mean().cpu()),
            "n_experiences": n_samples,
            "epochs": epochs,
            "batch_size": batch_size,
            "training_time_sec": round(elapsed, 3),
        }

        self._publish_metrics(metrics)
        logger.info(
            "Training complete: %d experiences, %d epochs, loss=%.4f in %.1fs",
            n_samples, epochs, metrics["policy_loss"], elapsed,
        )
        return metrics

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _validate_experiences(
        experiences: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        valid: list[Dict[str, Any]] = []
        for exp in experiences:
            state = exp.get("state")
            action = exp.get("action")
            reward = exp.get("reward")
            if state is None or action is None or reward is None:
                continue
            try:
                np.asarray(state, dtype=np.float32)
                int(action)
                float(reward)
            except (TypeError, ValueError):
                continue
            valid.append(exp)
        return valid

    def _publish_metrics(self, metrics: Dict[str, Any]) -> None:
        try:
            self.redis.hset("drl:training:latest", mapping={
                k: str(v) for k, v in metrics.items()
            })
        except _redis_mod.RedisError:
            logger.debug("Could not publish training metrics to Redis")
