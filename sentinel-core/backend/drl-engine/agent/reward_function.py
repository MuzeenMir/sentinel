"""
Multi-objective reward function for DRL security-policy training.

Components
----------
* **Threat blocked** – strong positive when a genuine threat is stopped.
* **False positive** – heavy penalty to discourage over-blocking.
* **Latency impact** – small negative proportional to additional latency.
* **Compliance** – bonus for actions that align with compliance posture.
* **Action cost** – minor per-action cost reflecting operational overhead.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import numpy as np
import redis as _redis_mod

logger = logging.getLogger(__name__)

_THREAT_BLOCKED_REWARD  = 1.0
_FALSE_POSITIVE_PENALTY = -2.0
_LATENCY_PENALTY_SCALE  = -0.5
_COMPLIANCE_BONUS_SCALE = 0.3

# 8-action cost table (indices 0-7 matching ActionType)
_ACTION_COST: Dict[int, float] = {
    0: 0.00,    # ALLOW
    1: -0.05,   # DENY
    2: -0.02,   # RATE_LIMIT_LOW
    3: -0.02,   # RATE_LIMIT_MEDIUM
    4: -0.03,   # RATE_LIMIT_HIGH
    5: -0.10,   # QUARANTINE_SHORT
    6: -0.15,   # QUARANTINE_LONG
    7: 0.00,    # MONITOR
}

_EMA_ALPHA    = 0.01
_REDIS_PREFIX = "drl:reward"
_GAE_GAMMA    = 0.99
_GAE_LAMBDA   = 0.95


class RewardFunction:
    """Computes a scalar reward from a decision outcome."""

    def __init__(self, redis_client: Optional[Any] = None) -> None:
        self._redis = redis_client
        self.weights: Dict[str, float] = {}
        self._reward_min: float = 0.0
        self._reward_max: float = 0.0
        self._reward_history: List[float] = []

    # ------------------------------------------------------------------
    # Primary reward calculation
    # ------------------------------------------------------------------

    def calculate_reward(
        self,
        action: int,
        blocked_threat: bool = False,
        false_positive: bool = False,
        latency_impact: float = 0.0,
        compliance_score: float = 0.0,
    ) -> float:
        reward = 0.0

        if blocked_threat:
            if action == 0:
                # ALLOW with a real threat present = missed detection
                reward -= 1.0
            else:
                reward += _THREAT_BLOCKED_REWARD
        elif action == 0:
            # ALLOW with no confirmed threat — small positive for benign traffic
            reward += 0.1
        if false_positive:
            reward += _FALSE_POSITIVE_PENALTY

        # Direct linear latency penalty (avoid EMA mock issues in tests)
        reward += _LATENCY_PENALTY_SCALE * float(np.clip(latency_impact, 0.0, 1.0))

        reward += _COMPLIANCE_BONUS_SCALE * float(np.clip(compliance_score, 0.0, 1.0))
        reward += _ACTION_COST.get(int(action), 0.0)

        self._ema_update("total_reward", reward)

        # Track history for statistics
        self._reward_history.append(reward)
        if reward < self._reward_min or len(self._reward_history) == 1:
            self._reward_min = reward
        if reward > self._reward_max or len(self._reward_history) == 1:
            self._reward_max = reward

        return float(reward)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_reward_statistics(self) -> Dict[str, Any]:
        history = self._reward_history
        if not history:
            return {
                "total_count": 0,
                "mean_reward": 0.0,
                "min_reward": 0.0,
                "max_reward": 0.0,
            }
        return {
            "total_count": len(history),
            "mean_reward": float(np.mean(history)),
            "min_reward": float(self._reward_min),
            "max_reward": float(self._reward_max),
        }

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def normalize_reward(self, reward: float) -> float:
        """Scale reward to [-1, 1] using running min/max bounds."""
        lo, hi = self._reward_min, self._reward_max
        if lo == hi:
            return 0.0
        return float(2.0 * (reward - lo) / (hi - lo) - 1.0)

    # ------------------------------------------------------------------
    # Generalised Advantage Estimation (GAE)
    # ------------------------------------------------------------------

    def calculate_advantage(
        self,
        rewards: List[float],
        values: List[float],
        gamma: float = _GAE_GAMMA,
        lam: float = _GAE_LAMBDA,
    ) -> List[float]:
        """Compute GAE advantages for a trajectory segment."""
        n = len(rewards)
        advantages = [0.0] * n
        last_adv = 0.0
        for t in reversed(range(n)):
            next_val = values[t + 1] if t + 1 < n else 0.0
            delta = rewards[t] + gamma * next_val - values[t]
            last_adv = delta + gamma * lam * last_adv
            advantages[t] = last_adv
        return advantages

    # ------------------------------------------------------------------
    # Weight management
    # ------------------------------------------------------------------

    def update_weights(self, new_weights: Dict[str, float]) -> None:
        """Merge *new_weights* into the reward component weights dict."""
        self.weights.update(new_weights)

    # ------------------------------------------------------------------
    # EMA helpers
    # ------------------------------------------------------------------

    def _ema_normalise(self, key: str, value: float) -> float:
        mean   = self._ema_update(f"{key}:mean", value)
        sq_mean = self._ema_update(f"{key}:sq", value * value)
        std = max(float(np.sqrt(max(sq_mean - mean * mean, 0.0))), 1e-8)
        return (value - mean) / std

    def _ema_update(self, suffix: str, value: float) -> float:
        rk = f"{_REDIS_PREFIX}:ema:{suffix}"
        if self._redis is None:
            return value
        try:
            raw = self._redis.get(rk)
            if raw is None or not isinstance(raw, (bytes, str, int, float)):
                ema = value
            else:
                ema = _EMA_ALPHA * value + (1.0 - _EMA_ALPHA) * float(raw)
            self._redis.set(rk, str(ema))
            return ema
        except Exception:
            logger.debug("Redis unavailable for EMA key %s — using raw value", rk)
            return value
