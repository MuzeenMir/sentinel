"""
Gymnasium environment that simulates network threat-and-response episodes
for offline DRL training.

Each step presents a new network event (benign or malicious).  The agent
chooses a response action and receives a reward that mirrors the production
reward function.  Ground-truth labels are known inside the environment but
are *not* exposed in the observation vector, so the agent must learn from
noisy threat signals.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

import gymnasium as gym
import numpy as np
from gymnasium import spaces

from agent.action_space import ActionSpace
from agent.state_builder import StateBuilder

logger = logging.getLogger(__name__)

_THREAT_TYPES = [
    "brute_force", "ddos", "port_scan", "malware",
    "data_exfiltration", "sql_injection", "c2_communication",
    "privilege_escalation", "lateral_movement", "credential_stuffing",
]

_PROTOCOLS = ["TCP", "UDP", "ICMP"]
_PROTOCOL_WEIGHTS = [0.70, 0.20, 0.10]

_COMMON_PORTS = [
    22, 23, 25, 53, 80, 110, 443, 445,
    1433, 3306, 3389, 5432, 8080, 8443, 9200,
]


class NetworkSecurityEnv(gym.Env):
    """Simulated network environment for PPO training."""

    metadata = {"render_modes": []}

    def __init__(
        self,
        state_builder: Optional[StateBuilder] = None,
        action_space_def: Optional[ActionSpace] = None,
        max_steps: int = 200,
        threat_ratio: float = 0.30,
    ) -> None:
        super().__init__()

        self._sb = state_builder or StateBuilder()
        self._asd = action_space_def or ActionSpace()
        self._max_steps = max_steps
        self._threat_ratio = threat_ratio

        self.observation_space = spaces.Box(
            low=0.0, high=1.0,
            shape=(self._sb.state_dim,),
            dtype=np.float32,
        )
        self.action_space = spaces.Discrete(self._asd.action_dim)

        self._rng: np.random.Generator = np.random.default_rng()
        self._step_count = 0
        self._current_event: Dict[str, Any] = {}
        self._episode_rewards: list[float] = []

    # -- gym API -----------------------------------------------------------

    def reset(
        self,
        *,
        seed: Optional[int] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        super().reset(seed=seed)
        self._rng = np.random.default_rng(seed)
        self._step_count = 0
        self._episode_rewards = []
        self._current_event = self._generate_event()
        obs = self._sb.build_state(self._current_event)
        return obs, {}

    def step(
        self, action: int,
    ) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
        self._step_count += 1

        is_threat = self._current_event.get("_is_threat", False)
        decoded = self._asd.decode_action(int(action))
        action_name = decoded["action"]

        reward = self._compute_reward(action_name, is_threat)
        self._episode_rewards.append(reward)

        self._current_event = self._generate_event()
        obs = self._sb.build_state(self._current_event)

        terminated = False
        truncated = self._step_count >= self._max_steps

        info: Dict[str, Any] = {
            "is_threat": is_threat,
            "action_taken": action_name,
            "step": self._step_count,
            "episode_reward": sum(self._episode_rewards),
        }
        return obs, reward, terminated, truncated, info

    # -- event generation --------------------------------------------------

    def _generate_event(self) -> Dict[str, Any]:
        is_threat = bool(self._rng.random() < self._threat_ratio)

        if is_threat:
            threat_score = float(np.clip(self._rng.normal(0.80, 0.15), 0, 1))
            threat_type: str = str(self._rng.choice(_THREAT_TYPES))
        else:
            threat_score = float(np.clip(self._rng.normal(0.15, 0.12), 0, 1))
            threat_type = "none"

        protocol: str = str(self._rng.choice(_PROTOCOLS, p=_PROTOCOL_WEIGHTS))
        dest_port = int(self._rng.choice(_COMMON_PORTS))

        if is_threat:
            src_ip = self._random_public_ip()
        else:
            src_ip = f"192.168.{self._rng.integers(0, 256)}.{self._rng.integers(1, 255)}"
        dest_ip = f"10.0.{self._rng.integers(0, 10)}.{self._rng.integers(1, 255)}"

        return {
            "threat_score": threat_score,
            "threat_type": threat_type,
            "source_ip": src_ip,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": protocol,
            "asset_criticality": float(self._rng.integers(1, 6)),
            "context": {
                "connection_rate": float(
                    self._rng.exponential(100) if is_threat else self._rng.exponential(10)
                ),
                "bytes_per_second": float(
                    self._rng.exponential(10_000) if is_threat else self._rng.exponential(1_000)
                ),
                "packets_per_second": float(
                    self._rng.exponential(500) if is_threat else self._rng.exponential(50)
                ),
                "historical_alerts": int(
                    self._rng.poisson(10) if is_threat else self._rng.poisson(1)
                ),
                "geo_risk": float(
                    self._rng.beta(5, 2) if is_threat else self._rng.beta(2, 5)
                ),
            },
            "_is_threat": is_threat,
        }

    def _random_public_ip(self) -> str:
        while True:
            octets = self._rng.integers(1, 224, size=4)
            first = int(octets[0])
            if first not in (10, 127) and not (first == 172 and 16 <= int(octets[1]) <= 31) \
               and not (first == 192 and int(octets[1]) == 168):
                return ".".join(str(int(o)) for o in octets)

    # -- reward (mirrors production RewardFunction logic) ------------------

    @staticmethod
    def _compute_reward(action_name: str, is_threat: bool) -> float:
        if is_threat:
            if action_name in ("DENY", "QUARANTINE"):
                return 1.0
            if action_name == "RATE_LIMIT":
                return 0.3
            if action_name == "MONITOR":
                return -0.3
            return -1.5  # ALLOW

        # benign traffic
        if action_name == "ALLOW":
            return 0.5
        if action_name == "MONITOR":
            return 0.2
        if action_name == "RATE_LIMIT":
            return -0.3
        return -2.0  # DENY or QUARANTINE on benign
