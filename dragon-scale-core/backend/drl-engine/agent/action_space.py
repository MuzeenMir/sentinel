"""
Discrete action space for the DRL security-policy agent.

Actions (8 total)
-----------------
0  ALLOW            – permit traffic unconditionally
1  DENY             – drop / reject traffic (1 h block)
2  RATE_LIMIT_LOW   – throttle to 1 000 pps (mild congestion)
3  RATE_LIMIT_MEDIUM– throttle to 100 pps  (moderate threat)
4  RATE_LIMIT_HIGH  – throttle to 10 pps   (severe congestion)
5  QUARANTINE_SHORT – isolate for 1 hour   (short-term threat)
6  QUARANTINE_LONG  – isolate for 24 hours (confirmed threat)
7  MONITOR          – allow but flag for deep inspection
"""

from __future__ import annotations

import random
from enum import IntEnum
from typing import Any, Dict, List, Optional


class ActionType(IntEnum):
    """Named constants for each discrete action index."""

    ALLOW = 0
    DENY = 1
    RATE_LIMIT_LOW = 2
    RATE_LIMIT_MEDIUM = 3
    RATE_LIMIT_HIGH = 4
    QUARANTINE_SHORT = 5
    QUARANTINE_LONG = 6
    MONITOR = 7


_ACTION_DEFS: List[Dict[str, Any]] = [
    {
        "index": ActionType.ALLOW,
        "name": "ALLOW",
        "description": "Permit traffic with no restrictions",
        "parameters": {},
    },
    {
        "index": ActionType.DENY,
        "name": "DENY",
        "description": "Block traffic (drop/reject) for 1 hour",
        "parameters": {"duration": 3600},
    },
    {
        "index": ActionType.RATE_LIMIT_LOW,
        "name": "RATE_LIMIT",
        "description": "Throttle to 1 000 packets/sec (mild throttle)",
        "parameters": {"packets_per_second": 1000, "burst": 2000, "duration": 600},
    },
    {
        "index": ActionType.RATE_LIMIT_MEDIUM,
        "name": "RATE_LIMIT",
        "description": "Throttle to 100 packets/sec (moderate throttle)",
        "parameters": {"packets_per_second": 100, "burst": 200, "duration": 600},
    },
    {
        "index": ActionType.RATE_LIMIT_HIGH,
        "name": "RATE_LIMIT",
        "description": "Throttle to 10 packets/sec (severe throttle)",
        "parameters": {"packets_per_second": 10, "burst": 20, "duration": 600},
    },
    {
        "index": ActionType.QUARANTINE_SHORT,
        "name": "QUARANTINE",
        "description": "Isolate source for 1 hour",
        "parameters": {
            "duration": 3600,
            "segment": "quarantine-vlan",
            "allow_dns": False,
        },
    },
    {
        "index": ActionType.QUARANTINE_LONG,
        "name": "QUARANTINE",
        "description": "Isolate source for 24 hours",
        "parameters": {
            "duration": 86400,
            "segment": "quarantine-vlan",
            "allow_dns": False,
        },
    },
    {
        "index": ActionType.MONITOR,
        "name": "MONITOR",
        "description": "Allow but flag for deep packet inspection",
        "parameters": {
            "inspection_level": "deep",
            "enhanced_logging": True,
            "alert_on_anomaly": True,
        },
    },
]


class ActionSpace:
    """Discrete 8-action space with human-readable encoding/decoding."""

    def __init__(self) -> None:
        self._actions = list(_ACTION_DEFS)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def action_dim(self) -> int:
        return len(self._actions)

    # ------------------------------------------------------------------
    # Decoding: action index → structured dict
    # ------------------------------------------------------------------

    def decode_action(self, action_idx: int) -> Dict[str, Any]:
        """Return action definition for *action_idx*.

        Falls back to MONITOR on out-of-range indices.
        """
        if not 0 <= int(action_idx) < len(self._actions):
            defn = self._actions[ActionType.MONITOR]
        else:
            defn = self._actions[int(action_idx)]

        return {
            "action": defn["name"],
            "action_code": defn["index"],
            "parameters": dict(defn["parameters"]),
        }

    # ------------------------------------------------------------------
    # Encoding: name [+ hints] → ActionType
    # ------------------------------------------------------------------

    def encode_action(
        self,
        action_name: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> ActionType:
        """Map a human-readable name (and optional parameters) to ActionType.

        Unknown names default to MONITOR.
        """
        name = action_name.upper()
        params = parameters or {}

        if name == "ALLOW":
            return ActionType.ALLOW
        if name == "DENY":
            return ActionType.DENY
        if name == "RATE_LIMIT":
            pps = params.get("packets_per_second", 1000)
            if pps >= 1000:
                return ActionType.RATE_LIMIT_LOW
            if pps >= 50:
                return ActionType.RATE_LIMIT_MEDIUM
            return ActionType.RATE_LIMIT_HIGH
        if name == "QUARANTINE":
            duration = params.get("duration", 3600)
            if duration <= 3600:
                return ActionType.QUARANTINE_SHORT
            return ActionType.QUARANTINE_LONG
        if name == "MONITOR":
            return ActionType.MONITOR
        return ActionType.MONITOR  # safe default

    # ------------------------------------------------------------------
    # Action mask
    # ------------------------------------------------------------------

    def get_action_mask(self, context: Dict[str, Any]) -> Dict[ActionType, bool]:
        """Return a mask of allowed actions given the current threat context.

        True  = action is permitted
        False = action is blocked (too aggressive or too lenient)
        """
        threat_score: float = context.get("threat_score", 0.5)
        is_internal: bool = bool(context.get("is_internal", False))

        mask: Dict[ActionType, bool] = {a: True for a in ActionType}

        # High threat: ALLOW is unsafe
        if threat_score >= 0.85:
            mask[ActionType.ALLOW] = False

        # Low threat: QUARANTINE_LONG is overkill
        if threat_score < 0.5:
            mask[ActionType.QUARANTINE_LONG] = False

        # Very low threat: QUARANTINE_SHORT is also overkill
        if threat_score < 0.3:
            mask[ActionType.QUARANTINE_SHORT] = False

        # Internal traffic: hard rate-limit is too aggressive
        if is_internal and threat_score < 0.9:
            mask[ActionType.RATE_LIMIT_HIGH] = False

        return mask

    # ------------------------------------------------------------------
    # Sampling
    # ------------------------------------------------------------------

    def sample_action(self, mask: Any = None) -> ActionType:
        """Sample a random *allowed* action.

        *mask* may be a list[bool] indexed by ActionType or a
        dict[ActionType, bool].  If all actions are masked, returns MONITOR.
        """
        if mask is None:
            return ActionType(random.randrange(self.action_dim))

        if isinstance(mask, dict):
            allowed = [a for a, allowed in mask.items() if allowed]
        else:
            allowed = [ActionType(i) for i, ok in enumerate(mask) if ok]

        return random.choice(allowed) if allowed else ActionType.MONITOR

    # ------------------------------------------------------------------
    # Descriptions
    # ------------------------------------------------------------------

    def get_action_descriptions(self) -> List[Dict[str, Any]]:
        return [
            {
                "index": a["index"],
                "name": a["name"],
                "description": a["description"],
                "default_parameters": dict(a["parameters"]),
            }
            for a in self._actions
        ]
