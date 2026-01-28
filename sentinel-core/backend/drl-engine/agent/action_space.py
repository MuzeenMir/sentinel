"""
Action Space definition for DRL policy decisions.
"""
import logging
from typing import Dict, List, Any
from enum import IntEnum

logger = logging.getLogger(__name__)


class ActionType(IntEnum):
    """Enumeration of available actions."""
    ALLOW = 0
    DENY = 1
    RATE_LIMIT_LOW = 2
    RATE_LIMIT_MEDIUM = 3
    RATE_LIMIT_HIGH = 4
    QUARANTINE_SHORT = 5
    QUARANTINE_LONG = 6
    MONITOR = 7


class ActionSpace:
    """
    Define and manage the action space for DRL policy decisions.
    
    Actions:
    - ALLOW: Allow traffic
    - DENY: Block traffic
    - RATE_LIMIT: Apply rate limiting (low/medium/high)
    - QUARANTINE: Isolate source (short/long duration)
    - MONITOR: Continue monitoring without action
    """
    
    # Action definitions with parameters
    ACTIONS = {
        ActionType.ALLOW: {
            'name': 'ALLOW',
            'description': 'Allow traffic to pass',
            'parameters': {}
        },
        ActionType.DENY: {
            'name': 'DENY',
            'description': 'Block/drop traffic',
            'parameters': {
                'duration': 3600  # 1 hour default
            }
        },
        ActionType.RATE_LIMIT_LOW: {
            'name': 'RATE_LIMIT',
            'description': 'Apply low rate limiting',
            'parameters': {
                'packets_per_second': 1000,
                'burst': 500
            }
        },
        ActionType.RATE_LIMIT_MEDIUM: {
            'name': 'RATE_LIMIT',
            'description': 'Apply medium rate limiting',
            'parameters': {
                'packets_per_second': 100,
                'burst': 50
            }
        },
        ActionType.RATE_LIMIT_HIGH: {
            'name': 'RATE_LIMIT',
            'description': 'Apply high rate limiting (strict)',
            'parameters': {
                'packets_per_second': 10,
                'burst': 5
            }
        },
        ActionType.QUARANTINE_SHORT: {
            'name': 'QUARANTINE',
            'description': 'Quarantine source for 1 hour',
            'parameters': {
                'duration': 3600,
                'isolate_completely': True
            }
        },
        ActionType.QUARANTINE_LONG: {
            'name': 'QUARANTINE',
            'description': 'Quarantine source for 24 hours',
            'parameters': {
                'duration': 86400,
                'isolate_completely': True
            }
        },
        ActionType.MONITOR: {
            'name': 'MONITOR',
            'description': 'Continue monitoring, no action',
            'parameters': {
                'enhanced_logging': True
            }
        }
    }
    
    def __init__(self):
        self.action_dim = len(ActionType)
    
    def decode_action(self, action: int) -> Dict[str, Any]:
        """
        Decode action index to action definition.
        
        Args:
            action: Action index (0 to action_dim-1)
            
        Returns:
            Action definition with name and parameters
        """
        try:
            action_type = ActionType(action)
            action_def = self.ACTIONS[action_type]
            
            return {
                'action': action_def['name'],
                'action_code': action,
                'description': action_def['description'],
                'parameters': action_def['parameters'].copy()
            }
        
        except ValueError:
            logger.warning(f"Invalid action index: {action}")
            return {
                'action': 'MONITOR',
                'action_code': ActionType.MONITOR,
                'description': 'Default to monitor',
                'parameters': {}
            }
    
    def encode_action(self, action_name: str, parameters: Dict = None) -> int:
        """
        Encode action name to action index.
        
        Args:
            action_name: Name of the action
            parameters: Optional parameters to match
            
        Returns:
            Action index
        """
        action_name = action_name.upper()
        
        for action_type, action_def in self.ACTIONS.items():
            if action_def['name'] == action_name:
                # If parameters specified, try to match
                if parameters:
                    if action_name == 'RATE_LIMIT':
                        pps = parameters.get('packets_per_second', 100)
                        if pps >= 500:
                            return ActionType.RATE_LIMIT_LOW
                        elif pps >= 50:
                            return ActionType.RATE_LIMIT_MEDIUM
                        else:
                            return ActionType.RATE_LIMIT_HIGH
                    
                    elif action_name == 'QUARANTINE':
                        duration = parameters.get('duration', 3600)
                        if duration > 7200:  # > 2 hours
                            return ActionType.QUARANTINE_LONG
                        else:
                            return ActionType.QUARANTINE_SHORT
                
                return action_type
        
        # Default to MONITOR
        return ActionType.MONITOR
    
    def get_action_descriptions(self) -> List[Dict[str, Any]]:
        """Get descriptions of all actions."""
        descriptions = []
        
        for action_type in ActionType:
            action_def = self.ACTIONS[action_type]
            descriptions.append({
                'index': int(action_type),
                'name': action_def['name'],
                'description': action_def['description'],
                'parameters': action_def['parameters']
            })
        
        return descriptions
    
    def get_action_mask(self, state: Dict[str, Any]) -> List[bool]:
        """
        Get mask of valid actions for a given state.
        
        Some actions may not be valid in certain contexts.
        
        Args:
            state: Current state information
            
        Returns:
            List of booleans indicating valid actions
        """
        mask = [True] * self.action_dim
        
        # Always allow MONITOR
        mask[ActionType.MONITOR] = True
        
        # Don't allow ALLOW for very high threat scores
        threat_score = state.get('threat_score', 0.5)
        if threat_score > 0.95:
            mask[ActionType.ALLOW] = False
        
        # Don't allow long quarantine for low threats
        if threat_score < 0.5:
            mask[ActionType.QUARANTINE_LONG] = False
        
        # Don't allow strict rate limiting for internal traffic
        if state.get('is_internal', False):
            mask[ActionType.RATE_LIMIT_HIGH] = False
        
        return mask
    
    def sample_action(self, mask: List[bool] = None) -> int:
        """
        Sample a random action (optionally with mask).
        
        Args:
            mask: Optional action mask
            
        Returns:
            Sampled action index
        """
        import random
        
        if mask:
            valid_actions = [i for i, valid in enumerate(mask) if valid]
            return random.choice(valid_actions)
        
        return random.randint(0, self.action_dim - 1)
