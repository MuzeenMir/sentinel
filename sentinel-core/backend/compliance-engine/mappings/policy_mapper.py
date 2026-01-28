"""Policy to compliance control mapper."""
from typing import Dict, List, Any


class PolicyToControlMapper:
    """Map security policies to compliance controls."""
    
    POLICY_TO_CONTROL_MAP = {
        'access_control': ['PR.AC', 'HIPAA-164.312(a)(1)', 'PCI-7', 'GDPR-32'],
        'encryption': ['PR.DS', 'HIPAA-164.312(e)(1)', 'PCI-4', 'GDPR-32'],
        'monitoring': ['DE.CM', 'HIPAA-164.312(b)', 'PCI-10', 'GDPR-32'],
        'incident_response': ['RS.RP', 'HIPAA-164.308(a)(6)', 'PCI-12', 'GDPR-33'],
        'firewall': ['PR.PT', 'PCI-1', 'DE.CM'],
        'authentication': ['PR.AC', 'HIPAA-164.312(d)', 'PCI-8'],
        'logging': ['PR.PT', 'HIPAA-164.312(b)', 'PCI-10', 'DE.AE']
    }
    
    def __init__(self, frameworks: Dict):
        self.frameworks = frameworks
    
    def map_policies(self, policies: List[Dict], framework_id: str) -> List[Dict]:
        """Map policies to framework controls."""
        mappings = []
        for policy in policies:
            policy_type = self._identify_policy_type(policy)
            controls = self._get_relevant_controls(policy_type, framework_id)
            mappings.append({
                'policy_id': policy.get('id'),
                'policy_type': policy_type,
                'mapped_controls': controls
            })
        return mappings
    
    def map_single_policy(self, policy: Dict, framework_id: str) -> Dict:
        """Map single policy to controls."""
        policy_type = self._identify_policy_type(policy)
        controls = self._get_relevant_controls(policy_type, framework_id)
        return {'policy_type': policy_type, 'controls': controls}
    
    def _identify_policy_type(self, policy: Dict) -> str:
        """Identify policy type from policy data."""
        action = policy.get('action', '').upper()
        if action in ['DENY', 'DROP']:
            return 'firewall'
        if 'auth' in str(policy).lower():
            return 'authentication'
        if 'encrypt' in str(policy).lower():
            return 'encryption'
        return 'access_control'
    
    def _get_relevant_controls(self, policy_type: str, framework_id: str) -> List[str]:
        """Get controls relevant to policy type for framework."""
        all_controls = self.POLICY_TO_CONTROL_MAP.get(policy_type, [])
        framework = self.frameworks.get(framework_id)
        if not framework:
            return all_controls
        return [c for c in all_controls if c in framework.controls]
