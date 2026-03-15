"""Base framework class."""
from abc import ABC, abstractmethod
from typing import Dict, List, Any


class BaseFramework(ABC):
    """Base class for compliance frameworks."""
    
    def __init__(self):
        self.controls: Dict[str, Dict] = {}
    
    @property
    @abstractmethod
    def full_name(self) -> str:
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        pass
    
    def get_controls_summary(self) -> List[Dict]:
        """Get summary of all controls."""
        return [
            {'id': cid, 'name': ctrl.get('name'), 'category': ctrl.get('category')}
            for cid, ctrl in self.controls.items()
        ]
    
    def get_categories(self) -> List[str]:
        """Get unique categories."""
        return list(set(c.get('category', 'General') for c in self.controls.values()))
    
    def assess(self, policies: List[Dict], configurations: Dict) -> List[Dict]:
        """Assess compliance of policies against controls."""
        assessments = []
        for cid, control in self.controls.items():
            status = self._assess_control(control, policies, configurations)
            assessments.append({
                'control_id': cid,
                'control_name': control.get('name'),
                'status': status,
                'score': 100 if status == 'compliant' else 50 if status == 'partial' else 0
            })
        return assessments
    
    def _assess_control(self, control: Dict, policies: List, configs: Dict) -> str:
        """Assess a single control."""
        # Default implementation - override in specific frameworks
        requirements = control.get('requirements', [])
        met = sum(1 for r in requirements if self._check_requirement(r, policies, configs))
        
        if met == len(requirements):
            return 'compliant'
        elif met > 0:
            return 'partial'
        return 'non_compliant'
    
    def _check_requirement(self, req: str, policies: List, configs: Dict) -> bool:
        """Check if a requirement is met."""
        return True  # Override in specific implementations
    
    def calculate_score(self, assessments: List[Dict]) -> float:
        """Calculate overall compliance score."""
        if not assessments:
            return 0.0
        return sum(a.get('score', 0) for a in assessments) / len(assessments)
    
    def identify_gaps(self, assessments: List[Dict]) -> List[Dict]:
        """Identify compliance gaps."""
        return [a for a in assessments if a.get('status') != 'compliant']
    
    def get_recommendations(self, assessments: List[Dict]) -> List[Dict]:
        """Get remediation recommendations."""
        recs = []
        for a in assessments:
            if a.get('status') != 'compliant':
                control = self.controls.get(a['control_id'], {})
                recs.append({
                    'control_id': a['control_id'],
                    'recommendation': control.get('remediation', 'Implement required controls'),
                    'priority': 'high' if a.get('score', 0) == 0 else 'medium'
                })
        return recs
    
    def detailed_gap_analysis(self, current_controls: Dict) -> List[Dict]:
        """Perform detailed gap analysis."""
        gaps = []
        for cid, control in self.controls.items():
            current = current_controls.get(cid, {})
            if not current.get('implemented', False):
                gaps.append({
                    'control_id': cid,
                    'control_name': control.get('name'),
                    'gap_type': 'not_implemented',
                    'severity': control.get('severity', 'medium')
                })
        return gaps
    
    def prioritize_gaps(self, gaps: List[Dict]) -> List[Dict]:
        """Prioritize gaps for remediation."""
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        return sorted(gaps, key=lambda x: priority_order.get(x.get('severity', 'medium'), 2))
    
    def estimate_remediation_effort(self, gaps: List[Dict]) -> Dict:
        """Estimate effort to remediate gaps."""
        return {
            'total_gaps': len(gaps),
            'critical': sum(1 for g in gaps if g.get('severity') == 'critical'),
            'high': sum(1 for g in gaps if g.get('severity') == 'high'),
            'estimated_effort': f"{len(gaps) * 2} hours"
        }
