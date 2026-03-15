"""Compliance report generator."""
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import redis


class ComplianceReporter:
    """Generate and store compliance reports."""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
    
    def generate(self, framework_id: str, report_type: str,
                date_range: Optional[Dict] = None) -> Dict:
        """Generate compliance report."""
        report = {
            'report_id': f"rpt_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            'framework': framework_id,
            'type': report_type,
            'generated_at': datetime.utcnow().isoformat(),
            'content': self._generate_content(framework_id, report_type, date_range)
        }
        
        # Store report
        self.redis.lpush(f'compliance:reports:{framework_id}', json.dumps(report))
        self.redis.ltrim(f'compliance:reports:{framework_id}', 0, 99)
        
        return report
    
    def store_assessment(self, assessment: Dict):
        """Store compliance assessment."""
        framework = assessment.get('framework', 'UNKNOWN')
        self.redis.lpush(f'compliance:assessments:{framework}', json.dumps(assessment))
        self.redis.ltrim(f'compliance:assessments:{framework}', 0, 99)
    
    def get_history(self, framework: Optional[str], limit: int) -> List[Dict]:
        """Get report history."""
        if framework:
            reports = self.redis.lrange(f'compliance:reports:{framework}', 0, limit - 1)
        else:
            reports = []
            for key in self.redis.scan_iter('compliance:reports:*'):
                reports.extend(self.redis.lrange(key, 0, limit - 1))
        
        return [json.loads(r) for r in reports[:limit]]
    
    def _generate_content(self, framework_id: str, report_type: str,
                         date_range: Optional[Dict]) -> Dict:
        """Generate report content."""
        return {
            'executive_summary': f'{framework_id} Compliance Report',
            'assessment_period': date_range or {'start': 'N/A', 'end': 'N/A'},
            'sections': ['Overview', 'Control Assessment', 'Gaps', 'Recommendations'],
            'status': 'generated'
        }
