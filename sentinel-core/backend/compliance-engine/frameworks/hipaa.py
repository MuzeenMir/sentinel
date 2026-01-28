"""HIPAA Framework."""
from .base import BaseFramework


class HIPAAFramework(BaseFramework):
    """HIPAA compliance framework."""
    
    @property
    def full_name(self) -> str:
        return "Health Insurance Portability and Accountability Act"
    
    @property
    def description(self) -> str:
        return "US regulation for healthcare data protection"
    
    def __init__(self):
        super().__init__()
        self.controls = {
            'HIPAA-164.308(a)(1)': {
                'name': 'Security Management Process',
                'category': 'Administrative',
                'requirements': ['risk_analysis', 'risk_management'],
                'remediation': 'Implement security management process',
                'severity': 'critical'
            },
            'HIPAA-164.308(a)(3)': {
                'name': 'Workforce Security',
                'category': 'Administrative',
                'requirements': ['authorization', 'clearance'],
                'remediation': 'Implement workforce security procedures',
                'severity': 'high'
            },
            'HIPAA-164.308(a)(5)': {
                'name': 'Security Awareness Training',
                'category': 'Administrative',
                'requirements': ['training', 'awareness'],
                'remediation': 'Conduct regular security training',
                'severity': 'medium'
            },
            'HIPAA-164.310(a)(1)': {
                'name': 'Facility Access Controls',
                'category': 'Physical',
                'requirements': ['access_control', 'facility_security'],
                'remediation': 'Implement facility access controls',
                'severity': 'high'
            },
            'HIPAA-164.312(a)(1)': {
                'name': 'Access Control',
                'category': 'Technical',
                'requirements': ['unique_user_id', 'emergency_access'],
                'remediation': 'Implement access control mechanisms',
                'severity': 'critical'
            },
            'HIPAA-164.312(b)': {
                'name': 'Audit Controls',
                'category': 'Technical',
                'requirements': ['audit_logs', 'monitoring'],
                'remediation': 'Implement audit logging',
                'severity': 'high'
            },
            'HIPAA-164.312(c)(1)': {
                'name': 'Integrity Controls',
                'category': 'Technical',
                'requirements': ['data_integrity', 'authentication'],
                'remediation': 'Implement integrity controls',
                'severity': 'high'
            },
            'HIPAA-164.312(e)(1)': {
                'name': 'Transmission Security',
                'category': 'Technical',
                'requirements': ['encryption', 'integrity_controls'],
                'remediation': 'Implement transmission security',
                'severity': 'critical'
            }
        }
