"""NIST Cybersecurity Framework."""
from .base import BaseFramework


class NISTCSFFramework(BaseFramework):
    """NIST CSF compliance framework."""
    
    @property
    def full_name(self) -> str:
        return "NIST Cybersecurity Framework"
    
    @property
    def description(self) -> str:
        return "Framework for improving critical infrastructure cybersecurity"
    
    def __init__(self):
        super().__init__()
        self.controls = {
            # IDENTIFY
            'ID.AM': {
                'name': 'Asset Management',
                'category': 'Identify',
                'requirements': ['asset_inventory', 'data_classification'],
                'remediation': 'Maintain asset inventory',
                'severity': 'high'
            },
            'ID.RA': {
                'name': 'Risk Assessment',
                'category': 'Identify',
                'requirements': ['risk_identification', 'risk_analysis'],
                'remediation': 'Conduct risk assessments',
                'severity': 'high'
            },
            # PROTECT
            'PR.AC': {
                'name': 'Identity Management and Access Control',
                'category': 'Protect',
                'requirements': ['identity_management', 'access_control'],
                'remediation': 'Implement IAM controls',
                'severity': 'critical'
            },
            'PR.DS': {
                'name': 'Data Security',
                'category': 'Protect',
                'requirements': ['data_protection', 'encryption'],
                'remediation': 'Implement data security controls',
                'severity': 'critical'
            },
            'PR.IP': {
                'name': 'Information Protection Processes',
                'category': 'Protect',
                'requirements': ['configuration_management', 'change_control'],
                'remediation': 'Establish information protection processes',
                'severity': 'high'
            },
            'PR.PT': {
                'name': 'Protective Technology',
                'category': 'Protect',
                'requirements': ['audit_logs', 'network_protection'],
                'remediation': 'Deploy protective technologies',
                'severity': 'high'
            },
            # DETECT
            'DE.AE': {
                'name': 'Anomalies and Events',
                'category': 'Detect',
                'requirements': ['baseline', 'event_detection'],
                'remediation': 'Implement anomaly detection',
                'severity': 'high'
            },
            'DE.CM': {
                'name': 'Security Continuous Monitoring',
                'category': 'Detect',
                'requirements': ['network_monitoring', 'personnel_monitoring'],
                'remediation': 'Implement continuous monitoring',
                'severity': 'critical'
            },
            'DE.DP': {
                'name': 'Detection Processes',
                'category': 'Detect',
                'requirements': ['detection_roles', 'detection_testing'],
                'remediation': 'Establish detection processes',
                'severity': 'high'
            },
            # RESPOND
            'RS.RP': {
                'name': 'Response Planning',
                'category': 'Respond',
                'requirements': ['response_plan', 'execution'],
                'remediation': 'Develop response plans',
                'severity': 'high'
            },
            'RS.CO': {
                'name': 'Communications',
                'category': 'Respond',
                'requirements': ['personnel_notification', 'external_notification'],
                'remediation': 'Establish communication procedures',
                'severity': 'medium'
            },
            'RS.MI': {
                'name': 'Mitigation',
                'category': 'Respond',
                'requirements': ['incident_containment', 'incident_mitigation'],
                'remediation': 'Implement mitigation capabilities',
                'severity': 'critical'
            },
            # RECOVER
            'RC.RP': {
                'name': 'Recovery Planning',
                'category': 'Recover',
                'requirements': ['recovery_plan', 'recovery_execution'],
                'remediation': 'Develop recovery plans',
                'severity': 'high'
            },
            'RC.IM': {
                'name': 'Improvements',
                'category': 'Recover',
                'requirements': ['lessons_learned', 'recovery_updates'],
                'remediation': 'Implement recovery improvements',
                'severity': 'medium'
            }
        }
