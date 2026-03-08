"""SOC2 (Service Organization Control 2) Trust Services Criteria framework.

Covers the five Trust Service Categories:
    CC — Common Criteria (Security)
    A  — Availability
    C  — Confidentiality
    PI — Processing Integrity
    P  — Privacy

Reference: AICPA TSP Section 100 (2017 Trust Services Criteria)
"""
from .base import BaseFramework


class SOC2Framework(BaseFramework):
    """SOC2 Trust Services Criteria compliance framework."""

    @property
    def full_name(self) -> str:
        return "SOC2 Trust Services Criteria"

    @property
    def description(self) -> str:
        return (
            "AICPA SOC2 framework covering security, availability, confidentiality, "
            "processing integrity, and privacy of service organizations"
        )

    def __init__(self):
        super().__init__()
        self.controls = {
            # ── Common Criteria (Security) ──────────────────────────────────
            "CC1.1": {
                "name": "Control Environment — Integrity and Ethics",
                "category": "Common Criteria",
                "requirements": ["code_of_conduct", "board_oversight", "management_philosophy"],
                "remediation": "Establish and communicate a formal code of ethics and conduct",
                "severity": "high",
            },
            "CC2.1": {
                "name": "Communication of Information",
                "category": "Common Criteria",
                "requirements": ["internal_communication", "external_communication"],
                "remediation": "Implement internal and external communication policies",
                "severity": "medium",
            },
            "CC3.1": {
                "name": "Risk Assessment Process",
                "category": "Common Criteria",
                "requirements": ["risk_identification", "risk_analysis", "risk_response"],
                "remediation": "Establish a formal risk assessment process",
                "severity": "high",
            },
            "CC4.1": {
                "name": "Monitoring Activities",
                "category": "Common Criteria",
                "requirements": ["ongoing_monitoring", "separate_evaluations"],
                "remediation": "Implement continuous monitoring and periodic reviews",
                "severity": "high",
            },
            "CC5.1": {
                "name": "Control Activities — Policies and Procedures",
                "category": "Common Criteria",
                "requirements": ["documented_policies", "policy_enforcement"],
                "remediation": "Document and enforce security policies and procedures",
                "severity": "high",
            },
            "CC6.1": {
                "name": "Logical and Physical Access Controls",
                "category": "Common Criteria",
                "requirements": ["access_control", "mfa", "least_privilege"],
                "remediation": "Implement MFA, least-privilege access, and access reviews",
                "severity": "critical",
                "mapped_checks": ["ssh_root_login", "password_policy", "inactive_accounts"],
            },
            "CC6.2": {
                "name": "Authentication and Authorisation",
                "category": "Common Criteria",
                "requirements": ["authentication", "authorization", "privileged_access"],
                "remediation": "Implement strong authentication and RBAC",
                "severity": "critical",
                "mapped_checks": ["require_auth", "require_role"],
            },
            "CC6.3": {
                "name": "Access Removal Procedures",
                "category": "Common Criteria",
                "requirements": ["termination_procedures", "access_revocation"],
                "remediation": "Establish formal access removal procedures",
                "severity": "high",
            },
            "CC6.6": {
                "name": "Security Boundaries",
                "category": "Common Criteria",
                "requirements": ["network_controls", "firewall", "dmz"],
                "remediation": "Implement and document network segmentation controls",
                "severity": "critical",
                "mapped_checks": ["ip_forwarding_disabled", "tcp_syncookies"],
            },
            "CC6.7": {
                "name": "Transmission and Encryption",
                "category": "Common Criteria",
                "requirements": ["tls_in_transit", "encryption_at_rest"],
                "remediation": "Enforce TLS 1.2+ in transit; encrypt sensitive data at rest",
                "severity": "critical",
                "mapped_checks": ["redis_transit_encryption", "rds_storage_encryption"],
            },
            "CC7.1": {
                "name": "Configuration Management",
                "category": "Common Criteria",
                "requirements": ["baseline_configuration", "change_management"],
                "remediation": "Establish secure baselines and change management processes",
                "severity": "high",
                "mapped_checks": [
                    "sysctl_ip_forward", "sysctl_rp_filter", "sysctl_syncookies",
                    "suid_files", "world_writable_files", "unowned_files",
                ],
            },
            "CC7.2": {
                "name": "Monitoring and Anomaly Detection",
                "category": "Common Criteria",
                "requirements": ["event_monitoring", "anomaly_detection", "alerting"],
                "remediation": "Deploy security monitoring and threat detection tools",
                "severity": "critical",
            },
            "CC7.3": {
                "name": "Incident Response",
                "category": "Common Criteria",
                "requirements": ["incident_response_plan", "escalation", "post_mortem"],
                "remediation": "Implement and test an incident response plan",
                "severity": "high",
            },
            "CC7.4": {
                "name": "Security Incident Notification",
                "category": "Common Criteria",
                "requirements": ["customer_notification", "regulatory_notification"],
                "remediation": "Establish timely security incident notification procedures",
                "severity": "high",
            },
            "CC8.1": {
                "name": "Change Management",
                "category": "Common Criteria",
                "requirements": ["change_authorization", "testing", "approval"],
                "remediation": "Implement formal change management and approval workflows",
                "severity": "medium",
            },
            "CC9.1": {
                "name": "Risk Mitigation — Vendor Management",
                "category": "Common Criteria",
                "requirements": ["vendor_assessment", "vendor_monitoring"],
                "remediation": "Assess and monitor third-party service providers",
                "severity": "medium",
            },
            # ── Availability ────────────────────────────────────────────────
            "A1.1": {
                "name": "Capacity and Performance",
                "category": "Availability",
                "requirements": ["capacity_planning", "performance_monitoring"],
                "remediation": "Implement capacity planning and auto-scaling",
                "severity": "high",
            },
            "A1.2": {
                "name": "Business Continuity and Disaster Recovery",
                "category": "Availability",
                "requirements": ["backup", "recovery_testing", "rto_rpo"],
                "remediation": "Establish and test DR procedures with defined RTO/RPO",
                "severity": "critical",
            },
            # ── Confidentiality ─────────────────────────────────────────────
            "C1.1": {
                "name": "Confidential Information Classification",
                "category": "Confidentiality",
                "requirements": ["data_classification", "handling_procedures"],
                "remediation": "Implement data classification and handling policies",
                "severity": "high",
            },
            "C1.2": {
                "name": "Confidentiality Obligations",
                "category": "Confidentiality",
                "requirements": ["nda", "confidentiality_agreements"],
                "remediation": "Establish confidentiality agreements with employees and vendors",
                "severity": "medium",
            },
            # ── Processing Integrity ─────────────────────────────────────────
            "PI1.1": {
                "name": "Processing Completeness and Accuracy",
                "category": "Processing Integrity",
                "requirements": ["input_validation", "error_handling", "completeness_checks"],
                "remediation": "Implement input validation and processing accuracy controls",
                "severity": "high",
            },
            # ── Privacy ──────────────────────────────────────────────────────
            "P1.1": {
                "name": "Privacy Notice",
                "category": "Privacy",
                "requirements": ["privacy_notice", "data_subject_rights"],
                "remediation": "Publish and maintain a comprehensive privacy notice",
                "severity": "medium",
            },
            "P3.1": {
                "name": "Consent",
                "category": "Privacy",
                "requirements": ["consent_mechanism", "consent_withdrawal"],
                "remediation": "Implement mechanisms to collect and withdraw consent",
                "severity": "high",
            },
            "P4.1": {
                "name": "Data Retention and Disposal",
                "category": "Privacy",
                "requirements": ["retention_policy", "secure_disposal"],
                "remediation": "Implement data retention schedules and secure deletion",
                "severity": "high",
            },
        }
