"""AICPA SOC 2 Trust Services Criteria compliance framework."""

import logging
from typing import Any, Dict, List

from frameworks.base import BaseFramework

logger = logging.getLogger(__name__)

_SOC2_CONTROLS: List[Dict[str, Any]] = [
    # --- Security (Common Criteria) ---
    {
        "id": "CC1",
        "name": "Control Environment",
        "description": "The entity demonstrates a commitment to integrity and ethical values, exercises oversight responsibility, establishes structure and authority, and demonstrates commitment to competence.",
        "category": "Security",
        "trust_category": "Common Criteria",
        "requirements": [
            "Define and communicate a commitment to integrity and ethical values",
            "Exercise board oversight of internal controls and security",
            "Establish organizational structure and reporting lines for security",
            "Demonstrate commitment to attract, develop, and retain competent security personnel",
            "Hold individuals accountable for internal control responsibilities",
        ],
    },
    {
        "id": "CC2",
        "name": "Communication and Information",
        "description": "The entity uses relevant, quality information to support the functioning of internal control and communicates internal control information internally and externally.",
        "category": "Security",
        "trust_category": "Common Criteria",
        "requirements": [
            "Obtain or generate relevant, quality information for internal control",
            "Communicate internal control information internally",
            "Communicate security policies and objectives to external parties",
            "Provide communication channels for reporting security matters",
        ],
    },
    {
        "id": "CC3",
        "name": "Risk Assessment",
        "description": "The entity specifies suitable objectives, identifies and analyzes risk, and assesses the potential for fraud.",
        "category": "Security",
        "trust_category": "Common Criteria",
        "requirements": [
            "Specify security objectives with sufficient clarity to identify risk",
            "Identify and analyze risks to the achievement of security objectives",
            "Assess fraud risk including management override of controls",
            "Identify and assess changes that could significantly impact internal controls",
        ],
    },
    {
        "id": "CC4",
        "name": "Monitoring Activities",
        "description": "The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether components of internal control are present and functioning.",
        "category": "Security",
        "trust_category": "Common Criteria",
        "requirements": [
            "Perform ongoing and/or separate evaluations of internal controls",
            "Evaluate and communicate internal control deficiencies in a timely manner",
            "Monitor effectiveness of security controls on a continuous basis",
        ],
    },
    {
        "id": "CC5",
        "name": "Control Activities",
        "description": "The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives.",
        "category": "Security",
        "trust_category": "Common Criteria",
        "requirements": [
            "Select and develop control activities to mitigate risks",
            "Select and develop general controls over technology",
            "Deploy control activities through policies and procedures",
            "Implement segregation of duties or alternative controls",
        ],
    },
    {
        "id": "CC6",
        "name": "Logical and Physical Access Controls",
        "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets.",
        "category": "Security",
        "trust_category": "Common Criteria",
        "requirements": [
            "Implement logical access security over protected assets",
            "Authenticate users before granting access to protected assets",
            "Manage credentials for infrastructure and software",
            "Restrict physical access to facilities and protected information assets",
            "Manage and dispose of assets securely when no longer needed",
            "Implement encryption to protect data in transit and at rest",
        ],
    },
    {
        "id": "CC7",
        "name": "System Operations",
        "description": "The entity detects and monitors changes to infrastructure and software that may introduce vulnerabilities, and manages system component lifecycle.",
        "category": "Security",
        "trust_category": "Common Criteria",
        "requirements": [
            "Detect and monitor configuration changes that introduce vulnerabilities",
            "Monitor system components for anomalies indicative of malicious acts",
            "Evaluate security events to determine whether they constitute incidents",
            "Respond to identified security incidents through defined procedures",
            "Implement recovery procedures to restore systems after incidents",
        ],
    },
    {
        "id": "CC8",
        "name": "Change Management",
        "description": "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
        "category": "Security",
        "trust_category": "Common Criteria",
        "requirements": [
            "Authorize, test, and approve changes before implementation",
            "Implement change management procedures for infrastructure and software",
            "Implement emergency change management procedures",
            "Maintain baseline configurations and documentation of changes",
        ],
    },
    {
        "id": "CC9",
        "name": "Risk Mitigation",
        "description": "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions and vendor management.",
        "category": "Security",
        "trust_category": "Common Criteria",
        "requirements": [
            "Identify and assess risks from business disruptions",
            "Assess and manage risks associated with vendors and business partners",
            "Implement risk mitigation activities including insurance and backup measures",
        ],
    },
    # --- Availability ---
    {
        "id": "A1",
        "name": "Availability",
        "description": "The entity maintains, monitors, and evaluates current processing capacity and environmental protections to meet availability commitments and system requirements.",
        "category": "Availability",
        "trust_category": "Availability",
        "requirements": [
            "Maintain capacity to meet processing demands and availability commitments",
            "Implement environmental protections and redundancy for critical systems",
            "Test recovery plan procedures regularly",
            "Define and monitor availability SLAs and uptime targets",
            "Implement automated failover and load balancing mechanisms",
        ],
    },
    # --- Processing Integrity ---
    {
        "id": "PI1",
        "name": "Processing Integrity",
        "description": "The entity implements policies and procedures over system processing to ensure completeness, validity, accuracy, timeliness, and authorization.",
        "category": "Processing Integrity",
        "trust_category": "Processing Integrity",
        "requirements": [
            "Define specifications for system processing objectives",
            "Implement data input controls to ensure completeness and accuracy",
            "Implement processing controls to ensure data is processed completely and accurately",
            "Implement output controls to ensure system output is complete and accurate",
            "Implement procedures to address processing errors and exceptions",
        ],
    },
    # --- Confidentiality ---
    {
        "id": "C1",
        "name": "Confidentiality",
        "description": "The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality.",
        "category": "Confidentiality",
        "trust_category": "Confidentiality",
        "requirements": [
            "Identify and classify confidential information",
            "Implement controls to protect confidential information from unauthorized access",
            "Implement data masking and tokenization for confidential data",
            "Dispose of confidential information securely when no longer needed",
            "Monitor access to confidential information",
        ],
    },
    # --- Privacy ---
    {
        "id": "P1",
        "name": "Notice",
        "description": "The entity provides notice to data subjects about its privacy practices, including the purposes for which personal information is collected and used.",
        "category": "Privacy",
        "trust_category": "Privacy",
        "requirements": [
            "Provide notice about privacy practices at or before the time of collection",
            "Describe the purposes for collection and use of personal information",
            "Describe the choices available to data subjects",
        ],
    },
    {
        "id": "P2",
        "name": "Choice and Consent",
        "description": "The entity communicates choices available regarding collection, use, retention, disclosure, and disposal of personal information.",
        "category": "Privacy",
        "trust_category": "Privacy",
        "requirements": [
            "Communicate choices available to data subjects",
            "Obtain implicit or explicit consent for collection and use of personal information",
            "Allow data subjects to update their consent preferences",
        ],
    },
    {
        "id": "P3",
        "name": "Collection",
        "description": "Personal information is collected consistent with the entity's objectives related to privacy.",
        "category": "Privacy",
        "trust_category": "Privacy",
        "requirements": [
            "Collect personal information only for the purposes identified in the notice",
            "Collect personal information by fair and lawful means",
            "Limit collection to the minimum necessary for identified purposes",
        ],
    },
    {
        "id": "P4",
        "name": "Use, Retention, and Disposal",
        "description": "Personal information is limited to the purposes identified in the notice, retained as necessary, and securely disposed of.",
        "category": "Privacy",
        "trust_category": "Privacy",
        "requirements": [
            "Limit use of personal information to purposes identified in the notice",
            "Retain personal information only as long as necessary to fulfill purposes",
            "Dispose of personal information securely when no longer needed",
        ],
    },
    {
        "id": "P5",
        "name": "Access",
        "description": "The entity provides data subjects with access to their personal information for review and update.",
        "category": "Privacy",
        "trust_category": "Privacy",
        "requirements": [
            "Provide data subjects with access to their personal information",
            "Authenticate data subjects before providing access",
            "Implement mechanisms for data subjects to update their information",
        ],
    },
    {
        "id": "P6",
        "name": "Disclosure and Notification",
        "description": "Personal information is disclosed to third parties only for identified purposes and with the consent of the data subject.",
        "category": "Privacy",
        "trust_category": "Privacy",
        "requirements": [
            "Disclose personal information to third parties only for identified purposes with consent",
            "Notify affected data subjects and authorities in the event of a data breach",
            "Document all disclosures of personal information to third parties",
        ],
    },
    {
        "id": "P7",
        "name": "Quality",
        "description": "The entity collects and maintains accurate, up-to-date, complete, and relevant personal information.",
        "category": "Privacy",
        "trust_category": "Privacy",
        "requirements": [
            "Maintain personal information that is accurate, complete, and relevant",
            "Implement processes to identify and correct inaccuracies",
            "Provide mechanisms for data subjects to request corrections",
        ],
    },
    {
        "id": "P8",
        "name": "Monitoring and Enforcement",
        "description": "The entity monitors compliance with its privacy commitments and procedures and has procedures to address privacy-related complaints and disputes.",
        "category": "Privacy",
        "trust_category": "Privacy",
        "requirements": [
            "Monitor compliance with privacy policies and procedures",
            "Implement procedures for handling privacy-related inquiries and complaints",
            "Perform periodic privacy impact assessments",
            "Define and enforce corrective and disciplinary actions for privacy violations",
        ],
    },
]


class SOC2Framework(BaseFramework):
    @property
    def full_name(self) -> str:
        return "AICPA SOC 2 — Trust Services Criteria"

    @property
    def description(self) -> str:
        return (
            "Framework developed by the American Institute of Certified Public "
            "Accountants (AICPA) for managing customer data based on five Trust "
            "Services Criteria: Security, Availability, Processing Integrity, "
            "Confidentiality, and Privacy."
        )

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return _SOC2_CONTROLS

    def get_categories(self) -> List[str]:
        return [
            "Security",
            "Availability",
            "Processing Integrity",
            "Confidentiality",
            "Privacy",
        ]

    def assess(
        self, policies: List[Dict], configurations: Dict
    ) -> List[Dict[str, Any]]:
        try:
            return self._assess_controls(policies, configurations)
        except Exception:
            logger.exception("SOC 2 assessment failed")
            raise

    def detailed_gap_analysis(self, current_controls: Dict) -> List[Dict[str, Any]]:
        try:
            return self._default_gap_analysis(current_controls)
        except Exception:
            logger.exception("SOC 2 gap analysis failed")
            raise
