"""EU General Data Protection Regulation (GDPR) compliance framework."""
import logging
from typing import Any, Dict, List

from frameworks.base import BaseFramework

logger = logging.getLogger(__name__)

_GDPR_CONTROLS: List[Dict[str, Any]] = [
    {
        "id": "GDPR-5.1a",
        "name": "Lawfulness, Fairness and Transparency",
        "description": "Personal data shall be processed lawfully, fairly and in a transparent manner in relation to the data subject.",
        "category": "Data Processing Principles",
        "article": "Article 5(1)(a)",
        "requirements": [
            "Document lawful basis for each processing activity",
            "Provide clear privacy notices to data subjects",
            "Ensure processing is fair and does not have unjustified adverse effects",
            "Maintain transparency about data processing purposes",
        ],
    },
    {
        "id": "GDPR-5.1b",
        "name": "Purpose Limitation",
        "description": "Personal data shall be collected for specified, explicit and legitimate purposes and not further processed in a manner incompatible.",
        "category": "Data Processing Principles",
        "article": "Article 5(1)(b)",
        "requirements": [
            "Specify purpose before collection begins",
            "Document all processing purposes explicitly",
            "Assess compatibility before any new processing",
            "Implement technical controls preventing purpose creep",
        ],
    },
    {
        "id": "GDPR-5.1c",
        "name": "Data Minimisation",
        "description": "Personal data shall be adequate, relevant and limited to what is necessary in relation to the purposes for which they are processed.",
        "category": "Data Processing Principles",
        "article": "Article 5(1)(c)",
        "requirements": [
            "Collect only data fields strictly necessary for stated purpose",
            "Regularly review data holdings for relevance",
            "Implement data minimisation checks at collection points",
            "Anonymise or pseudonymise data where full identification is unnecessary",
        ],
    },
    {
        "id": "GDPR-5.1d",
        "name": "Accuracy",
        "description": "Personal data shall be accurate and, where necessary, kept up to date.",
        "category": "Data Processing Principles",
        "article": "Article 5(1)(d)",
        "requirements": [
            "Implement mechanisms for data subjects to update their data",
            "Schedule periodic data accuracy reviews",
            "Rectify or erase inaccurate data without undue delay",
        ],
    },
    {
        "id": "GDPR-5.1e",
        "name": "Storage Limitation",
        "description": "Personal data shall be kept in a form which permits identification of data subjects for no longer than necessary.",
        "category": "Data Processing Principles",
        "article": "Article 5(1)(e)",
        "requirements": [
            "Define retention periods for each data category",
            "Implement automated deletion or anonymisation at end of retention period",
            "Document justification for retention periods",
            "Conduct periodic retention reviews",
        ],
    },
    {
        "id": "GDPR-5.1f",
        "name": "Integrity and Confidentiality",
        "description": "Personal data shall be processed in a manner that ensures appropriate security, including protection against unauthorised processing, loss, destruction or damage.",
        "category": "Data Processing Principles",
        "article": "Article 5(1)(f)",
        "requirements": [
            "Implement encryption for data at rest and in transit",
            "Enforce access controls based on least privilege",
            "Deploy intrusion detection and prevention systems",
            "Maintain audit logs of data access",
        ],
    },
    {
        "id": "GDPR-6",
        "name": "Lawfulness of Processing",
        "description": "Processing shall be lawful only if at least one lawful basis applies: consent, contract, legal obligation, vital interests, public task, or legitimate interests.",
        "category": "Lawful Basis",
        "article": "Article 6",
        "requirements": [
            "Identify and document lawful basis before processing begins",
            "Implement consent management platform where consent is the basis",
            "Record legitimate interest assessments",
            "Provide mechanisms to withdraw consent easily",
        ],
    },
    {
        "id": "GDPR-13",
        "name": "Transparency — Direct Collection",
        "description": "Where personal data are collected from the data subject, the controller shall provide specified information at the time of obtaining the data.",
        "category": "Transparency",
        "article": "Article 13",
        "requirements": [
            "Display identity and contact details of controller at collection point",
            "State purposes and lawful basis at point of collection",
            "Inform about data subject rights at collection point",
            "Disclose any recipients or categories of recipients",
        ],
    },
    {
        "id": "GDPR-14",
        "name": "Transparency — Indirect Collection",
        "description": "Where personal data have not been obtained from the data subject, the controller shall provide information within a reasonable period.",
        "category": "Transparency",
        "article": "Article 14",
        "requirements": [
            "Notify data subjects within one month of obtaining data",
            "Disclose source of personal data",
            "Provide all Article 13 information to indirectly collected subjects",
        ],
    },
    {
        "id": "GDPR-15",
        "name": "Right of Access",
        "description": "The data subject shall have the right to obtain confirmation of processing and access to a copy of the personal data.",
        "category": "Data Subject Rights",
        "article": "Article 15",
        "requirements": [
            "Implement subject access request (SAR) handling process",
            "Respond to SARs within one calendar month",
            "Provide data in a commonly used electronic format",
            "Verify identity of requester before disclosure",
        ],
    },
    {
        "id": "GDPR-17",
        "name": "Right to Erasure",
        "description": "The data subject shall have the right to obtain the erasure of personal data without undue delay.",
        "category": "Data Subject Rights",
        "article": "Article 17",
        "requirements": [
            "Implement erasure request processing workflow",
            "Propagate erasure to all processors and recipients",
            "Verify applicability of erasure exceptions before refusing",
            "Complete erasure within one month of valid request",
        ],
    },
    {
        "id": "GDPR-20",
        "name": "Right to Data Portability",
        "description": "The data subject shall have the right to receive personal data in a structured, commonly used and machine-readable format.",
        "category": "Data Subject Rights",
        "article": "Article 20",
        "requirements": [
            "Export data in structured machine-readable format (JSON, CSV)",
            "Support direct transmission to another controller where technically feasible",
            "Limit portability to data provided by the subject and processed by consent or contract",
        ],
    },
    {
        "id": "GDPR-22",
        "name": "Automated Decision-Making",
        "description": "The data subject shall have the right not to be subject to a decision based solely on automated processing that produces legal or significant effects.",
        "category": "Data Subject Rights",
        "article": "Article 22",
        "requirements": [
            "Identify all automated decision-making processes",
            "Implement human review mechanism for significant automated decisions",
            "Provide meaningful information about the logic involved",
            "Allow data subjects to contest automated decisions",
        ],
    },
    {
        "id": "GDPR-25",
        "name": "Data Protection by Design and Default",
        "description": "The controller shall implement appropriate technical and organisational measures designed to implement data-protection principles.",
        "category": "Privacy by Design",
        "article": "Article 25",
        "requirements": [
            "Embed privacy controls into system architecture from inception",
            "Default to the most privacy-friendly settings",
            "Implement pseudonymisation where possible",
            "Conduct privacy reviews during system design phase",
            "Apply data minimisation at the architectural level",
        ],
    },
    {
        "id": "GDPR-30",
        "name": "Records of Processing Activities",
        "description": "Each controller shall maintain a record of processing activities under its responsibility.",
        "category": "Accountability",
        "article": "Article 30",
        "requirements": [
            "Maintain a register of all processing activities (ROPA)",
            "Include purposes, categories, recipients, transfers, retention periods",
            "Keep records available for supervisory authority on request",
            "Review and update records at least annually",
        ],
    },
    {
        "id": "GDPR-32",
        "name": "Security of Processing",
        "description": "The controller and processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk.",
        "category": "Security",
        "article": "Article 32",
        "requirements": [
            "Implement pseudonymisation and encryption of personal data",
            "Ensure ongoing confidentiality, integrity, availability and resilience",
            "Restore availability and access to data in a timely manner after incident",
            "Conduct regular testing, assessing and evaluating of security measures",
            "Implement access control and authentication mechanisms",
        ],
    },
    {
        "id": "GDPR-33",
        "name": "Breach Notification to Authority",
        "description": "In the case of a personal data breach, the controller shall notify the supervisory authority within 72 hours.",
        "category": "Breach Notification",
        "article": "Article 33",
        "requirements": [
            "Implement breach detection and classification procedures",
            "Notify supervisory authority within 72 hours of becoming aware",
            "Document the nature of the breach, categories and number of subjects affected",
            "Describe measures taken or proposed to address the breach",
        ],
    },
    {
        "id": "GDPR-34",
        "name": "Breach Communication to Data Subjects",
        "description": "When a breach is likely to result in a high risk to rights and freedoms, the controller shall communicate it to data subjects without undue delay.",
        "category": "Breach Notification",
        "article": "Article 34",
        "requirements": [
            "Assess risk level of breach to data subjects",
            "Communicate breach to affected subjects in clear and plain language",
            "Describe likely consequences and measures taken",
            "Maintain communication records for accountability",
        ],
    },
    {
        "id": "GDPR-35",
        "name": "Data Protection Impact Assessment",
        "description": "Where processing is likely to result in a high risk, the controller shall carry out a DPIA prior to processing.",
        "category": "Risk Assessment",
        "article": "Article 35",
        "requirements": [
            "Identify processing operations requiring DPIA",
            "Conduct DPIA before commencing high-risk processing",
            "Include systematic description of processing and necessity assessment",
            "Assess risks to rights and freedoms and identify mitigation measures",
            "Consult the DPO during DPIA process",
        ],
    },
    {
        "id": "GDPR-37",
        "name": "Data Protection Officer",
        "description": "The controller and processor shall designate a DPO where required by regulation.",
        "category": "Accountability",
        "article": "Article 37",
        "requirements": [
            "Designate a DPO where processing is carried out by a public authority",
            "Ensure DPO has expert knowledge of data protection law and practices",
            "Publish DPO contact details and communicate them to the supervisory authority",
            "Ensure DPO is involved in all issues relating to protection of personal data",
        ],
    },
]


class GDPRFramework(BaseFramework):

    @property
    def full_name(self) -> str:
        return "General Data Protection Regulation (EU) 2016/679"

    @property
    def description(self) -> str:
        return (
            "EU regulation on data protection and privacy for all individuals "
            "within the European Union and the European Economic Area. "
            "Addresses the transfer of personal data outside the EU and EEA."
        )

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return _GDPR_CONTROLS

    def assess(
        self, policies: List[Dict], configurations: Dict
    ) -> List[Dict[str, Any]]:
        try:
            return self._assess_controls(policies, configurations)
        except Exception:
            logger.exception("GDPR assessment failed")
            raise

    def detailed_gap_analysis(
        self, current_controls: Dict
    ) -> List[Dict[str, Any]]:
        try:
            return self._default_gap_analysis(current_controls)
        except Exception:
            logger.exception("GDPR gap analysis failed")
            raise
