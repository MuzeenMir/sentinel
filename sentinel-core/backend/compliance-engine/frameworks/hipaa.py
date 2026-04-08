"""US Health Insurance Portability and Accountability Act (HIPAA) Security Rule framework."""
import logging
from typing import Any, Dict, List

from frameworks.base import BaseFramework

logger = logging.getLogger(__name__)

_HIPAA_CONTROLS: List[Dict[str, Any]] = [
    # --- Administrative Safeguards (45 CFR 164.308) ---
    {
        "id": "HIPAA-308-a1",
        "name": "Security Management Process",
        "description": "Implement policies and procedures to prevent, detect, contain, and correct security violations.",
        "category": "Administrative Safeguards",
        "reference": "45 CFR 164.308(a)(1)",
        "requirements": [
            "Conduct an accurate and thorough risk analysis",
            "Implement security measures sufficient to reduce risks to a reasonable level",
            "Apply appropriate sanctions against workforce members who violate policies",
            "Implement procedures to regularly review records of information system activity",
        ],
    },
    {
        "id": "HIPAA-308-a2",
        "name": "Assigned Security Responsibility",
        "description": "Identify the security official responsible for developing and implementing security policies and procedures.",
        "category": "Administrative Safeguards",
        "reference": "45 CFR 164.308(a)(2)",
        "requirements": [
            "Designate a security official responsible for HIPAA security",
            "Document the security official's role and responsibilities",
            "Ensure the security official has adequate authority and resources",
        ],
    },
    {
        "id": "HIPAA-308-a3",
        "name": "Workforce Security",
        "description": "Implement policies and procedures to ensure that all members of the workforce have appropriate access to ePHI.",
        "category": "Administrative Safeguards",
        "reference": "45 CFR 164.308(a)(3)",
        "requirements": [
            "Implement procedures for authorization and supervision of workforce members",
            "Implement procedures for granting and modifying access to ePHI",
            "Implement procedures for terminating access when employment ends",
            "Conduct background checks on workforce members with ePHI access",
        ],
    },
    {
        "id": "HIPAA-308-a4",
        "name": "Information Access Management",
        "description": "Implement policies and procedures for authorizing access to ePHI consistent with the minimum necessary standard.",
        "category": "Administrative Safeguards",
        "reference": "45 CFR 164.308(a)(4)",
        "requirements": [
            "Implement role-based access control for ePHI systems",
            "Establish policies for granting access to ePHI",
            "Implement procedures for reviewing and modifying user access rights",
            "Enforce minimum necessary access principle",
        ],
    },
    {
        "id": "HIPAA-308-a5",
        "name": "Security Awareness and Training",
        "description": "Implement a security awareness and training program for all members of the workforce.",
        "category": "Administrative Safeguards",
        "reference": "45 CFR 164.308(a)(5)",
        "requirements": [
            "Provide periodic security reminders to workforce",
            "Implement procedures for guarding against and detecting malicious software",
            "Implement procedures for monitoring log-in attempts and reporting discrepancies",
            "Implement procedures for creating, changing, and safeguarding passwords",
        ],
    },
    {
        "id": "HIPAA-308-a6",
        "name": "Security Incident Procedures",
        "description": "Implement policies and procedures to address security incidents.",
        "category": "Administrative Safeguards",
        "reference": "45 CFR 164.308(a)(6)",
        "requirements": [
            "Identify and respond to suspected or known security incidents",
            "Mitigate harmful effects of known security incidents to the extent practicable",
            "Document security incidents and their outcomes",
            "Implement procedures for incident escalation and notification",
        ],
    },
    {
        "id": "HIPAA-308-a7",
        "name": "Contingency Plan",
        "description": "Establish policies and procedures for responding to an emergency or occurrence that damages systems containing ePHI.",
        "category": "Administrative Safeguards",
        "reference": "45 CFR 164.308(a)(7)",
        "requirements": [
            "Establish and implement a data backup plan",
            "Establish and implement a disaster recovery plan",
            "Establish and implement an emergency mode operation plan",
            "Implement procedures for periodic testing and revision of contingency plans",
            "Assess the relative criticality of specific applications and data",
        ],
    },
    {
        "id": "HIPAA-308-a8",
        "name": "Evaluation",
        "description": "Perform periodic technical and non-technical evaluation to establish the extent to which security policies meet HIPAA requirements.",
        "category": "Administrative Safeguards",
        "reference": "45 CFR 164.308(a)(8)",
        "requirements": [
            "Conduct periodic evaluations of security policies and procedures",
            "Assess impact of environmental or operational changes on security",
            "Document evaluation findings and corrective actions",
        ],
    },
    # --- Physical Safeguards (45 CFR 164.310) ---
    {
        "id": "HIPAA-310-a",
        "name": "Facility Access Controls",
        "description": "Implement policies and procedures to limit physical access to electronic information systems and the facilities in which they are housed.",
        "category": "Physical Safeguards",
        "reference": "45 CFR 164.310(a)",
        "requirements": [
            "Establish contingency operations procedures for facility access during emergencies",
            "Implement a facility security plan to safeguard equipment and the facility",
            "Implement procedures for validating physical access based on role or function",
            "Maintain records of modifications to physical security components",
        ],
    },
    {
        "id": "HIPAA-310-b",
        "name": "Workstation Use",
        "description": "Implement policies and procedures specifying the proper functions, manner of use, and physical attributes of workstations accessing ePHI.",
        "category": "Physical Safeguards",
        "reference": "45 CFR 164.310(b)",
        "requirements": [
            "Define acceptable use policies for workstations with ePHI access",
            "Specify physical safeguards for workstations (screen locks, positioning)",
            "Restrict functions performed on workstations that access ePHI",
        ],
    },
    {
        "id": "HIPAA-310-c",
        "name": "Workstation Security",
        "description": "Implement physical safeguards for all workstations that access ePHI to restrict access to authorized users.",
        "category": "Physical Safeguards",
        "reference": "45 CFR 164.310(c)",
        "requirements": [
            "Implement physical controls to restrict workstation access",
            "Enforce automatic screen lock and session timeout",
            "Position workstations to prevent unauthorized viewing",
        ],
    },
    {
        "id": "HIPAA-310-d",
        "name": "Device and Media Controls",
        "description": "Implement policies and procedures governing the receipt and removal of hardware and electronic media containing ePHI.",
        "category": "Physical Safeguards",
        "reference": "45 CFR 164.310(d)",
        "requirements": [
            "Implement procedures for final disposal of ePHI and hardware",
            "Implement procedures for removal of ePHI before media re-use",
            "Maintain records of hardware and electronic media movements",
            "Create retrievable exact copies of ePHI before equipment moves",
        ],
    },
    # --- Technical Safeguards (45 CFR 164.312) ---
    {
        "id": "HIPAA-312-a",
        "name": "Access Control",
        "description": "Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software.",
        "category": "Technical Safeguards",
        "reference": "45 CFR 164.312(a)",
        "requirements": [
            "Assign a unique identifier for each user accessing ePHI",
            "Establish emergency access procedures for obtaining ePHI during emergencies",
            "Implement automatic logoff after period of inactivity",
            "Implement encryption and decryption mechanisms for ePHI",
        ],
    },
    {
        "id": "HIPAA-312-b",
        "name": "Audit Controls",
        "description": "Implement hardware, software, and procedural mechanisms that record and examine activity in systems containing ePHI.",
        "category": "Technical Safeguards",
        "reference": "45 CFR 164.312(b)",
        "requirements": [
            "Implement audit logging on all systems processing ePHI",
            "Record access attempts, modifications, and deletions of ePHI",
            "Implement centralized log management and correlation",
            "Review audit logs regularly for suspicious activity",
            "Retain audit logs for a minimum of six years",
        ],
    },
    {
        "id": "HIPAA-312-c",
        "name": "Integrity Controls",
        "description": "Implement policies and procedures to protect ePHI from improper alteration or destruction.",
        "category": "Technical Safeguards",
        "reference": "45 CFR 164.312(c)",
        "requirements": [
            "Implement mechanisms to authenticate and verify ePHI integrity",
            "Protect ePHI from improper alteration or destruction",
            "Implement checksums or digital signatures for data integrity verification",
        ],
    },
    {
        "id": "HIPAA-312-d",
        "name": "Person or Entity Authentication",
        "description": "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.",
        "category": "Technical Safeguards",
        "reference": "45 CFR 164.312(d)",
        "requirements": [
            "Implement multi-factor authentication for ePHI access",
            "Verify identity before granting access to ePHI systems",
            "Implement strong password policies",
            "Use certificate-based or biometric authentication where appropriate",
        ],
    },
    {
        "id": "HIPAA-312-e",
        "name": "Transmission Security",
        "description": "Implement technical security measures to guard against unauthorized access to ePHI being transmitted over electronic communications networks.",
        "category": "Technical Safeguards",
        "reference": "45 CFR 164.312(e)",
        "requirements": [
            "Implement integrity controls for ePHI in transit",
            "Encrypt ePHI in transit using TLS 1.2 or higher",
            "Implement VPN or equivalent for remote access to ePHI systems",
            "Monitor network traffic for unauthorized ePHI transmissions",
        ],
    },
]


class HIPAAFramework(BaseFramework):

    @property
    def full_name(self) -> str:
        return "Health Insurance Portability and Accountability Act — Security Rule"

    @property
    def description(self) -> str:
        return (
            "US federal law establishing national standards for the protection "
            "of electronic protected health information (ePHI). The Security Rule "
            "requires administrative, physical, and technical safeguards."
        )

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return _HIPAA_CONTROLS

    def assess(
        self, policies: List[Dict], configurations: Dict
    ) -> List[Dict[str, Any]]:
        try:
            return self._assess_controls(policies, configurations)
        except Exception:
            logger.exception("HIPAA assessment failed")
            raise

    def detailed_gap_analysis(
        self, current_controls: Dict
    ) -> List[Dict[str, Any]]:
        try:
            return self._default_gap_analysis(current_controls)
        except Exception:
            logger.exception("HIPAA gap analysis failed")
            raise
