"""Payment Card Industry Data Security Standard (PCI DSS) v4.0 compliance framework."""

import logging
from typing import Any, Dict, List

from frameworks.base import BaseFramework

logger = logging.getLogger(__name__)

_PCI_DSS_CONTROLS: List[Dict[str, Any]] = [
    {
        "id": "PCI-1",
        "name": "Install and Maintain Network Security Controls",
        "description": "Network security controls (NSCs) such as firewalls and other network security technologies are used to restrict traffic between trusted and untrusted networks.",
        "category": "Build and Maintain a Secure Network",
        "requirement": "Requirement 1",
        "requirements": [
            "Define and implement firewall and router configurations",
            "Restrict inbound and outbound traffic to that which is necessary",
            "Prohibit direct public access between the internet and cardholder data environment",
            "Install personal firewall software on portable computing devices",
            "Document and maintain network diagrams showing all cardholder data flows",
        ],
    },
    {
        "id": "PCI-2",
        "name": "Apply Secure Configurations to All System Components",
        "description": "Vendor-supplied defaults and other security parameters shall be changed before systems are deployed.",
        "category": "Build and Maintain a Secure Network",
        "requirement": "Requirement 2",
        "requirements": [
            "Change vendor-supplied defaults before installing on the network",
            "Develop configuration standards for all system components",
            "Encrypt all non-console administrative access using strong cryptography",
            "Maintain an inventory of system components in scope for PCI DSS",
        ],
    },
    {
        "id": "PCI-3",
        "name": "Protect Stored Account Data",
        "description": "Methods such as encryption, truncation, masking, and hashing protect stored account data.",
        "category": "Protect Account Data",
        "requirement": "Requirement 3",
        "requirements": [
            "Keep cardholder data storage to a minimum with data retention and disposal policies",
            "Do not store sensitive authentication data after authorization",
            "Mask PAN when displayed so that only authorized personnel can see full PAN",
            "Render PAN unreadable anywhere it is stored using strong cryptography",
            "Document and implement key management procedures for cryptographic keys",
        ],
    },
    {
        "id": "PCI-4",
        "name": "Protect Cardholder Data with Strong Cryptography During Transmission",
        "description": "Use strong cryptography and security protocols to protect cardholder data during transmission over open, public networks.",
        "category": "Protect Account Data",
        "requirement": "Requirement 4",
        "requirements": [
            "Use strong cryptography (TLS 1.2+) for cardholder data in transit over public networks",
            "Never send unprotected PANs by end-user messaging technologies",
            "Document and implement policies for transmission of cardholder data",
            "Maintain an inventory of trusted keys and certificates",
        ],
    },
    {
        "id": "PCI-5",
        "name": "Protect All Systems and Networks from Malicious Software",
        "description": "Protect all systems likely to be affected by malicious software with regularly updated anti-malware mechanisms.",
        "category": "Maintain a Vulnerability Management Program",
        "requirement": "Requirement 5",
        "requirements": [
            "Deploy anti-malware software on all systems commonly affected by malware",
            "Ensure anti-malware mechanisms are kept current and perform periodic scans",
            "Ensure anti-malware mechanisms are actively running and cannot be disabled by users",
            "Implement mechanisms to detect and protect against phishing attacks",
        ],
    },
    {
        "id": "PCI-6",
        "name": "Develop and Maintain Secure Systems and Software",
        "description": "Develop applications securely and protect systems and software from known vulnerabilities by installing applicable security patches.",
        "category": "Maintain a Vulnerability Management Program",
        "requirement": "Requirement 6",
        "requirements": [
            "Establish a process to identify and assign risk ranking to security vulnerabilities",
            "Install critical security patches within one month of release",
            "Develop software applications in accordance with secure development guidelines",
            "Protect web applications against known attacks (OWASP Top 10)",
            "Implement change control procedures for all changes to system components",
        ],
    },
    {
        "id": "PCI-7",
        "name": "Restrict Access to System Components and Cardholder Data by Business Need to Know",
        "description": "Access to system components and cardholder data is limited to only those individuals whose job requires such access.",
        "category": "Implement Strong Access Control Measures",
        "requirement": "Requirement 7",
        "requirements": [
            "Implement access control system that restricts access based on need to know",
            "Define access needs for each role and restrict accordingly",
            "Set default deny-all for access control systems",
            "Review access rights at least semi-annually",
        ],
    },
    {
        "id": "PCI-8",
        "name": "Identify Users and Authenticate Access to System Components",
        "description": "Assign a unique ID to each person with computer access and implement strong authentication.",
        "category": "Implement Strong Access Control Measures",
        "requirement": "Requirement 8",
        "requirements": [
            "Assign a unique ID to each person with computer access",
            "Implement multi-factor authentication for all access into the CDE",
            "Implement multi-factor authentication for all remote network access",
            "Enforce password length minimum of 12 characters with complexity requirements",
            "Do not use group, shared, or generic accounts and passwords",
            "Implement account lockout after no more than 10 invalid access attempts",
        ],
    },
    {
        "id": "PCI-9",
        "name": "Restrict Physical Access to Cardholder Data",
        "description": "Use physical access controls to limit and monitor physical access to systems that store, process, or transmit cardholder data.",
        "category": "Implement Strong Access Control Measures",
        "requirement": "Requirement 9",
        "requirements": [
            "Use appropriate facility entry controls to limit physical access to the CDE",
            "Implement procedures to distinguish between onsite personnel and visitors",
            "Control physical access to publicly accessible network jacks",
            "Restrict physical access to wireless access points and network devices",
            "Protect media containing cardholder data against physical theft",
        ],
    },
    {
        "id": "PCI-10",
        "name": "Log and Monitor All Access to System Components and Cardholder Data",
        "description": "Implement logging mechanisms and be able to track and monitor all access to network resources and cardholder data.",
        "category": "Regularly Monitor and Test Networks",
        "requirement": "Requirement 10",
        "requirements": [
            "Implement audit trails to link access to individual users",
            "Record audit trail entries for all access to cardholder data",
            "Synchronize all critical system clocks using NTP",
            "Review logs for all system components at least daily",
            "Retain audit trail history for at least 12 months with 3 months immediately available",
            "Deploy file-integrity monitoring to detect unauthorized changes to critical files",
        ],
    },
    {
        "id": "PCI-11",
        "name": "Test Security of Systems and Networks Regularly",
        "description": "System components, processes, and bespoke and custom software are tested regularly to ensure security controls continue to reflect a changing environment.",
        "category": "Regularly Monitor and Test Networks",
        "requirement": "Requirement 11",
        "requirements": [
            "Implement wireless access point detection processes quarterly",
            "Run internal and external network vulnerability scans at least quarterly",
            "Perform external and internal penetration testing at least annually",
            "Deploy intrusion-detection or intrusion-prevention techniques on all traffic",
            "Deploy a change-detection mechanism to alert on unauthorized modification",
        ],
    },
    {
        "id": "PCI-12",
        "name": "Support Information Security with Organizational Policies and Programs",
        "description": "Maintain a policy that addresses information security for all personnel.",
        "category": "Maintain an Information Security Policy",
        "requirement": "Requirement 12",
        "requirements": [
            "Establish, publish, maintain, and disseminate a security policy",
            "Implement a risk-assessment process performed at least annually",
            "Develop usage policies for critical technologies",
            "Ensure the security policy clearly defines information security responsibilities",
            "Assign information security management to a qualified individual or team",
            "Implement a formal security awareness program for all personnel",
            "Screen potential personnel prior to hire to minimize insider threat risk",
        ],
    },
    {
        "id": "PCI-3.5",
        "name": "Protect Stored Primary Account Numbers (PAN)",
        "description": "PAN is secured wherever it is stored, using any of several approved methods.",
        "category": "Protect Account Data",
        "requirement": "Requirement 3.5",
        "requirements": [
            "Render PAN unreadable using one-way hashes, truncation, index tokens, or strong cryptography",
            "If disk-level encryption is used, logical access must be managed independently",
            "Limit cryptographic key access to fewest number of custodians necessary",
        ],
    },
    {
        "id": "PCI-6.4",
        "name": "Public-Facing Web Application Protection",
        "description": "Public-facing web applications are protected against attacks.",
        "category": "Maintain a Vulnerability Management Program",
        "requirement": "Requirement 6.4",
        "requirements": [
            "Deploy a web application firewall (WAF) in front of public-facing web applications",
            "Keep WAF rules up to date to address new vulnerabilities",
            "Review public-facing web applications using automated or manual tools annually",
        ],
    },
    {
        "id": "PCI-8.3",
        "name": "Strong Authentication for Users and Administrators",
        "description": "Strong authentication for users and administrators is established and managed.",
        "category": "Implement Strong Access Control Measures",
        "requirement": "Requirement 8.3",
        "requirements": [
            "Implement MFA for all non-console administrative access",
            "Implement MFA for all remote access to the CDE",
            "Authenticate all access to any database containing cardholder data",
            "Require unique credentials for service and application accounts",
        ],
    },
]


class PCIDSSFramework(BaseFramework):
    @property
    def full_name(self) -> str:
        return "Payment Card Industry Data Security Standard v4.0"

    @property
    def description(self) -> str:
        return (
            "Global security standard for all entities that store, process, or "
            "transmit cardholder data. PCI DSS v4.0 provides a baseline of "
            "technical and operational requirements to protect payment account data."
        )

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return _PCI_DSS_CONTROLS

    def assess(
        self, policies: List[Dict], configurations: Dict
    ) -> List[Dict[str, Any]]:
        try:
            return self._assess_controls(policies, configurations)
        except Exception:
            logger.exception("PCI DSS assessment failed")
            raise

    def detailed_gap_analysis(self, current_controls: Dict) -> List[Dict[str, Any]]:
        try:
            return self._default_gap_analysis(current_controls)
        except Exception:
            logger.exception("PCI DSS gap analysis failed")
            raise
