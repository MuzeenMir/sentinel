"""NIST Cybersecurity Framework (CSF) 2.0 compliance framework."""

import logging
from typing import Any, Dict, List

from frameworks.base import BaseFramework

logger = logging.getLogger(__name__)

_NIST_CSF_CONTROLS: List[Dict[str, Any]] = [
    # --- Govern (GV) ---
    {
        "id": "GV.OC",
        "name": "Organizational Context",
        "description": "The circumstances — mission, stakeholder expectations, dependencies, and legal/regulatory/contractual requirements — surrounding the organization's cybersecurity risk management decisions are understood.",
        "category": "Govern",
        "function": "GV",
        "requirements": [
            "Identify and document the organizational mission and objectives",
            "Determine cybersecurity-related stakeholder expectations",
            "Identify legal, regulatory, and contractual cybersecurity requirements",
            "Understand dependencies and critical functions of the organization",
        ],
    },
    {
        "id": "GV.RM",
        "name": "Risk Management Strategy",
        "description": "The organization's priorities, constraints, risk tolerance, and appetite statements are established, communicated, and used to support operational risk decisions.",
        "category": "Govern",
        "function": "GV",
        "requirements": [
            "Establish and communicate risk tolerance and appetite",
            "Define a cybersecurity risk management strategy",
            "Integrate cybersecurity risk into enterprise risk management",
            "Determine and communicate strategic direction for risk response",
        ],
    },
    {
        "id": "GV.RR",
        "name": "Roles, Responsibilities, and Authorities",
        "description": "Cybersecurity roles, responsibilities, and authorities to foster accountability are established and communicated.",
        "category": "Govern",
        "function": "GV",
        "requirements": [
            "Define cybersecurity roles and responsibilities across the organization",
            "Establish accountability for cybersecurity risk management",
            "Communicate authorities for cybersecurity decisions",
            "Ensure adequate resourcing for cybersecurity functions",
        ],
    },
    {
        "id": "GV.PO",
        "name": "Policy",
        "description": "Organizational cybersecurity policy is established, communicated, and enforced.",
        "category": "Govern",
        "function": "GV",
        "requirements": [
            "Establish cybersecurity policy based on organizational context and strategy",
            "Communicate policy to all relevant parties",
            "Review and update policy at planned intervals or after significant changes",
            "Enforce policy through appropriate mechanisms",
        ],
    },
    {
        "id": "GV.OV",
        "name": "Oversight",
        "description": "Results of organization-wide cybersecurity risk management activities are used to inform, improve, and adjust the risk management strategy.",
        "category": "Govern",
        "function": "GV",
        "requirements": [
            "Review cybersecurity risk management outcomes at the leadership level",
            "Adjust strategy based on performance metrics and lessons learned",
            "Report cybersecurity posture to stakeholders",
        ],
    },
    {
        "id": "GV.SC",
        "name": "Cybersecurity Supply Chain Risk Management",
        "description": "Cyber supply chain risk management processes are identified, established, managed, monitored, and improved by organizational stakeholders.",
        "category": "Govern",
        "function": "GV",
        "requirements": [
            "Identify and prioritize suppliers and third-party partners",
            "Establish cybersecurity requirements for suppliers",
            "Integrate supply chain risk management into cybersecurity processes",
            "Monitor suppliers for cybersecurity risk on an ongoing basis",
        ],
    },
    # --- Identify (ID) ---
    {
        "id": "ID.AM",
        "name": "Asset Management",
        "description": "Assets that enable the organization to achieve business purposes are identified and managed consistent with their relative importance.",
        "category": "Identify",
        "function": "ID",
        "requirements": [
            "Inventory all hardware assets within the organization",
            "Inventory all software platforms and applications",
            "Map organizational communication and data flows",
            "Catalog external information systems and services",
            "Prioritize assets based on classification, criticality, and business value",
        ],
    },
    {
        "id": "ID.RA",
        "name": "Risk Assessment",
        "description": "The organization understands the cybersecurity risk to organizational operations, assets, and individuals.",
        "category": "Identify",
        "function": "ID",
        "requirements": [
            "Identify and document asset vulnerabilities",
            "Receive and correlate cyber threat intelligence from multiple sources",
            "Identify both internal and external threats",
            "Determine potential business impacts and likelihoods",
            "Use risk assessments to determine risk responses",
        ],
    },
    {
        "id": "ID.IM",
        "name": "Improvement",
        "description": "Improvements to organizational cybersecurity risk management processes, procedures, and activities are identified across all CSF Functions.",
        "category": "Identify",
        "function": "ID",
        "requirements": [
            "Establish processes for continuous improvement of cybersecurity posture",
            "Evaluate effectiveness of current cybersecurity practices",
            "Implement corrective actions based on assessment findings",
        ],
    },
    # --- Protect (PR) ---
    {
        "id": "PR.AA",
        "name": "Identity Management, Authentication, and Access Control",
        "description": "Access to physical and logical assets is limited to authorized users, services, and hardware and managed commensurate with the assessed risk.",
        "category": "Protect",
        "function": "PR",
        "requirements": [
            "Manage identities and credentials for authorized devices, users, and processes",
            "Implement multi-factor authentication for network and privileged access",
            "Enforce least-privilege and separation of duties",
            "Manage remote access sessions with appropriate controls",
            "Manage network integrity through network segregation and segmentation",
        ],
    },
    {
        "id": "PR.AT",
        "name": "Awareness and Training",
        "description": "The organization's personnel are provided cybersecurity awareness and are trained to perform their cybersecurity-related duties.",
        "category": "Protect",
        "function": "PR",
        "requirements": [
            "Provide cybersecurity awareness training to all users",
            "Train privileged users in their security responsibilities",
            "Train third-party stakeholders in their security obligations",
            "Ensure senior executives understand their cybersecurity roles",
        ],
    },
    {
        "id": "PR.DS",
        "name": "Data Security",
        "description": "Data is managed consistent with the organization's risk strategy to protect the confidentiality, integrity, and availability of information.",
        "category": "Protect",
        "function": "PR",
        "requirements": [
            "Protect data-at-rest with encryption or equivalent safeguards",
            "Protect data-in-transit with encryption or equivalent safeguards",
            "Manage assets throughout removal, transfers, and disposition",
            "Maintain adequate capacity to ensure availability",
            "Implement protections against data leaks",
        ],
    },
    {
        "id": "PR.PS",
        "name": "Platform Security",
        "description": "The hardware, software, and services of physical and virtual platforms are managed consistent with the organization's risk strategy.",
        "category": "Protect",
        "function": "PR",
        "requirements": [
            "Establish and apply configuration baselines for IT and OT systems",
            "Integrate software lifecycle management with secure development practices",
            "Manage the hardware lifecycle from acquisition through disposal",
            "Apply log management to support continuous monitoring",
        ],
    },
    {
        "id": "PR.IR",
        "name": "Technology Infrastructure Resilience",
        "description": "Security architectures are managed with the organization's risk strategy to protect asset confidentiality, integrity, and availability, and organizational resilience.",
        "category": "Protect",
        "function": "PR",
        "requirements": [
            "Establish and maintain redundancy in network and system infrastructure",
            "Implement resilient system design to tolerate component failures",
            "Implement and test backup and recovery processes",
            "Ensure infrastructure supports continuity of operations",
        ],
    },
    # --- Detect (DE) ---
    {
        "id": "DE.CM",
        "name": "Continuous Monitoring",
        "description": "Assets are monitored to find anomalies, indicators of compromise, and other potentially adverse events.",
        "category": "Detect",
        "function": "DE",
        "requirements": [
            "Monitor networks for potential cybersecurity events",
            "Monitor the physical environment for potential cybersecurity events",
            "Monitor personnel activity for potential cybersecurity events",
            "Detect malicious code and unauthorized mobile code",
            "Detect unauthorized external service provider activity",
            "Monitor for unauthorized personnel, connections, devices, and software",
        ],
    },
    {
        "id": "DE.AE",
        "name": "Adverse Event Analysis",
        "description": "Anomalies, indicators of compromise, and other potentially adverse events are analyzed to characterize the events and detect cybersecurity incidents.",
        "category": "Detect",
        "function": "DE",
        "requirements": [
            "Establish and maintain baselines of network operations and expected data flows",
            "Analyze detected events to understand attack targets and methods",
            "Correlate event data from multiple sources and sensors",
            "Determine impact of events and establish incident thresholds",
        ],
    },
    # --- Respond (RS) ---
    {
        "id": "RS.MA",
        "name": "Incident Management",
        "description": "Responses to detected cybersecurity incidents are managed.",
        "category": "Respond",
        "function": "RS",
        "requirements": [
            "Execute incident response plan upon incident detection",
            "Triage and validate incident reports",
            "Categorize and prioritize incidents based on severity",
            "Escalate incidents according to established criteria",
        ],
    },
    {
        "id": "RS.AN",
        "name": "Incident Analysis",
        "description": "Investigations are conducted to ensure effective response and support forensics and recovery activities.",
        "category": "Respond",
        "function": "RS",
        "requirements": [
            "Investigate notifications from detection systems",
            "Understand the scope and impact of incidents",
            "Perform forensics on collected evidence",
            "Classify incidents in accordance with response plans",
        ],
    },
    {
        "id": "RS.CO",
        "name": "Incident Response Reporting and Communication",
        "description": "Response activities are coordinated with internal and external stakeholders as required.",
        "category": "Respond",
        "function": "RS",
        "requirements": [
            "Notify stakeholders including management and legal",
            "Coordinate with law enforcement as appropriate",
            "Share information with external parties as required",
            "Communicate incident status updates to designated stakeholders",
        ],
    },
    {
        "id": "RS.MI",
        "name": "Incident Mitigation",
        "description": "Activities are performed to prevent expansion of an event and mitigate its effects.",
        "category": "Respond",
        "function": "RS",
        "requirements": [
            "Contain incidents to prevent further damage",
            "Mitigate incidents in accordance with playbooks",
            "Address newly identified vulnerabilities revealed by the incident",
        ],
    },
    # --- Recover (RC) ---
    {
        "id": "RC.RP",
        "name": "Incident Recovery Plan Execution",
        "description": "Restoration activities are performed to ensure operational availability of systems and services affected by cybersecurity incidents.",
        "category": "Recover",
        "function": "RC",
        "requirements": [
            "Execute recovery plan during or after a cybersecurity incident",
            "Prioritize recovery actions based on business impact",
            "Verify the integrity of restored systems and data",
            "Confirm normal operations and declare incident closed",
        ],
    },
    {
        "id": "RC.CO",
        "name": "Incident Recovery Communication",
        "description": "Restoration activities are coordinated with internal and external parties.",
        "category": "Recover",
        "function": "RC",
        "requirements": [
            "Manage public relations during and after recovery",
            "Communicate recovery status to internal and external stakeholders",
            "Update recovery strategies based on lessons learned",
        ],
    },
]


class NISTCSFFramework(BaseFramework):
    @property
    def full_name(self) -> str:
        return "NIST Cybersecurity Framework (CSF) 2.0"

    @property
    def description(self) -> str:
        return (
            "A voluntary framework by the National Institute of Standards and "
            "Technology consisting of standards, guidelines, and best practices "
            "to manage cybersecurity-related risk. Version 2.0 adds the Govern "
            "function and expands supply chain risk management."
        )

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return _NIST_CSF_CONTROLS

    def get_categories(self) -> List[str]:
        return ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]

    def assess(
        self, policies: List[Dict], configurations: Dict
    ) -> List[Dict[str, Any]]:
        try:
            return self._assess_controls(policies, configurations)
        except Exception:
            logger.exception("NIST CSF assessment failed")
            raise

    def detailed_gap_analysis(self, current_controls: Dict) -> List[Dict[str, Any]]:
        try:
            return self._default_gap_analysis(current_controls)
        except Exception:
            logger.exception("NIST CSF gap analysis failed")
            raise
