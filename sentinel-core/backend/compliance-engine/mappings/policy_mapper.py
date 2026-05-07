"""Maps SENTINEL firewall/security policies to compliance framework controls."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_POLICY_TYPE_KEYWORDS: Dict[str, List[str]] = {
    "firewall": [
        "firewall",
        "network",
        "traffic",
        "port",
        "protocol",
        "ingress",
        "egress",
        "deny",
        "allow",
        "block",
        "filter",
        "segment",
    ],
    "access_control": [
        "access",
        "authentication",
        "authorization",
        "rbac",
        "role",
        "privilege",
        "permission",
        "credential",
        "identity",
        "mfa",
        "login",
    ],
    "encryption": [
        "encrypt",
        "tls",
        "ssl",
        "cipher",
        "key",
        "certificate",
        "cryptograph",
        "hash",
        "aes",
        "rsa",
    ],
    "monitoring": [
        "monitor",
        "audit",
        "log",
        "alert",
        "detect",
        "siem",
        "intrusion",
        "anomaly",
        "event",
        "observation",
    ],
    "data_protection": [
        "data",
        "retention",
        "backup",
        "erasure",
        "anonymi",
        "pseudonymi",
        "mask",
        "classification",
        "privacy",
    ],
    "incident_response": [
        "incident",
        "response",
        "breach",
        "recovery",
        "forensic",
        "containment",
        "notification",
        "escalation",
    ],
    "vulnerability_management": [
        "vulnerability",
        "patch",
        "scan",
        "penetration",
        "remediat",
        "update",
        "cve",
        "exploit",
    ],
    "physical_security": [
        "physical",
        "facility",
        "badge",
        "cctv",
        "workstation",
        "media",
        "disposal",
    ],
}

_FRAMEWORK_CONTROL_KEYWORDS: Dict[str, Dict[str, List[str]]] = {
    "GDPR": {
        "encryption": ["GDPR-5.1f", "GDPR-32"],
        "access_control": ["GDPR-5.1f", "GDPR-32", "GDPR-25"],
        "monitoring": ["GDPR-5.1f", "GDPR-32"],
        "data_protection": [
            "GDPR-5.1b",
            "GDPR-5.1c",
            "GDPR-5.1e",
            "GDPR-15",
            "GDPR-17",
            "GDPR-20",
            "GDPR-25",
            "GDPR-30",
        ],
        "incident_response": ["GDPR-33", "GDPR-34"],
        "firewall": ["GDPR-32"],
    },
    "HIPAA": {
        "access_control": [
            "HIPAA-308-a3",
            "HIPAA-308-a4",
            "HIPAA-312-a",
            "HIPAA-312-d",
        ],
        "encryption": ["HIPAA-312-a", "HIPAA-312-e"],
        "monitoring": ["HIPAA-312-b", "HIPAA-308-a1"],
        "incident_response": ["HIPAA-308-a6", "HIPAA-308-a7"],
        "data_protection": ["HIPAA-312-c", "HIPAA-310-d"],
        "physical_security": ["HIPAA-310-a", "HIPAA-310-b", "HIPAA-310-c"],
        "firewall": ["HIPAA-312-e"],
        "vulnerability_management": ["HIPAA-308-a8"],
    },
    "PCI-DSS": {
        "firewall": ["PCI-1"],
        "access_control": ["PCI-7", "PCI-8", "PCI-8.3"],
        "encryption": ["PCI-3", "PCI-3.5", "PCI-4"],
        "monitoring": ["PCI-10", "PCI-11"],
        "vulnerability_management": ["PCI-5", "PCI-6", "PCI-6.4"],
        "data_protection": ["PCI-3", "PCI-3.5"],
        "physical_security": ["PCI-9"],
        "incident_response": ["PCI-12"],
    },
    "NIST": {
        "access_control": ["PR.AA"],
        "monitoring": ["DE.CM", "DE.AE"],
        "incident_response": ["RS.MA", "RS.AN", "RS.CO", "RS.MI"],
        "encryption": ["PR.DS"],
        "data_protection": ["PR.DS", "ID.AM"],
        "vulnerability_management": ["ID.RA", "PR.PS"],
        "firewall": ["PR.AA", "PR.PS"],
        "physical_security": ["PR.AA"],
    },
    "SOC2": {
        "access_control": ["CC5", "CC6"],
        "monitoring": ["CC4", "CC7"],
        "incident_response": ["CC7", "CC9"],
        "encryption": ["CC6", "C1"],
        "data_protection": ["C1", "P1", "P3", "P4"],
        "vulnerability_management": ["CC8", "CC3"],
        "firewall": ["CC6"],
        "physical_security": ["CC6"],
    },
}


class PolicyToControlMapper:
    def __init__(self, frameworks: Dict[str, Any]) -> None:
        self._frameworks = frameworks

    def map_policies(self, policies: List[Dict], framework_id: str) -> Dict[str, Any]:
        framework_id = framework_id.upper()
        if framework_id not in self._frameworks:
            logger.warning("Unknown framework for policy mapping: %s", framework_id)
            return {"framework": framework_id, "mappings": [], "unmapped": policies}

        mappings: List[Dict[str, Any]] = []
        unmapped: List[Dict] = []

        for policy in policies:
            mapping = self._map_single(policy, framework_id)
            if mapping["control_ids"]:
                mappings.append(mapping)
            else:
                unmapped.append(policy)

        return {
            "framework": framework_id,
            "total_policies": len(policies),
            "mapped_count": len(mappings),
            "unmapped_count": len(unmapped),
            "mappings": mappings,
            "unmapped": unmapped,
        }

    def map_single_policy(self, policy: Dict, framework_id: str) -> Dict[str, Any]:
        return self._map_single(policy, framework_id.upper())

    def _map_single(self, policy: Dict, framework_id: str) -> Dict[str, Any]:
        policy_types = self._classify_policy(policy)
        control_ids: List[str] = []
        mapping_rationale: List[str] = []

        fk_map = _FRAMEWORK_CONTROL_KEYWORDS.get(framework_id, {})
        for ptype in policy_types:
            matched_controls = fk_map.get(ptype, [])
            for cid in matched_controls:
                if cid not in control_ids:
                    control_ids.append(cid)
                    mapping_rationale.append(
                        f"Policy type '{ptype}' maps to control {cid}"
                    )

        return {
            "policy_id": policy.get("id", "unknown"),
            "policy_name": policy.get("name", ""),
            "policy_type": policy_types[0] if policy_types else "unknown",
            "policy_types": policy_types,
            "control_ids": control_ids,
            "controls": control_ids,  # alias for backward compat
            "rationale": mapping_rationale,
            "confidence": self._calculate_confidence(policy_types, control_ids),
        }

    def _classify_policy(self, policy: Dict) -> List[str]:
        text = " ".join(str(v) for v in policy.values()).lower()
        matched_types: List[str] = []

        for ptype, keywords in _POLICY_TYPE_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in text)
            if score >= 2:
                matched_types.append(ptype)

        if not matched_types:
            action = str(policy.get("action", "")).lower()
            if action in ("deny", "block", "drop", "reject"):
                matched_types.append("firewall")
            elif action in ("allow", "permit"):
                matched_types.append("access_control")

        return matched_types

    @staticmethod
    def _calculate_confidence(policy_types: List[str], control_ids: List[str]) -> float:
        if not policy_types or not control_ids:
            return 0.0
        type_score = min(len(policy_types) * 0.2, 0.4)
        control_score = min(len(control_ids) * 0.1, 0.6)
        return round(min(type_score + control_score, 1.0), 2)
