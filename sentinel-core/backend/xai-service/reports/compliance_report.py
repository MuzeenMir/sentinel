"""Compliance-formatted report generator for AI explanations."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_FRAMEWORK_SECTIONS: Dict[str, Dict[str, Any]] = {
    "GDPR": {
        "title": "GDPR Article 22 — Automated Decision-Making Transparency Report",
        "articles": [
            "Article 13(2)(f)",
            "Article 14(2)(g)",
            "Article 15(1)(h)",
            "Article 22",
        ],
        "requirements": [
            "Meaningful information about the logic involved in automated decisions",
            "Significance and envisaged consequences of automated processing",
            "Right to obtain human intervention and contest automated decisions",
        ],
    },
    "HIPAA": {
        "title": "HIPAA Security Rule — Automated Processing Audit Report",
        "articles": ["45 CFR 164.312(b)", "45 CFR 164.308(a)(1)"],
        "requirements": [
            "Audit controls recording system activity involving ePHI",
            "Documentation of security incident investigation outcomes",
        ],
    },
    "PCI-DSS": {
        "title": "PCI DSS — Automated Threat Detection Audit Report",
        "articles": ["Requirement 10", "Requirement 12"],
        "requirements": [
            "Audit trails linking system access and automated decisions to individual events",
            "Documentation of security monitoring and response procedures",
        ],
    },
    "NIST": {
        "title": "NIST AI RMF / CSF — AI Transparency Report",
        "articles": ["MAP 2.3", "MEASURE 2.6", "MANAGE 4.1"],
        "requirements": [
            "Explanation of AI system behaviour and decision rationale",
            "Documentation of AI performance and reliability metrics",
        ],
    },
    "SOC2": {
        "title": "SOC 2 Trust Services — Processing Integrity and Monitoring Report",
        "articles": ["CC4", "CC7", "PI1"],
        "requirements": [
            "Monitoring activities and evaluation of control effectiveness",
            "Processing integrity documentation for automated systems",
        ],
    },
}


class ComplianceReportGenerator:
    def generate(
        self,
        explanations: List[Dict[str, Any]],
        framework: str = "general",
        date_range: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        try:
            filtered = self._filter_by_date(explanations, date_range)

            if framework.upper() in _FRAMEWORK_SECTIONS:
                return self._framework_report(framework.upper(), filtered)
            return self._general_report(filtered)
        except Exception:
            logger.exception("Compliance report generation failed")
            return {
                "error": "Report generation failed",
                "generated_at": datetime.utcnow().isoformat(),
            }

    # ------------------------------------------------------------------
    # Framework-specific
    # ------------------------------------------------------------------

    def _framework_report(
        self, framework: str, explanations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        section = _FRAMEWORK_SECTIONS[framework]
        by_type = self._group_by_type(explanations)
        stats = self._compute_stats(explanations)

        return {
            "report_title": section["title"],
            "framework": framework,
            "generated_at": datetime.utcnow().isoformat(),
            "applicable_articles": section["articles"],
            "compliance_requirements": section["requirements"],
            "statistics": stats,
            "sections": self._build_sections(by_type, framework),
            "attestation": (
                f"This report documents {stats['total_explanations']} AI-generated "
                f"explanations produced by SENTINEL's XAI service, covering the "
                f"period {stats['date_range']['start']} to {stats['date_range']['end']}. "
                f"All automated decisions were accompanied by machine-generated "
                f"explanations to satisfy {framework} transparency obligations."
            ),
        }

    # ------------------------------------------------------------------
    # General (framework-agnostic)
    # ------------------------------------------------------------------

    def _general_report(self, explanations: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_type = self._group_by_type(explanations)
        stats = self._compute_stats(explanations)

        return {
            "report_title": "SENTINEL AI Explanation Compliance Report",
            "framework": "general",
            "generated_at": datetime.utcnow().isoformat(),
            "statistics": stats,
            "sections": self._build_sections(by_type, "general"),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _filter_by_date(
        explanations: List[Dict[str, Any]],
        date_range: Optional[Dict[str, str]],
    ) -> List[Dict[str, Any]]:
        if not date_range:
            return explanations

        start_str = date_range.get("start")
        end_str = date_range.get("end")
        start_dt = datetime.fromisoformat(start_str) if start_str else None
        end_dt = datetime.fromisoformat(end_str) if end_str else None

        filtered: List[Dict[str, Any]] = []
        for exp in explanations:
            ts_str = exp.get("timestamp")
            if not ts_str:
                filtered.append(exp)
                continue
            try:
                ts = datetime.fromisoformat(ts_str)
            except (ValueError, TypeError):
                filtered.append(exp)
                continue
            if start_dt and ts < start_dt:
                continue
            if end_dt and ts > end_dt:
                continue
            filtered.append(exp)
        return filtered

    @staticmethod
    def _group_by_type(
        explanations: List[Dict[str, Any]],
    ) -> Dict[str, List[Dict[str, Any]]]:
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for exp in explanations:
            etype = exp.get("type", "unknown")
            groups.setdefault(etype, []).append(exp)
        return groups

    @staticmethod
    def _compute_stats(explanations: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not explanations:
            now = datetime.utcnow().isoformat()
            return {
                "total_explanations": 0,
                "by_type": {},
                "date_range": {"start": now, "end": now},
            }

        type_counts: Dict[str, int] = {}
        timestamps: List[str] = []
        for exp in explanations:
            etype = exp.get("type", "unknown")
            type_counts[etype] = type_counts.get(etype, 0) + 1
            ts = exp.get("timestamp")
            if ts:
                timestamps.append(ts)

        timestamps.sort()
        return {
            "total_explanations": len(explanations),
            "by_type": type_counts,
            "date_range": {
                "start": timestamps[0] if timestamps else "",
                "end": timestamps[-1] if timestamps else "",
            },
        }

    @staticmethod
    def _build_sections(
        by_type: Dict[str, List[Dict[str, Any]]],
        framework: str,
    ) -> List[Dict[str, Any]]:
        sections: List[Dict[str, Any]] = []

        detection_exps = by_type.get("detection", [])
        if detection_exps:
            sections.append(
                {
                    "title": "Threat Detection Explanations",
                    "description": (
                        "Automated explanations for AI-based threat detection decisions, "
                        "including feature contributions and model-level breakdowns."
                    ),
                    "count": len(detection_exps),
                    "sample_ids": [e.get("entity_id", "") for e in detection_exps[:10]],
                }
            )

        policy_exps = by_type.get("policy", [])
        if policy_exps:
            sections.append(
                {
                    "title": "Policy Decision Explanations",
                    "description": (
                        "Automated explanations for Deep Reinforcement Learning policy "
                        "decisions, including action rationale and contributing state features."
                    ),
                    "count": len(policy_exps),
                    "sample_ids": [e.get("entity_id", "") for e in policy_exps[:10]],
                }
            )

        for etype, exps in by_type.items():
            if etype in ("detection", "policy"):
                continue
            sections.append(
                {
                    "title": f"{etype.replace('_', ' ').title()} Explanations",
                    "description": f"Explanations categorised as '{etype}'.",
                    "count": len(exps),
                    "sample_ids": [e.get("entity_id", "") for e in exps[:10]],
                }
            )

        return sections
