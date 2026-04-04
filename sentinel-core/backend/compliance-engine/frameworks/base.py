"""Abstract base class for all compliance frameworks."""
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class BaseFramework(ABC):

    @property
    @abstractmethod
    def full_name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def controls(self) -> List[Dict[str, Any]]: ...

    def get_controls_summary(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": c["id"],
                "name": c["name"],
                "category": c["category"],
                "description": c["description"],
            }
            for c in self.controls
        ]

    def get_categories(self) -> List[str]:
        return sorted({c["category"] for c in self.controls})

    @abstractmethod
    def assess(
        self, policies: List[Dict], configurations: Dict
    ) -> List[Dict[str, Any]]: ...

    def calculate_score(self, assessment: List[Dict[str, Any]]) -> float:
        if not assessment:
            return 0.0
        compliant = sum(1 for a in assessment if a.get("status") == "compliant")
        partial = sum(
            1 for a in assessment if a.get("status") == "partially_compliant"
        )
        return round((compliant + partial * 0.5) / len(assessment) * 100, 2)

    def identify_gaps(self, assessment: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        gaps = []
        for a in assessment:
            if a.get("status") in ("non_compliant", "partially_compliant"):
                gaps.append(
                    {
                        "control_id": a["control_id"],
                        "control_name": a.get("control_name", ""),
                        "status": a["status"],
                        "findings": a.get("findings", []),
                    }
                )
        return gaps

    def get_recommendations(
        self, assessment: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        recommendations: List[Dict[str, Any]] = []
        for a in assessment:
            if a.get("status") != "compliant":
                for rec in a.get("recommendations", []):
                    recommendations.append(
                        {
                            "control_id": a["control_id"],
                            "recommendation": rec,
                            "priority": (
                                "high"
                                if a["status"] == "non_compliant"
                                else "medium"
                            ),
                        }
                    )
        return recommendations

    @abstractmethod
    def detailed_gap_analysis(
        self, current_controls: Dict
    ) -> List[Dict[str, Any]]: ...

    def prioritize_gaps(self, gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        scored = []
        for gap in gaps:
            severity = gap.get("severity", "medium")
            scored.append({**gap, "priority_score": priority_order.get(severity, 2)})
        scored.sort(key=lambda g: g["priority_score"])
        return scored

    def estimate_remediation_effort(self, gaps: List[Dict[str, Any]]) -> Dict[str, Any]:
        effort_map = {"critical": 40, "high": 24, "medium": 16, "low": 8}
        total_hours = 0
        breakdown = []
        for gap in gaps:
            severity = gap.get("severity", "medium")
            hours = effort_map.get(severity, 16)
            total_hours += hours
            breakdown.append(
                {
                    "control_id": gap.get("control_id"),
                    "estimated_hours": hours,
                    "severity": severity,
                }
            )
        return {
            "total_estimated_hours": total_hours,
            "gap_count": len(gaps),
            "breakdown": breakdown,
        }

    # ------------------------------------------------------------------
    # Shared helpers used by concrete framework implementations
    # ------------------------------------------------------------------

    def _match_policies_to_control(
        self, policies: List[Dict], control: Dict
    ) -> List[Dict]:
        matched = []
        control_keywords: set[str] = set()
        for field in ("name", "description", "category"):
            control_keywords.update(control.get(field, "").lower().split())
        for req in control.get("requirements", []):
            control_keywords.update(req.lower().split())

        for policy in policies:
            policy_text = " ".join(str(v) for v in policy.values()).lower()
            overlap = sum(
                1 for kw in control_keywords if kw in policy_text and len(kw) > 3
            )
            if overlap >= 2:
                matched.append(policy)
        return matched

    def _check_config_for_control(
        self, configurations: Dict, control: Dict
    ) -> Dict[str, Any]:
        met: List[str] = []
        unmet: List[str] = []
        for req in control.get("requirements", []):
            req_words = [w for w in req.lower().split() if len(w) > 4]
            found = False
            for key, value in configurations.items():
                config_text = f"{key} {value}".lower()
                if any(w in config_text for w in req_words):
                    found = True
                    break
            (met if found else unmet).append(req)
        return {"met": met, "unmet": unmet}

    def _assess_controls(
        self, policies: List[Dict], configurations: Dict
    ) -> List[Dict[str, Any]]:
        """Generic assessment loop reusable by all concrete frameworks."""
        results: List[Dict[str, Any]] = []
        for control in self.controls:
            matched_policies = self._match_policies_to_control(policies, control)
            config_check = self._check_config_for_control(configurations, control)

            total_reqs = len(control.get("requirements", []))
            met_count = len(config_check["met"]) + min(len(matched_policies), 1)
            ratio = met_count / max(total_reqs, 1)

            if ratio >= 0.8:
                status = "compliant"
            elif ratio >= 0.4:
                status = "partially_compliant"
            else:
                status = "non_compliant"

            findings = []
            if config_check["unmet"]:
                findings.append(
                    f"{len(config_check['unmet'])} requirement(s) not satisfied by current configuration"
                )
            if not matched_policies:
                findings.append("No matching policies found for this control")

            recommendations = []
            for unmet in config_check["unmet"]:
                recommendations.append(f"Implement: {unmet}")

            results.append(
                {
                    "control_id": control["id"],
                    "control_name": control["name"],
                    "category": control["category"],
                    "status": status,
                    "coverage_ratio": round(ratio, 2),
                    "matched_policies": len(matched_policies),
                    "requirements_met": len(config_check["met"]),
                    "requirements_total": total_reqs,
                    "findings": findings,
                    "recommendations": recommendations,
                }
            )
        return results

    def _default_gap_analysis(
        self, current_controls: Dict
    ) -> List[Dict[str, Any]]:
        """Generic gap analysis reusable by all concrete frameworks."""
        implemented_ids = set(current_controls.get("implemented", []))
        partial_ids = set(current_controls.get("partial", []))
        gaps: List[Dict[str, Any]] = []

        for control in self.controls:
            cid = control["id"]
            if cid in implemented_ids:
                continue

            is_partial = cid in partial_ids
            has_requirements = bool(control.get("requirements"))
            severity = "high" if has_requirements and not is_partial else "medium"

            gaps.append(
                {
                    "control_id": cid,
                    "control_name": control["name"],
                    "category": control["category"],
                    "status": "partially_implemented" if is_partial else "missing",
                    "severity": severity,
                    "description": control["description"],
                    "requirements": control.get("requirements", []),
                    "remediation_steps": [
                        f"Implement {control['name']}"
                    ],
                }
            )
        return gaps
