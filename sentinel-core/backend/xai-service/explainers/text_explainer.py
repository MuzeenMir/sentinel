"""Natural-language explanation generator for AI detections and DRL policy decisions."""
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_THREAT_LEVELS = [
    (0.95, "critical", "overwhelmingly strong indicators"),
    (0.85, "high", "strong and corroborating indicators"),
    (0.70, "elevated", "moderate indicators that warrant investigation"),
    (0.50, "guarded", "weak indicators suggesting caution"),
    (0.0, "low", "insufficient indicators to suggest a real threat"),
]

_ACTION_LABELS: Dict[str, str] = {
    "DENY": "block the traffic",
    "ALLOW": "permit the traffic",
    "RATE_LIMIT": "throttle the traffic rate",
    "MONITOR": "continue monitoring without intervention",
    "QUARANTINE": "isolate the source for further analysis",
    "REDIRECT": "redirect the traffic to a honeypot",
}

_FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "threat_score": "aggregate threat confidence",
    "anomaly_score": "deviation from normal behaviour baseline",
    "src_reputation": "reputation score of the source address",
    "dst_reputation": "reputation score of the destination address",
    "packet_rate": "packets-per-second volume",
    "byte_rate": "bytes-per-second throughput",
    "connection_count": "number of concurrent connections from the source",
    "geo_risk": "geolocation-based risk factor",
    "time_risk": "time-of-day risk factor",
    "protocol_risk": "risk associated with the network protocol in use",
    "port_risk": "risk associated with the destination port",
    "payload_entropy": "randomness of the payload content",
    "asset_criticality": "business criticality of the targeted asset",
    "severity": "severity rating of the detection",
    "historical_alert_count": "prior alert volume from this source",
}


class TextExplainer:

    def explain_detection(
        self,
        features: Dict[str, Any],
        prediction: Dict[str, Any],
        model_verdicts: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            confidence = prediction.get("confidence", 0.0)
            is_threat = prediction.get("is_threat", confidence >= 0.5)
            level, label, qualifier = self._threat_level(confidence)

            summary = self._detection_summary(
                confidence, is_threat, label, qualifier, model_verdicts
            )
            detailed = self._detection_detailed(
                features, prediction, model_verdicts, level, label
            )

            return {"summary": summary, "detailed": detailed}
        except Exception:
            logger.exception("Text explanation for detection failed")
            return {
                "summary": "Explanation unavailable due to an internal error.",
                "detailed": "The explanation subsystem encountered an error. "
                            "Please review raw detection data for analysis.",
            }

    def explain_policy_decision(
        self,
        action: str,
        state_features: Dict[str, Any],
        confidence: float,
    ) -> Dict[str, Any]:
        try:
            action_text = _ACTION_LABELS.get(action, action.lower())
            summary = self._policy_summary(action, action_text, confidence, state_features)
            reasoning = self._policy_reasoning(action, state_features, confidence)
            basis = self._policy_basis(action, state_features, confidence)

            return {"summary": summary, "reasoning": reasoning, "basis": basis}
        except Exception:
            logger.exception("Text explanation for policy decision failed")
            return {
                "summary": "Explanation unavailable due to an internal error.",
                "reasoning": "",
                "basis": "",
            }

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _threat_level(confidence: float) -> tuple:
        for threshold, level, qualifier in _THREAT_LEVELS:
            if confidence >= threshold:
                return level, level, qualifier
        return "low", "low", "insufficient indicators"

    def _detection_summary(
        self,
        confidence: float,
        is_threat: bool,
        label: str,
        qualifier: str,
        model_verdicts: Dict[str, Any],
    ) -> str:
        verdict = "malicious" if is_threat else "benign"
        model_count = len(model_verdicts)
        agreeing = sum(
            1 for v in model_verdicts.values() if v.get("is_threat") == is_threat
        )

        summary = (
            f"The ensemble classified this event as {verdict} with {label} confidence "
            f"({confidence:.0%}), based on {qualifier}. "
            f"{agreeing} of {model_count} model(s) agree on the verdict."
        )
        return summary

    def _detection_detailed(
        self,
        features: Dict[str, Any],
        prediction: Dict[str, Any],
        model_verdicts: Dict[str, Any],
        level: str,
        label: str,
    ) -> str:
        parts: List[str] = []

        parts.append(
            f"Threat level: {label.upper()} "
            f"(confidence {prediction.get('confidence', 0.0):.1%})."
        )

        top_features = self._top_contributing_features(features, n=5)
        if top_features:
            feat_lines = []
            for name, value in top_features:
                desc = _FEATURE_DESCRIPTIONS.get(name, name.replace("_", " "))
                feat_lines.append(f"  - {desc}: {value}")
            parts.append("Key contributing factors:\n" + "\n".join(feat_lines))

        for model, verdict in model_verdicts.items():
            v = "threat" if verdict.get("is_threat") else "benign"
            c = verdict.get("confidence", 0.0)
            parts.append(f"Model '{model}' classified as {v} ({c:.1%} confidence).")

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Policy helpers
    # ------------------------------------------------------------------

    def _policy_summary(
        self,
        action: str,
        action_text: str,
        confidence: float,
        state_features: Dict[str, Any],
    ) -> str:
        threat_score = state_features.get("threat_score", 0.0)
        asset = state_features.get("asset_criticality", "unknown")

        summary = (
            f"The DRL agent decided to {action_text} (action: {action}) "
            f"with {confidence:.0%} confidence. "
            f"The threat score is {threat_score:.2f} and the targeted asset "
            f"has a criticality rating of {asset}."
        )
        return summary

    def _policy_reasoning(
        self,
        action: str,
        state_features: Dict[str, Any],
        confidence: float,
    ) -> str:
        reasons: List[str] = []
        threat_score = state_features.get("threat_score", 0.0)

        if action == "DENY":
            reasons.append(
                f"Threat score ({threat_score:.2f}) exceeds the blocking threshold."
            )
            if state_features.get("src_reputation", 1.0) < 0.3:
                reasons.append("The source has a poor reputation score.")
            if state_features.get("historical_alert_count", 0) > 5:
                reasons.append("The source has a history of prior alerts.")
        elif action == "ALLOW":
            reasons.append(
                f"Threat score ({threat_score:.2f}) is below the alerting threshold."
            )
            if state_features.get("src_reputation", 0.0) > 0.7:
                reasons.append("The source has a good reputation score.")
        elif action == "RATE_LIMIT":
            reasons.append(
                "The threat level is moderate; rate limiting reduces risk without full denial."
            )
            if state_features.get("packet_rate", 0) > 1000:
                reasons.append("High packet rate suggests volumetric abuse.")
        elif action == "MONITOR":
            reasons.append(
                "Indicators are inconclusive; continued observation is recommended."
            )

        if confidence < 0.6:
            reasons.append(
                f"Note: decision confidence is relatively low ({confidence:.0%}), "
                "suggesting borderline conditions."
            )

        return " ".join(reasons) if reasons else "No additional reasoning available."

    @staticmethod
    def _policy_basis(
        action: str,
        state_features: Dict[str, Any],
        confidence: float,
    ) -> str:
        basis_parts: List[str] = [
            "Decision informed by the following state features:"
        ]
        for feat, value in sorted(state_features.items()):
            desc = _FEATURE_DESCRIPTIONS.get(feat, feat.replace("_", " "))
            basis_parts.append(f"  - {desc} = {value}")
        basis_parts.append(
            f"\nOverall confidence in the chosen action ({action}): {confidence:.0%}."
        )
        return "\n".join(basis_parts)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _top_contributing_features(
        features: Dict[str, Any], n: int = 5
    ) -> List[tuple]:
        numeric: List[tuple] = []
        for name, value in features.items():
            if isinstance(value, (int, float)):
                numeric.append((name, value))
        numeric.sort(key=lambda x: abs(x[1]), reverse=True)
        return numeric[:n]
