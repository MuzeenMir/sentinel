"""Data models returned by the SENTINEL SDK.

Plain dataclasses with ``from_dict`` helpers so the SDK stays
dependency-free (no Pydantic required at runtime).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DetectionResult:
    is_threat: bool
    confidence: float
    threat_type: str = ""
    detection_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DetectionResult:
        return cls(
            is_threat=data.get("is_threat", False),
            confidence=float(data.get("confidence", 0.0)),
            threat_type=data.get("threat_type", ""),
            detection_id=str(data.get("detection_id", "")),
            details=data.get("details", {}),
        )


@dataclass
class Threat:
    id: int
    source_ip: str = ""
    destination_ip: str = ""
    threat_type: str = ""
    severity: str = ""
    confidence: float = 0.0
    status: str = ""
    timestamp: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Threat:
        return cls(
            id=int(data.get("id", 0)),
            source_ip=data.get("source_ip", ""),
            destination_ip=data.get("destination_ip", ""),
            threat_type=data.get("threat_type", ""),
            severity=data.get("severity", ""),
            confidence=float(data.get("confidence", 0.0)),
            status=data.get("status", ""),
            timestamp=data.get("timestamp", ""),
            details=data.get("details", {}),
        )


@dataclass
class Alert:
    id: int
    title: str = ""
    severity: str = ""
    status: str = ""
    source: str = ""
    message: str = ""
    timestamp: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Alert:
        return cls(
            id=int(data.get("id", 0)),
            title=data.get("title", ""),
            severity=data.get("severity", ""),
            status=data.get("status", ""),
            source=data.get("source", ""),
            message=data.get("message", ""),
            timestamp=data.get("timestamp", ""),
            details=data.get("details", {}),
        )


@dataclass
class Policy:
    id: str = ""
    name: str = ""
    action: str = ""
    source: str = ""
    destination: str = ""
    protocol: str = ""
    status: str = ""
    created_at: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Policy:
        return cls(
            id=str(data.get("id", "")),
            name=data.get("name", ""),
            action=data.get("action", ""),
            source=data.get("source", ""),
            destination=data.get("destination", ""),
            protocol=data.get("protocol", ""),
            status=data.get("status", ""),
            created_at=data.get("created_at", ""),
            details=data.get("details", {}),
        )


@dataclass
class Assessment:
    framework: str = ""
    overall_score: float = 0.0
    status: str = ""
    controls: List[Dict[str, Any]] = field(default_factory=list)
    gaps: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    timestamp: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Assessment:
        return cls(
            framework=data.get("framework", ""),
            overall_score=float(data.get("overall_score", 0.0)),
            status=data.get("status", ""),
            controls=data.get("controls", []),
            gaps=data.get("gaps", []),
            recommendations=data.get("recommendations", []),
            timestamp=data.get("timestamp", ""),
        )


@dataclass
class Explanation:
    detection_id: str = ""
    summary: str = ""
    feature_importance: Dict[str, float] = field(default_factory=dict)
    contributing_factors: List[str] = field(default_factory=list)
    confidence_breakdown: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Explanation:
        return cls(
            detection_id=str(data.get("detection_id", "")),
            summary=data.get("summary", ""),
            feature_importance=data.get("feature_importance", {}),
            contributing_factors=data.get("contributing_factors", []),
            confidence_breakdown=data.get("confidence_breakdown", {}),
            timestamp=data.get("timestamp", ""),
        )
