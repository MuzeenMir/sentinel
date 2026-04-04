"""Compliance assessment storage and report generation backed by Redis."""
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_ASSESSMENT_KEY_PREFIX = "compliance:assessment:"
_REPORT_KEY_PREFIX     = "compliance:report:"
_ASSESSMENT_INDEX      = "compliance:assessments:index"
_REPORTS_INDEX         = "compliance:reports:index"
_ASSESSMENT_TTL_DAYS   = 365
_REPORT_TTL_DAYS       = 90


class ComplianceReporter:

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    # ------------------------------------------------------------------
    # Assessment storage
    # ------------------------------------------------------------------

    def store_assessment(self, result: Dict[str, Any]) -> str:
        assessment_id = result.get(
            "assessment_id",
            f"assess_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        )
        framework = result.get("framework", "unknown")
        key = f"{_ASSESSMENT_KEY_PREFIX}{assessment_id}"

        record = {
            "assessment_id": assessment_id,
            "framework": framework,
            "timestamp": result.get("timestamp", datetime.utcnow().isoformat()),
            "overall_score": result.get("overall_score", 0.0),
            "status": result.get("status", "unknown"),
            "control_assessments": result.get("control_assessments", []),
            "gaps": result.get("gaps", []),
            "recommendations": result.get("recommendations", []),
        }

        try:
            self._redis.setex(
                key,
                timedelta(days=_ASSESSMENT_TTL_DAYS),
                json.dumps(record, default=str),
            )
            self._redis.lpush(_ASSESSMENT_INDEX, json.dumps({
                "assessment_id": assessment_id,
                "framework": framework,
                "timestamp": record["timestamp"],
                "overall_score": record["overall_score"],
                "status": record["status"],
            }))
            self._redis.ltrim(_ASSESSMENT_INDEX, 0, 999)
            logger.info("Stored assessment %s for %s", assessment_id, framework)
        except Exception:
            logger.exception("Failed to store assessment %s", assessment_id)
            raise

        return assessment_id

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate(
        self,
        framework_id: str,
        report_type: str = "summary",
        date_range: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        try:
            assessments = self._fetch_assessments(framework_id, date_range)

            if report_type == "detailed":
                raw = self._build_detailed_content(framework_id, assessments)
            elif report_type == "trend":
                raw = self._build_trend_content(framework_id, assessments)
            else:
                raw = self._build_summary_content(framework_id, assessments)

            now = datetime.utcnow().isoformat()
            report_id = f"rpt_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')[:18]}"

            # Derive assessment period
            if date_range:
                period = {
                    "start": date_range.get("start", ""),
                    "end": date_range.get("end", ""),
                }
            else:
                period = {
                    "start": (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d"),
                    "end": datetime.utcnow().strftime("%Y-%m-%d"),
                }

            content = {
                "executive_summary": raw.pop("_executive_summary",
                    f"{report_type.title()} compliance report for {framework_id}."),
                "assessment_period": period,
                "sections": raw.pop("_sections", [raw] if raw else []),
            }
            content.update(raw)   # any remaining top-level keys become part of content

            report = {
                "report_id": report_id,
                "type": report_type,
                "framework": framework_id,
                "generated_at": now,
                "content": content,
            }

            # Persist report metadata for history
            try:
                self._redis.setex(
                    f"{_REPORT_KEY_PREFIX}{report_id}",
                    timedelta(days=_REPORT_TTL_DAYS),
                    json.dumps(report, default=str),
                )
                self._redis.lpush(_REPORTS_INDEX, json.dumps({
                    "report_id": report_id,
                    "framework": framework_id,
                    "type": report_type,
                    "generated_at": now,
                }))
                self._redis.ltrim(_REPORTS_INDEX, 0, 999)
            except Exception:
                logger.exception("Failed to persist report %s", report_id)

            return report

        except Exception:
            logger.exception("Report generation failed for %s", framework_id)
            raise

    # ------------------------------------------------------------------
    # History retrieval  (reports, not assessments)
    # ------------------------------------------------------------------

    def get_history(
        self, framework: Optional[str] = None, limit: int = 10
    ) -> List[Dict[str, Any]]:
        try:
            raw_entries = self._redis.lrange(_REPORTS_INDEX, 0, limit * 3)
            history: List[Dict[str, Any]] = []
            for entry in raw_entries:
                record = json.loads(entry)
                if framework and record.get("framework", "").upper() != framework.upper():
                    continue
                history.append(record)
                if len(history) >= limit:
                    break
            return history
        except Exception:
            logger.exception("Failed to retrieve report history")
            return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_assessments(
        self, framework_id: str, date_range: Optional[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        start_dt = end_dt = None
        if date_range:
            if date_range.get("start"):
                start_dt = datetime.fromisoformat(date_range["start"])
            if date_range.get("end"):
                end_dt = datetime.fromisoformat(date_range["end"])

        raw_entries = self._redis.lrange(_ASSESSMENT_INDEX, 0, 999)
        assessments: List[Dict[str, Any]] = []

        for entry in raw_entries:
            meta = json.loads(entry)
            if meta.get("framework", "").upper() != framework_id.upper():
                continue

            ts = datetime.fromisoformat(meta["timestamp"])
            if start_dt and ts < start_dt:
                continue
            if end_dt and ts > end_dt:
                continue

            key = f"{_ASSESSMENT_KEY_PREFIX}{meta['assessment_id']}"
            raw = self._redis.get(key)
            if raw:
                assessments.append(json.loads(raw))

        return assessments

    def _build_summary_content(
        self, framework_id: str, assessments: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not assessments:
            return {
                "_executive_summary": f"No assessments found for {framework_id}.",
                "_sections": [],
            }

        latest = assessments[-1]
        scores = [a["overall_score"] for a in assessments]
        gap_counts: Dict[str, int] = {}
        for gap in latest.get("gaps", []):
            status = gap.get("status", "non_compliant")
            gap_counts[status] = gap_counts.get(status, 0) + 1

        summary = {
            "assessment_count": len(assessments),
            "current_score": latest["overall_score"],
            "current_status": latest.get("status", "unknown"),
            "average_score": round(sum(scores) / len(scores), 2),
            "gap_summary": gap_counts,
            "total_gaps": len(latest.get("gaps", [])),
            "total_recommendations": len(latest.get("recommendations", [])),
            "top_recommendations": latest.get("recommendations", [])[:5],
        }
        return {
            "_executive_summary": (
                f"Compliance score for {framework_id}: "
                f"{latest['overall_score']:.1f}% ({latest.get('status','unknown')})."
            ),
            "_sections": [summary],
        }

    def _build_detailed_content(
        self, framework_id: str, assessments: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not assessments:
            return {
                "_executive_summary": f"No assessments found for {framework_id}.",
                "_sections": [],
            }

        latest = assessments[-1]
        by_category: Dict[str, Dict[str, Any]] = {}
        for ca in latest.get("control_assessments", []):
            cat = ca.get("category", "Other")
            if cat not in by_category:
                by_category[cat] = {"compliant": 0, "partial": 0, "non_compliant": 0, "controls": []}
            bucket = by_category[cat]
            if ca["status"] == "compliant":
                bucket["compliant"] += 1
            elif ca["status"] == "partially_compliant":
                bucket["partial"] += 1
            else:
                bucket["non_compliant"] += 1
            bucket["controls"].append(ca)

        section = {
            "current_score": latest["overall_score"],
            "current_status": latest.get("status", "unknown"),
            "category_breakdown": {
                cat: {
                    "compliant": data["compliant"],
                    "partially_compliant": data["partial"],
                    "non_compliant": data["non_compliant"],
                    "total": data["compliant"] + data["partial"] + data["non_compliant"],
                }
                for cat, data in by_category.items()
            },
            "control_assessments": latest.get("control_assessments", []),
            "gaps": latest.get("gaps", []),
            "recommendations": latest.get("recommendations", []),
        }
        return {
            "_executive_summary": (
                f"Detailed compliance analysis for {framework_id}: "
                f"{latest['overall_score']:.1f}% ({latest.get('status','unknown')})."
            ),
            "_sections": [section],
        }

    def _build_trend_content(
        self, framework_id: str, assessments: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not assessments:
            return {
                "_executive_summary": f"No trend data available for {framework_id}.",
                "_sections": [],
            }

        trend_data = [
            {
                "assessment_id": a.get("assessment_id"),
                "timestamp": a.get("timestamp"),
                "score": a.get("overall_score", 0.0),
                "status": a.get("status", "unknown"),
                "gap_count": len(a.get("gaps", [])),
            }
            for a in assessments
        ]
        scores = [t["score"] for t in trend_data]
        direction = (
            "improving" if len(scores) > 1 and scores[-1] > scores[0]
            else "declining" if len(scores) > 1 and scores[-1] < scores[0]
            else "stable"
        )
        section = {
            "data_points": len(trend_data),
            "trend_direction": direction,
            "score_min": round(min(scores), 2),
            "score_max": round(max(scores), 2),
            "score_latest": scores[-1],
            "trend": trend_data,
        }
        return {
            "_executive_summary": (
                f"Trend analysis for {framework_id}: "
                f"{len(trend_data)} data points, direction={direction}."
            ),
            "_sections": [section],
        }
