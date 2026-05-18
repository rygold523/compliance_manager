from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from app.continuous_compliance.services.reporting.summary import build_domain_summary


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_domain_statuses() -> List[Dict[str, Any]]:
    """
    Lightweight state model.

    This intentionally starts as 'unknown' until automation evidence,
    freshness checks, or human review confirms the domain state.
    """
    domains = build_domain_summary()

    statuses = []

    for item in domains:
        domain = item.get("domain")

        statuses.append({
            "id": str(uuid4()),
            "domain": domain,
            "status": "unknown",
            "status_reason": "No automated validation or governance review has confirmed this domain yet.",
            "required_actions": 1,
            "last_checked_at": utcnow_iso(),
            "last_marked_current_at": None,
            "marked_current_by": None,
            "next_review_due_at": None,
            "readiness_score": item.get("readiness_score", 0),
            "total_controls": item.get("total_controls", 0),
        })

    return statuses


def summarize_status_counts(statuses: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "current": 0,
        "valid": 0,
        "within_compliance": 0,
        "action_required": 0,
        "stale": 0,
        "unknown": 0,
    }

    for item in statuses:
        status = item.get("status", "unknown")
        if status in counts:
            counts[status] += 1
        else:
            counts["unknown"] += 1

    return counts
