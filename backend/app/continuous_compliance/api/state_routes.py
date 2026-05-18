from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from app.continuous_compliance.services.state.domain_status import (
    summarize_status_counts,
)

from app.continuous_compliance.services.evaluation.domain_evaluator import (
    build_operational_domain_states,
)

router = APIRouter(
    prefix="/api/v2/continuous-compliance/state",
    tags=["continuous-compliance-state"],
)


class MarkCurrentRequest(BaseModel):
    domain: str
    marked_by: Optional[str] = "system"
    status: Optional[str] = "current"
    note: Optional[str] = None


@router.get("/domains")
def domain_state():
    statuses = build_operational_domain_states()

    return {
        "summary": summarize_status_counts(statuses),
        "domains": statuses,
    }


@router.post("/domains/mark-current")
def mark_domain_current(payload: MarkCurrentRequest):
    """
    Placeholder governance action.

    This confirms the API contract without changing existing workflows.
    Persistence can be added after the UI behavior is validated.
    """
    now = datetime.now(timezone.utc).isoformat()

    return {
        "accepted": True,
        "domain": payload.domain,
        "status": payload.status,
        "marked_by": payload.marked_by,
        "marked_current_at": now,
        "note": payload.note,
    }
