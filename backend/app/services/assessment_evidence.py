from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from app.api.changelog import write_changelog
from app.auth.service import audit
from app.models.models import Assessment, AssessmentEvidence, Evidence


ASSESSMENT_STATUSES = frozenset({"planned", "in_progress", "completed", "closed", "cancelled"})
ACTIVE_ASSESSMENT_STATUSES = frozenset({"planned", "in_progress"})
ALLOWED_TRANSITIONS = {
    "planned": frozenset({"in_progress", "cancelled"}),
    "in_progress": frozenset({"completed", "cancelled"}),
    "completed": frozenset({"closed", "in_progress"}),
    "closed": frozenset(),
    "cancelled": frozenset(),
}


def _clean(value: str | None, field: str, maximum: int) -> str:
    result = (value or "").strip()
    if not result:
        raise ValueError(f"{field} is required.")
    if len(result) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters.")
    return result


def serialize_assessment(row: Assessment, evidence_ids: list[str] | None = None) -> dict:
    return {
        "assessment_id": row.assessment_id,
        "name": row.name,
        "framework": row.framework,
        "status": row.status,
        "active": row.status in ACTIVE_ASSESSMENT_STATUSES,
        "owner": row.owner,
        "description": row.description,
        "starts_at": row.starts_at,
        "ends_at": row.ends_at,
        "created_by": row.created_by,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "evidence_ids": evidence_ids or [],
    }


def create_assessment(db: Session, *, name: str, owner: str, actor: str,
                      framework: str | None = None, description: str | None = None,
                      starts_at: datetime | None = None, ends_at: datetime | None = None) -> Assessment:
    actor = _clean(actor, "actor", 128)
    name = _clean(name, "name", 255)
    owner = _clean(owner, "owner", 255)
    if starts_at and ends_at and ends_at < starts_at:
        raise ValueError("ends_at cannot be earlier than starts_at.")
    row = Assessment(
        assessment_id=f"ASM-{uuid4().hex}", name=name, framework=(framework or "").strip() or None,
        status="planned", owner=owner, description=(description or "").strip() or None,
        starts_at=starts_at, ends_at=ends_at, created_by=actor,
    )
    db.add(row)
    audit(db, "assessment_created", username=actor, detail={"assessment_id": row.assessment_id, "name": name})
    db.commit()
    db.refresh(row)
    write_changelog("assessment_created", "compliance-dashboard", f"Assessment {row.assessment_id} was created.",
                    {"assessment_id": row.assessment_id, "name": name, "owner": owner, "actor_username": actor})
    return row


def update_status(db: Session, assessment_id: str, status: str, actor: str) -> Assessment:
    actor = _clean(actor, "actor", 128)
    status = status.strip().lower()
    if status not in ASSESSMENT_STATUSES:
        raise ValueError("Unsupported assessment status.")
    row = db.query(Assessment).filter(Assessment.assessment_id == assessment_id).first()
    if row is None:
        raise LookupError("Assessment not found.")
    if status == row.status:
        return row
    if status != row.status and status not in ALLOWED_TRANSITIONS[row.status]:
        raise ValueError(f"Assessment cannot transition from {row.status} to {status}.")
    previous = row.status
    row.status = status
    row.updated_at = datetime.now(timezone.utc)
    audit(db, "assessment_status_changed", username=actor,
          detail={"assessment_id": assessment_id, "previous_status": previous, "status": status})
    db.commit()
    db.refresh(row)
    write_changelog("assessment_status_changed", "compliance-dashboard",
                    f"Assessment {assessment_id} status changed from {previous} to {status}.",
                    {"assessment_id": assessment_id, "previous_status": previous, "status": status,
                     "actor_username": actor})
    return row


def link_evidence(db: Session, assessment_id: str, evidence_id: str, actor: str,
                  rationale: str | None = None) -> AssessmentEvidence:
    actor = _clean(actor, "actor", 128)
    assessment = db.query(Assessment).filter(Assessment.assessment_id == assessment_id).first()
    if assessment is None:
        raise LookupError("Assessment not found.")
    if assessment.status in {"closed", "cancelled"}:
        raise ValueError("Evidence cannot be linked to a closed or cancelled assessment.")
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise LookupError("Evidence not found.")
    existing = db.query(AssessmentEvidence).filter(
        AssessmentEvidence.assessment_id == assessment_id,
        AssessmentEvidence.evidence_id == evidence_id,
    ).first()
    if existing:
        return existing
    row = AssessmentEvidence(assessment_id=assessment_id, evidence_id=evidence_id,
                             linked_by=actor, rationale=(rationale or "").strip() or None)
    db.add(row)
    audit(db, "assessment_evidence_linked", username=actor,
          detail={"assessment_id": assessment_id, "evidence_id": evidence_id})
    db.commit()
    db.refresh(row)
    write_changelog("assessment_evidence_linked", evidence.asset_id or "compliance-dashboard",
                    f"Evidence {evidence_id} was linked to assessment {assessment_id}.",
                    {"assessment_id": assessment_id, "evidence_id": evidence_id,
                     "rationale": row.rationale, "actor_username": actor})
    return row


def unlink_evidence(db: Session, assessment_id: str, evidence_id: str, actor: str) -> None:
    actor = _clean(actor, "actor", 128)
    row = db.query(AssessmentEvidence).filter(
        AssessmentEvidence.assessment_id == assessment_id,
        AssessmentEvidence.evidence_id == evidence_id,
    ).first()
    if row is None:
        raise LookupError("Assessment evidence relationship not found.")
    db.delete(row)
    audit(db, "assessment_evidence_unlinked", username=actor,
          detail={"assessment_id": assessment_id, "evidence_id": evidence_id})
    db.commit()
    write_changelog("assessment_evidence_unlinked", "compliance-dashboard",
                    f"Evidence {evidence_id} was unlinked from assessment {assessment_id}.",
                    {"assessment_id": assessment_id, "evidence_id": evidence_id, "actor_username": actor})


def active_assessment_evidence_ids(db: Session) -> set[str]:
    return {
        evidence_id for (evidence_id,) in (
            db.query(AssessmentEvidence.evidence_id)
            .join(Assessment, Assessment.assessment_id == AssessmentEvidence.assessment_id)
            .filter(Assessment.status.in_(ACTIVE_ASSESSMENT_STATUSES))
            .distinct().all()
        )
    }
