from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.core.database import get_db
from app.models.models import Assessment, AssessmentEvidence
from app.services import assessment_evidence as service


router = APIRouter(prefix="/api/assessments", tags=["Assessments"])


class AssessmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    owner: str = Field(min_length=1, max_length=255)
    framework: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=8000)
    starts_at: datetime | None = None
    ends_at: datetime | None = None


class StatusUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=32)


class EvidenceLinkCreate(BaseModel):
    evidence_id: str = Field(min_length=1, max_length=128)
    rationale: str | None = Field(default=None, max_length=4000)


def _detail(db: Session, row: Assessment) -> dict:
    evidence_ids = [
        value for (value,) in db.query(AssessmentEvidence.evidence_id)
        .filter(AssessmentEvidence.assessment_id == row.assessment_id)
        .order_by(AssessmentEvidence.evidence_id.asc()).all()
    ]
    return service.serialize_assessment(row, evidence_ids)


@router.get("")
def list_assessments(
    assessment_status: str | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
    _user=Depends(require_roles("admin", "auditor")),
):
    query = db.query(Assessment)
    if assessment_status:
        query = query.filter(Assessment.status == assessment_status.strip().lower())
    rows = query.order_by(Assessment.created_at.desc(), Assessment.id.desc()).all()
    return [_detail(db, row) for row in rows]


@router.get("/{assessment_id}")
def get_assessment(
    assessment_id: str,
    db: Session = Depends(get_db),
    _user=Depends(require_roles("admin", "auditor")),
):
    row = db.query(Assessment).filter(Assessment.assessment_id == assessment_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return _detail(db, row)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_assessment(
    payload: AssessmentCreate,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    try:
        row = service.create_assessment(db, actor=admin.username, **payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _detail(db, row)


@router.patch("/{assessment_id}/status")
def update_assessment_status(
    assessment_id: str,
    payload: StatusUpdate,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    try:
        row = service.update_status(db, assessment_id, payload.status, admin.username)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _detail(db, row)


@router.post("/{assessment_id}/evidence", status_code=status.HTTP_201_CREATED)
def link_assessment_evidence(
    assessment_id: str,
    payload: EvidenceLinkCreate,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    try:
        service.link_evidence(db, assessment_id, payload.evidence_id, admin.username, payload.rationale)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    row = db.query(Assessment).filter(Assessment.assessment_id == assessment_id).one()
    return _detail(db, row)


@router.delete("/{assessment_id}/evidence/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
def unlink_assessment_evidence(
    assessment_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    try:
        service.unlink_evidence(db, assessment_id, evidence_id, admin.username)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return None
