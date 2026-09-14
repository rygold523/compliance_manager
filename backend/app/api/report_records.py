from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.core.database import get_db
from app.models.models import GeneratedReport, GeneratedReportEvidence
from app.services import generated_reports as service


router = APIRouter(prefix="/api/report-records", tags=["Generated Reports"])


class ReportStatusUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=32)


def _detail(db: Session, row: GeneratedReport) -> dict:
    evidence_ids = [
        value for (value,) in db.query(GeneratedReportEvidence.evidence_id)
        .filter(GeneratedReportEvidence.report_id == row.report_id)
        .order_by(GeneratedReportEvidence.evidence_id.asc()).all()
    ]
    return service.serialize_report(row, evidence_ids)


@router.get("")
def list_report_records(
    report_status: str | None = Query(default=None, alias="status"),
    framework: str | None = None,
    db: Session = Depends(get_db),
    _user=Depends(require_roles("admin", "auditor")),
):
    query = db.query(GeneratedReport)
    if report_status:
        query = query.filter(GeneratedReport.status == report_status.strip().lower())
    if framework:
        query = query.filter(GeneratedReport.framework == framework.strip().lower())
    rows = query.order_by(GeneratedReport.generated_at.desc(), GeneratedReport.id.desc()).all()
    return [_detail(db, row) for row in rows]


@router.get("/{report_id}")
def get_report_record(
    report_id: str,
    db: Session = Depends(get_db),
    _user=Depends(require_roles("admin", "auditor")),
):
    row = db.query(GeneratedReport).filter(GeneratedReport.report_id == report_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Generated report not found.")
    return _detail(db, row)


@router.patch("/{report_id}/status")
def update_report_status(
    report_id: str,
    payload: ReportStatusUpdate,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    try:
        row = service.update_status(db, report_id, payload.status, admin.username)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _detail(db, row)
