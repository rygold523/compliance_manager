from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Finding
from app.schemas.schemas import FindingImport
from app.services.control_mapper import map_finding_to_control, get_framework_mappings
from app.services.compliance import affected_frameworks_from_mappings

router = APIRouter()


def finding_state_key(finding: Finding):
    raw = finding.raw or {}

    evidence_id = raw.get("evidence_id")
    if evidence_id and finding.finding_id.startswith("EF-EV-"):
        parts = finding.finding_id.split("-")
        # EF-EV-<ID PARTS>-<TYPE PARTS>
        # More reliable key is asset + type + control.
        return (
            finding.asset_id or "unknown",
            finding.finding_type or finding.title or "unknown",
            finding.control_id or "unknown",
        )

    return (
        finding.asset_id or "unknown",
        finding.finding_type or finding.title or finding.finding_id,
        finding.control_id or "unknown",
    )


def latest_findings_only(records):
    latest = {}

    for finding in records:
        key = finding_state_key(finding)

        if key not in latest or finding.created_at > latest[key].created_at:
            latest[key] = finding

    return sorted(latest.values(), key=lambda x: x.created_at, reverse=True)


@router.get("/")
def list_current_findings(db: Session = Depends(get_db)):
    records = db.query(Finding).filter(Finding.status == "open").all()
    return latest_findings_only(records)


@router.get("/history")
def list_findings_history(db: Session = Depends(get_db)):
    return db.query(Finding).order_by(Finding.id.desc()).all()


@router.post("/import")
def import_finding(payload: FindingImport, db: Session = Depends(get_db)):
    existing = db.query(Finding).filter(Finding.finding_id == payload.finding_id).first()

    if existing:
        raise HTTPException(status_code=409, detail="Finding already exists")

    control_id = map_finding_to_control(payload.finding_type, payload.title, payload.cve)
    mappings = get_framework_mappings(control_id)

    score = {
        "critical": 100,
        "high": 80,
        "medium": 50,
        "low": 25,
        "informational": 5,
    }.get(payload.severity.lower(), 0)

    finding = Finding(
        **payload.model_dump(),
        control_id=control_id,
        framework_mappings=mappings,
        affected_frameworks=affected_frameworks_from_mappings(mappings),
        risk_score=score,
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/{finding_id}")
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.finding_id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding
