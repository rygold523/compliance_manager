from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, UploadFile, File, Form
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models import Evidence

router = APIRouter()


def latest_evidence_only(records):
    latest = {}

    for ev in records:
        key = (
            ev.asset_id or "unknown",
            ev.collector or ev.evidence_type or ev.source or "unknown",
            ev.control_id or "unknown",
        )

        if key not in latest or ev.created_at > latest[key].created_at:
            latest[key] = ev

    return sorted(latest.values(), key=lambda x: x.created_at, reverse=True)


@router.get("/")
def list_current_evidence(db: Session = Depends(get_db)):
    records = db.query(Evidence).all()
    return latest_evidence_only(records)


@router.get("/history")
def list_evidence_history(db: Session = Depends(get_db)):
    return db.query(Evidence).order_by(Evidence.id.desc()).all()


@router.post("/upload")
async def upload_evidence(
    file: UploadFile = File(...),
    source: str = Form(...),
    description: str | None = Form(None),
    finding_id: str | None = Form(None),
    asset_id: str | None = Form(None),
    control_id: str | None = Form(None),
    framework: str | None = Form(None),
    db: Session = Depends(get_db),
):
    evidence_id = f"EV-{uuid4().hex[:12].upper()}"
    safe_name = Path(file.filename or "evidence.bin").name
    target_dir = Path(settings.evidence_root) / (asset_id or "manual") / (control_id or "unmapped")
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / f"{evidence_id}_{safe_name}"
    target_path.write_bytes(await file.read())

    ev = Evidence(
        evidence_id=evidence_id,
        finding_id=finding_id,
        asset_id=asset_id,
        control_id=control_id,
        framework=framework,
        filename=safe_name,
        file_path=str(target_path),
        source=source,
        description=description,
    )

    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev
