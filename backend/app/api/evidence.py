from pathlib import Path
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Query,
    UploadFile,
)
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.services.path_security import contained_path
from app.core.database import get_db
from app.models import Evidence


router = APIRouter()


def serialize_evidence(
    evidence: Evidence,
) -> dict:
    return {
        "id": evidence.id,
        "evidence_id": evidence.evidence_id,
        "finding_id": evidence.finding_id,
        "asset_id": evidence.asset_id,
        "control_id": evidence.control_id,
        "framework": evidence.framework,
        "filename": evidence.filename,
        "file_path": evidence.file_path,
        "source": evidence.source,
        "description": evidence.description,
        "collector": evidence.collector,
        "evidence_type": evidence.evidence_type,
        "frameworks": evidence.frameworks or {},
        "validated": bool(evidence.validated),
        "created_at": evidence.created_at,
    }


@router.get("/")
def list_current_evidence(
    limit: int = Query(
        default=1000,
        ge=1,
        le=5000,
    ),
    db: Session = Depends(get_db),
):
    logical_collector = func.coalesce(
        Evidence.collector,
        Evidence.evidence_type,
        Evidence.source,
        "unknown",
    )

    ranked = (
        db.query(
            Evidence.id.label("evidence_row_id"),
            func.row_number()
            .over(
                partition_by=(
                    func.coalesce(
                        Evidence.asset_id,
                        "unknown",
                    ),
                    logical_collector,
                    func.coalesce(
                        Evidence.control_id,
                        "unknown",
                    ),
                ),
                order_by=(
                    Evidence.created_at.desc(),
                    Evidence.id.desc(),
                ),
            )
            .label("row_rank"),
        )
        .subquery()
    )

    records = (
        db.query(Evidence)
        .join(
            ranked,
            Evidence.id
            == ranked.c.evidence_row_id,
        )
        .filter(ranked.c.row_rank == 1)
        .order_by(
            Evidence.created_at.desc(),
            Evidence.id.desc(),
        )
        .limit(limit)
        .all()
    )

    response = [
        serialize_evidence(record)
        for record in records
    ]

    db.rollback()
    return response


@router.get("/history")
def list_evidence_history(
    limit: int = Query(
        default=250,
        ge=1,
        le=1000,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    db: Session = Depends(get_db),
):
    records = (
        db.query(Evidence)
        .order_by(Evidence.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    response = [
        serialize_evidence(record)
        for record in records
    ]

    db.rollback()
    return response


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
    evidence_id = (
        f"EV-{uuid4().hex[:12].upper()}"
    )
    safe_name = Path(
        file.filename or "evidence.bin"
    ).name
    try:
        target_dir = contained_path(
            settings.evidence_root,
            asset_id or "manual",
            control_id or "unmapped",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid evidence path.") from exc
    target_dir.mkdir(
        parents=True,
        exist_ok=True,
    )
    target_path = (
        target_dir
        / f"{evidence_id}_{safe_name}"
    )
    target_path.write_bytes(
        await file.read()
    )

    evidence = Evidence(
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

    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    return serialize_evidence(evidence)
