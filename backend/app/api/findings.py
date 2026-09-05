from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Finding
from app.schemas.schemas import FindingImport
from app.services.compliance import (
    affected_frameworks_from_mappings,
)
from app.services.control_mapper import (
    get_framework_mappings,
    map_finding_to_control,
)


router = APIRouter()


def serialize_finding(
    finding: Finding,
    include_raw: bool = True,
) -> dict:
    result = {
        "id": finding.id,
        "finding_id": finding.finding_id,
        "asset_id": finding.asset_id,
        "source": finding.source,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "cve": finding.cve,
        "finding_type": finding.finding_type,
        "control_id": finding.control_id,
        "status": finding.status,
        "risk_score": finding.risk_score,
        "framework_mappings": (
            finding.framework_mappings or {}
        ),
        "affected_frameworks": (
            finding.affected_frameworks or []
        ),
        "created_at": finding.created_at,
    }

    if include_raw:
        result["raw"] = finding.raw or {}

    return result


@router.get("/")
def list_current_findings(
    limit: int = Query(
        default=1000,
        ge=1,
        le=5000,
    ),
    db: Session = Depends(get_db),
):
    logical_type = func.coalesce(
        Finding.finding_type,
        Finding.title,
        Finding.finding_id,
    )

    ranked = (
        db.query(
            Finding.id.label("finding_row_id"),
            func.row_number()
            .over(
                partition_by=(
                    func.coalesce(
                        Finding.asset_id,
                        "unknown",
                    ),
                    logical_type,
                    func.coalesce(
                        Finding.control_id,
                        "unknown",
                    ),
                ),
                order_by=(
                    Finding.created_at.desc(),
                    Finding.id.desc(),
                ),
            )
            .label("row_rank"),
        )
        .filter(Finding.status == "open")
        .subquery()
    )

    records = (
        db.query(Finding)
        .join(
            ranked,
            Finding.id
            == ranked.c.finding_row_id,
        )
        .filter(ranked.c.row_rank == 1)
        .order_by(
            Finding.created_at.desc(),
            Finding.id.desc(),
        )
        .limit(limit)
        .all()
    )

    response = [
        serialize_finding(record)
        for record in records
    ]

    db.rollback()
    return response


@router.get("/history")
def list_findings_history(
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
        db.query(Finding)
        .order_by(Finding.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    response = [
        serialize_finding(record)
        for record in records
    ]

    db.rollback()
    return response


@router.post("/import")
def import_finding(
    payload: FindingImport,
    db: Session = Depends(get_db),
):
    existing = (
        db.query(Finding)
        .filter(
            Finding.finding_id
            == payload.finding_id
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Finding already exists",
        )

    control_id = map_finding_to_control(
        payload.finding_type,
        payload.title,
        payload.cve,
    )
    mappings = get_framework_mappings(
        control_id
    )

    score = {
        "critical": 100,
        "high": 80,
        "medium": 50,
        "low": 25,
        "informational": 5,
    }.get(
        payload.severity.lower(),
        0,
    )

    finding = Finding(
        **payload.model_dump(),
        control_id=control_id,
        framework_mappings=mappings,
        affected_frameworks=(
            affected_frameworks_from_mappings(
                mappings
            )
        ),
        risk_score=score,
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return serialize_finding(finding)


@router.get("/{finding_id}")
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
):
    finding = (
        db.query(Finding)
        .filter(
            Finding.finding_id
            == finding_id
        )
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    response = serialize_finding(finding)
    db.rollback()

    return response
