from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Evidence
from app.services.evidence_finding_analyzer import analyze_all_evidence, analyze_evidence_record

router = APIRouter()


@router.post("/analyze")
def analyze_evidence(db: Session = Depends(get_db)):
    return analyze_all_evidence(db)


@router.post("/analyze/{evidence_id}")
def analyze_single_evidence(evidence_id: str, db: Session = Depends(get_db)):
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()

    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    created = analyze_evidence_record(db, evidence)
    db.commit()

    return {
        "evidence_id": evidence_id,
        "created_findings_count": len(created),
        "created_findings": [
            {
                "finding_id": f.finding_id,
                "asset_id": f.asset_id,
                "severity": f.severity,
                "control_id": f.control_id,
                "title": f.title,
            }
            for f in created
        ],
    }
