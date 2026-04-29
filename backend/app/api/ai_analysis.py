from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import Finding
from app.services.finding_analyzer import analyze_finding_with_ai

router = APIRouter()

@router.post("/findings/{finding_id}/analyze")
def analyze_existing_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.finding_id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return analyze_finding_with_ai(finding.raw or {}, {"control_id": finding.control_id, "framework_mappings": finding.framework_mappings})
