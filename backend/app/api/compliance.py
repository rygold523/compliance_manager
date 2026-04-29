from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import Evidence, Finding
from app.services.compliance import FRAMEWORKS, framework_label

router = APIRouter()

REQUIRED_CONTROLS = {fw: ["AC-01","AC-02","VM-01","SI-01","CM-01","NS-01","EN-01","IR-01","CP-01"] for fw in FRAMEWORKS}

def calculate_score(framework: str, db: Session) -> dict:
    required = REQUIRED_CONTROLS[framework]
    evidence = db.query(Evidence).all()
    findings = db.query(Finding).all()

    controls_with_evidence = set()
    for ev in evidence:
        if ev.validated and ev.frameworks and ev.frameworks.get(framework) and ev.control_id:
            controls_with_evidence.add(ev.control_id)

    open_high_critical = [
        f for f in findings
        if f.status == "open" and f.severity.lower() in ["critical", "high"] and f.framework_mappings and f.framework_mappings.get(framework)
    ]

    missing_controls = [c for c in required if c not in controls_with_evidence]
    evidence_score = (len(controls_with_evidence) / len(required)) * 100 if required else 0
    score = max(0, round(evidence_score - min(len(open_high_critical) * 7, 35) - min(len(missing_controls) * 3, 30), 2))
    return {
        "framework": framework,
        "label": framework_label(framework),
        "readiness_score": score,
        "total_required_controls": len(required),
        "controls_with_valid_evidence": sorted(list(controls_with_evidence)),
        "missing_controls": missing_controls,
        "open_high_critical_findings": len(open_high_critical),
        "status": "strong_readiness" if score >= 90 else "moderate_readiness" if score >= 75 else "at_risk" if score >= 50 else "not_ready",
    }

@router.get("/score")
def all_scores(db: Session = Depends(get_db)):
    return {fw: calculate_score(fw, db) for fw in FRAMEWORKS}

@router.get("/score/{framework}")
def framework_score(framework: str, db: Session = Depends(get_db)):
    return calculate_score(framework, db)

@router.get("/findings/{framework}")
def findings_by_framework(framework: str, db: Session = Depends(get_db)):
    return [f for f in db.query(Finding).all() if f.framework_mappings and f.framework_mappings.get(framework)]

@router.get("/evidence/{framework}")
def evidence_by_framework(framework: str, db: Session = Depends(get_db)):
    return [e for e in db.query(Evidence).all() if e.frameworks and e.frameworks.get(framework)]
