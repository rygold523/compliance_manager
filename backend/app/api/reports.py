from pathlib import Path
from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from app.core.database import get_db
from app.models import Evidence, Finding
from app.api.compliance import calculate_score
from app.services.compliance import framework_label

router = APIRouter()

@router.get("/{framework}")
def generate_report(framework: str, db: Session = Depends(get_db)):
    report_dir = Path("/app/evidence/reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"{framework}_readiness_report.pdf"

    score = calculate_score(framework, db)
    evidence = [e for e in db.query(Evidence).all() if e.frameworks and e.frameworks.get(framework)]
    findings = [f for f in db.query(Finding).all() if f.framework_mappings and f.framework_mappings.get(framework)]

    c = canvas.Canvas(str(path), pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, f"{framework_label(framework)} Readiness Report")
    y -= 30
    c.setFont("Helvetica", 11)
    for line in [
        f"Readiness Score: {score['readiness_score']}%",
        f"Status: {score['status']}",
        f"Controls With Valid Evidence: {len(score['controls_with_valid_evidence'])}",
        f"Missing Controls: {len(score['missing_controls'])}",
        f"Open High/Critical Findings: {score['open_high_critical_findings']}",
    ]:
        c.drawString(50, y, line)
        y -= 20

    y -= 20
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Evidence")
    y -= 20
    c.setFont("Helvetica", 9)
    for ev in evidence[:35]:
        if y < 80:
            c.showPage(); y = height - 50; c.setFont("Helvetica", 9)
        c.drawString(50, y, f"{ev.evidence_id} | {ev.asset_id} | {ev.control_id} | {ev.collector} | validated={ev.validated}")
        y -= 14

    y -= 20
    if y < 120:
        c.showPage(); y = height - 50

    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Findings")
    y -= 20
    c.setFont("Helvetica", 9)
    for f in findings[:35]:
        if y < 80:
            c.showPage(); y = height - 50; c.setFont("Helvetica", 9)
        c.drawString(50, y, f"{f.finding_id} | {f.asset_id} | {f.severity} | {f.control_id} | {f.status}")
        y -= 14

    c.save()
    return FileResponse(path=str(path), filename=path.name, media_type="application/pdf")
