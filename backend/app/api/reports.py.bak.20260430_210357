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

    evidence = [
        e for e in db.query(Evidence).all()
        if e.frameworks and e.frameworks.get(framework)
    ]

    findings = [
        f for f in db.query(Finding).all()
        if (
            f.framework_mappings and f.framework_mappings.get(framework)
        ) or (
            f.affected_frameworks and framework in f.affected_frameworks
        )
    ]

    c = canvas.Canvas(str(path), pagesize=letter)
    width, height = letter
    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, f"{framework_label(framework)} Readiness Report")
    y -= 30

    c.setFont("Helvetica", 11)
    lines = [
        f"Readiness Score: {score.get('readiness_score', 0)}%",
        f"Status: {score.get('status', 'unknown')}",
        f"Total Requirements: {score.get('summary', {}).get('total_requirements', 0)}",
        f"Requirements With Evidence: {score.get('summary', {}).get('requirements_with_evidence', 0)}",
        f"Requirements With Failed Collectors: {score.get('summary', {}).get('requirements_with_failed_collectors', 0)}",
        f"Requirements With Open Findings: {score.get('summary', {}).get('requirements_with_open_findings', 0)}",
    ]

    for line in lines:
        c.drawString(50, y, line)
        y -= 20

    y -= 20
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Weighted Requirements")
    y -= 20
    c.setFont("Helvetica", 9)

    for req in score.get("requirements", []):
        if y < 90:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 9)

        c.drawString(
            50,
            y,
            f"{req.get('requirement')} | weight={req.get('weight')} | score={req.get('score')} | evidence={len(req.get('matched_evidence', []))} | failed={len(req.get('failed_evidence', []))} | findings={len(req.get('open_findings', []))}"
        )
        y -= 14

    y -= 20
    if y < 120:
        c.showPage()
        y = height - 50

    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Evidence")
    y -= 20
    c.setFont("Helvetica", 9)

    for ev in evidence[:50]:
        if y < 80:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 9)

        c.drawString(
            50,
            y,
            f"{ev.evidence_id} | {ev.asset_id} | {ev.control_id} | {ev.collector or ev.source} | validated={ev.validated}"
        )
        y -= 14

    y -= 20
    if y < 120:
        c.showPage()
        y = height - 50

    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Findings")
    y -= 20
    c.setFont("Helvetica", 9)

    for f in findings[:50]:
        if y < 80:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 9)

        c.drawString(
            50,
            y,
            f"{f.finding_id} | {f.asset_id} | {f.severity} | {f.control_id} | {f.status}"
        )
        y -= 14

    c.save()

    return FileResponse(
        path=str(path),
        filename=path.name,
        media_type="application/pdf",
    )
