from fastapi import APIRouter, Request
from fastapi.responses import Response
from playwright.sync_api import sync_playwright

from app.api.reports import collect_report_artifacts, normalize_framework
from app.core.database import SessionLocal
from app.services.generated_reports import register_report

router = APIRouter(prefix="/api/reports", tags=["report-pdf"])


@router.get("/{framework}/pdf")
def download_report_pdf(framework: str, request: Request):
    framework = normalize_framework(framework)
    base_url = str(request.base_url).rstrip("/")
    report_url = f"{base_url}/api/reports/{framework}"

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )

        page = browser.new_page(viewport={"width": 1600, "height": 1200})
        page.goto(report_url, wait_until="networkidle", timeout=60000)

        pdf_bytes = page.pdf(
            format="A4",
            landscape=True,
            print_background=True,
            margin={
                "top": "0.35in",
                "right": "0.35in",
                "bottom": "0.35in",
                "left": "0.35in",
            },
        )

        browser.close()

    artifacts = collect_report_artifacts(framework)
    evidence_ids = [item["evidence_id"] for item in artifacts["evidence"] if item.get("evidence_id")]
    actor = getattr(getattr(request.state, "auth_user", None), "username", "system")
    with SessionLocal() as db:
        report = register_report(
            db, report_type="pdf", framework=framework, actor=actor,
            content=pdf_bytes, extension="pdf", evidence_ids=evidence_ids,
        )

    filename = f"{framework}_compliance_traceability_report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Generated-Report-ID": report.report_id,
        },
    )
