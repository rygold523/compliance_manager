#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
cd "$REPO_DIR"

PDF_ROUTER="backend/app/api/report_pdf.py"
REQ="backend/requirements.txt"
DOCKERFILE="backend/Dockerfile"

cp "$PDF_ROUTER" "${PDF_ROUTER}.bak.browserpdf.$(date +%Y%m%d_%H%M%S)"
cp "$REQ" "${REQ}.bak.browserpdf.$(date +%Y%m%d_%H%M%S)"
cp "$DOCKERFILE" "${DOCKERFILE}.bak.browserpdf.$(date +%Y%m%d_%H%M%S)"

grep -qi '^playwright' "$REQ" || echo "playwright" >> "$REQ"

cat > "$PDF_ROUTER" <<'PY'
from fastapi import APIRouter, Request
from fastapi.responses import Response
from playwright.sync_api import sync_playwright

router = APIRouter(prefix="/api/reports", tags=["report-pdf"])


@router.get("/{framework}/pdf")
def download_report_pdf(framework: str, request: Request):
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

    filename = f"{framework}_compliance_traceability_report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )
PY

python3 <<'PY'
from pathlib import Path

path = Path("backend/Dockerfile")
content = path.read_text()

if "playwright install --with-deps chromium" not in content:
    content += """

# Browser support for HTML-to-PDF report rendering
RUN python -m playwright install --with-deps chromium
"""

path.write_text(content)
print("[+] Backend Dockerfile updated for Playwright Chromium.")
PY

echo "[+] Browser-rendered PDF endpoint installed."
