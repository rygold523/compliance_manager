#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
cd "$REPO_DIR"

echo "[+] Adding safe PDF report download endpoint..."

REQ="backend/requirements.txt"
MAIN="backend/app/main.py"
FRONTEND="frontend/src/main.jsx"
PDF_ROUTER="backend/app/api/report_pdf.py"

cp "$REQ" "${REQ}.bak.pdfsafe.$(date +%Y%m%d_%H%M%S)"
cp "$MAIN" "${MAIN}.bak.pdfsafe.$(date +%Y%m%d_%H%M%S)"
cp "$FRONTEND" "${FRONTEND}.bak.pdfsafe.$(date +%Y%m%d_%H%M%S)"

if ! grep -qi '^reportlab' "$REQ"; then
  echo "reportlab" >> "$REQ"
fi

cat > "$PDF_ROUTER" <<'PY'
from html.parser import HTMLParser
from io import BytesIO

import requests
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse


router = APIRouter(prefix="/api/reports", tags=["report-pdf"])


class ReportTextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.current = ""

    def handle_starttag(self, tag, attrs):
        if tag in {"h1", "h2", "h3", "p", "tr"}:
            self._flush()
        elif tag in {"td", "th"}:
            self.current += " | "

    def handle_endtag(self, tag):
        if tag in {"h1", "h2", "h3", "p", "tr"}:
            self._flush()

    def handle_data(self, data):
        text = " ".join(data.split())
        if text:
            self.current += text + " "

    def _flush(self):
        value = self.current.strip(" |")
        if value:
            self.parts.append(value)
        self.current = ""

    def get_text_lines(self):
        self._flush()
        return self.parts


@router.get("/{framework}/pdf")
def download_report_pdf(framework: str, request: Request):
    """
    Generates a basic PDF from the existing HTML traceability report.

    This avoids changing the existing report generation logic.
    If PDF generation fails, only this endpoint is affected.
    """

    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

    base_url = str(request.base_url).rstrip("/")
    source_url = f"{base_url}/api/reports/{framework}"

    html_response = requests.get(source_url, timeout=30)
    html_response.raise_for_status()

    parser = ReportTextParser()
    parser.feed(html_response.text)
    lines = parser.get_text_lines()

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(f"{framework.upper()} Compliance Traceability Report", styles["Title"]))
    story.append(Spacer(1, 12))

    for line in lines:
        if line.lower().startswith(f"{framework.lower()} requirement"):
            story.append(Spacer(1, 10))
            story.append(Paragraph(line, styles["Heading2"]))
        elif line.lower().startswith("status:"):
            story.append(Paragraph(line, styles["Heading4"]))
        else:
            story.append(Paragraph(line, styles["BodyText"]))

        story.append(Spacer(1, 6))

    doc.build(story)
    buffer.seek(0)

    filename = f"{framework}_compliance_traceability_report.pdf"

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
PY

python3 <<'PY'
from pathlib import Path

path = Path("backend/app/main.py")
content = path.read_text()

import_line = "from app.api.report_pdf import router as report_pdf_router"
router_line = "app.include_router(report_pdf_router)"

if import_line not in content:
    lines = content.splitlines()
    insert_at = 0
    for i, line in enumerate(lines):
        if line.startswith("from app.api."):
            insert_at = i + 1
    lines.insert(insert_at, import_line)
    content = "\n".join(lines)

if router_line not in content:
    content += f"\n{router_line}\n"

path.write_text(content)
print("[+] PDF router wired.")
PY

python3 <<'PY'
from pathlib import Path

path = Path("frontend/src/main.jsx")
content = path.read_text()

zip_link = '<a href={`${API}/api/reports/${r.framework}/package`} target="_blank">Download ZIP</a>'

pdf_link = '''<a href={`${API}/api/reports/${r.framework}/package`} target="_blank">Download ZIP</a>
                    {' '}
                    <a href={`${API}/api/reports/${r.framework}/pdf`} target="_blank">Download PDF</a>'''

if "Download PDF" not in content:
    if zip_link not in content:
        raise SystemExit("ERROR: Could not locate Download ZIP link.")
    content = content.replace(zip_link, pdf_link)

path.write_text(content)
print("[+] Frontend PDF link added.")
PY

echo "[+] Safe PDF report download support added."
