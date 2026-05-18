#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
PDF_ROUTER="$REPO_DIR/backend/app/api/report_pdf.py"

cd "$REPO_DIR"

cp "$PDF_ROUTER" "${PDF_ROUTER}.bak.stripcss.$(date +%Y%m%d_%H%M%S)"

cat > "$PDF_ROUTER" <<'PY'
import re
from html.parser import HTMLParser
from io import BytesIO

import requests
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/api/reports", tags=["report-pdf"])


class CleanReportTextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.current = ""
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        if tag in {"style", "script", "head", "title"}:
            self.skip_depth += 1
            return

        if self.skip_depth:
            return

        if tag in {"h1", "h2", "h3", "p", "tr", "div"}:
            self._flush()
        elif tag in {"td", "th"}:
            self.current += " | "
        elif tag == "li":
            self.current += "- "

    def handle_endtag(self, tag):
        tag = tag.lower()

        if tag in {"style", "script", "head", "title"} and self.skip_depth:
            self.skip_depth -= 1
            return

        if self.skip_depth:
            return

        if tag in {"h1", "h2", "h3", "p", "tr", "div", "li"}:
            self._flush()

    def handle_data(self, data):
        if self.skip_depth:
            return

        text = " ".join(data.split())
        if text:
            self.current += text + " "

    def _flush(self):
        value = self.current.strip(" |")
        value = re.sub(r"\s+", " ", value).strip()

        if value:
            self.parts.append(value)

        self.current = ""

    def get_text_lines(self):
        self._flush()
        return self.parts


def _clean_html(html: str) -> str:
    html = re.sub(r"(?is)<head.*?>.*?</head>", "", html)
    html = re.sub(r"(?is)<style.*?>.*?</style>", "", html)
    html = re.sub(r"(?is)<script.*?>.*?</script>", "", html)
    html = re.sub(r"(?is)<!doctype.*?>", "", html)
    return html


@router.get("/{framework}/pdf")
def download_report_pdf(framework: str, request: Request):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

    base_url = str(request.base_url).rstrip("/")
    source_url = f"{base_url}/api/reports/{framework}"

    html_response = requests.get(source_url, timeout=30)
    html_response.raise_for_status()

    cleaned_html = _clean_html(html_response.text)

    parser = CleanReportTextParser()
    parser.feed(cleaned_html)
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
        safe_line = (
            line.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
        )

        lower = line.lower()

        if lower.startswith(f"{framework.lower()} compliance traceability report"):
            continue

        if lower.startswith(f"{framework.lower()} requirement"):
            story.append(Spacer(1, 10))
            story.append(Paragraph(safe_line, styles["Heading2"]))
        elif lower.startswith("status:"):
            story.append(Paragraph(safe_line, styles["Heading4"]))
        else:
            story.append(Paragraph(safe_line, styles["BodyText"]))

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

echo "[+] PDF report CSS stripping fix applied."
