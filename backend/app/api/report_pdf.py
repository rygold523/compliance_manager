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
