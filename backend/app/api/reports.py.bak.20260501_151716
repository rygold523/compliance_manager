from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone
import html
import json

from app.services.control_catalog import list_controls

router = APIRouter(prefix="/api/reports", tags=["reports"])

POLICIES_DB = Path("/var/lib/ai-vulnerability-management/policies/policies.json")
DOCUMENTS_DB = Path("/var/lib/ai-vulnerability-management/documents/documents.json")

FRAMEWORK_ALIASES = {
    "pci": "pci_dss",
    "pci-dss": "pci_dss",
    "pci_dss": "pci_dss",
    "soc2": "soc2",
    "soc-2": "soc2",
    "nist": "nist_800_53",
    "nist-800-53": "nist_800_53",
    "nist_800_53": "nist_800_53",
    "iso": "iso_27002",
    "iso-27001": "iso_27001",
    "iso_27001": "iso_27001",
    "iso-27002": "iso_27002",
    "iso_27002": "iso_27002",
}


def esc(value):
    if value is None:
        return ""
    return html.escape(str(value))


def load_json(path):
    if not path.exists():
        return []

    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def row_to_dict(row):
    if row is None:
        return {}

    if isinstance(row, dict):
        return row

    if hasattr(row, "__table__"):
        return {column.name: getattr(row, column.name) for column in row.__table__.columns}

    return dict(row)


def get_db_rows(model_name):
    try:
        from app.core.database import SessionLocal
        from app.models import models

        model = getattr(models, model_name, None)
        if model is None:
            return []

        db = SessionLocal()
        try:
            return [row_to_dict(row) for row in db.query(model).all()]
        finally:
            db.close()
    except Exception:
        return []


def normalize_bool(value):
    if value is True:
        return True

    if isinstance(value, str) and value.lower() in ["true", "yes", "1"]:
        return True

    return False


def normalize_framework(framework):
    normalized = FRAMEWORK_ALIASES.get((framework or "").lower())
    if not normalized:
        raise HTTPException(status_code=404, detail=f"Unsupported framework: {framework}")
    return normalized


def latest_evidence_by_asset_collector(evidence):
    latest = {}

    for ev in evidence:
        asset_id = ev.get("asset_id") or "unknown"
        collector = ev.get("collector") or ev.get("source") or "unknown"
        key = f"{asset_id}:{collector}"
        ts = ev.get("created_at") or ev.get("updated_at") or ev.get("collected_at") or ""

        old_ts = ""
        if key in latest:
            old_ts = latest[key].get("created_at") or latest[key].get("updated_at") or latest[key].get("collected_at") or ""

        if key not in latest or ts > old_ts:
            latest[key] = ev

    return latest


def latest_findings_by_asset_control_title(findings):
    latest = {}

    for finding in findings:
        asset_id = finding.get("asset_id") or finding.get("asset") or "unknown"
        control_id = finding.get("control_id") or finding.get("control") or "UNMAPPED"
        title = finding.get("title") or ""
        key = f"{asset_id}:{control_id}:{title.lower()}"
        ts = finding.get("created_at") or finding.get("updated_at") or finding.get("collected_at") or ""

        old_ts = ""
        if key in latest:
            old_ts = latest[key].get("created_at") or latest[key].get("updated_at") or latest[key].get("collected_at") or ""

        if key not in latest or ts > old_ts:
            latest[key] = finding

    return latest


def index_artifacts_by_control(records, id_key):
    indexed = defaultdict(list)

    for record in records:
        for control_id in record.get("mapped_controls", []) or []:
            indexed[control_id].append({
                "id": record.get(id_key),
                "filename": record.get("filename"),
                "scope": record.get("scope"),
                "updated_at": record.get("updated_at"),
                "mapped_frameworks": record.get("mapped_frameworks", {}),
            })

    return indexed


def index_evidence_by_control(evidence):
    indexed = defaultdict(list)

    latest = latest_evidence_by_asset_collector(evidence)

    for ev in latest.values():
        control_id = ev.get("control_id")
        if not control_id:
            continue

        indexed[control_id].append({
            "evidence_id": ev.get("evidence_id"),
            "asset_id": ev.get("asset_id"),
            "collector": ev.get("collector") or ev.get("source"),
            "validated": normalize_bool(ev.get("validated")),
            "created_at": ev.get("created_at"),
        })

    return indexed


def index_open_findings_by_control(findings):
    indexed = defaultdict(list)

    latest = latest_findings_by_asset_control_title(findings)

    for finding in latest.values():
        status = (finding.get("status") or "open").lower()
        if status not in ["open", "active", "new"]:
            continue

        control_id = finding.get("control_id") or finding.get("control")
        if not control_id:
            continue

        indexed[control_id].append({
            "finding_id": finding.get("finding_id"),
            "asset_id": finding.get("asset_id") or finding.get("asset"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "status": finding.get("status"),
        })

    return indexed


def build_requirement_rows(framework):
    controls = list_controls()
    policies = load_json(POLICIES_DB)
    documents = load_json(DOCUMENTS_DB)
    evidence = get_db_rows("Evidence")
    findings = get_db_rows("Finding")

    policies_by_control = index_artifacts_by_control(policies, "policy_id")
    documents_by_control = index_artifacts_by_control(documents, "document_id")
    evidence_by_control = index_evidence_by_control(evidence)
    findings_by_control = index_open_findings_by_control(findings)

    requirements = defaultdict(list)

    for control in controls:
        mappings = dict(control.get("framework_mappings") or {})
        if "iso_27001" not in mappings and "iso_27002" in mappings:
            mappings["iso_27001"] = mappings["iso_27002"]
        refs = mappings.get(framework) or []

        for ref in refs:
            ref = str(ref)
            requirements[ref].append(control)

    rows = []

    for requirement, mapped_controls in sorted(requirements.items(), key=lambda item: str(item[0])):
        control_rows = []

        requirement_has_valid_evidence = False
        requirement_has_documentation = False
        requirement_has_gap = False

        for control in mapped_controls:
            control_id = control.get("control_id")
            policy_refs = policies_by_control.get(control_id, [])
            document_refs = documents_by_control.get(control_id, [])
            evidence_refs = evidence_by_control.get(control_id, [])
            finding_refs = findings_by_control.get(control_id, [])

            validated_evidence = [item for item in evidence_refs if item.get("validated")]
            invalid_evidence = [item for item in evidence_refs if not item.get("validated")]

            has_documentation = bool(policy_refs or document_refs)
            has_validated_evidence = bool(validated_evidence)

            if has_validated_evidence:
                control_status = "Validated"
                requirement_has_valid_evidence = True
            elif has_documentation:
                control_status = "Documented"
                requirement_has_documentation = True
            else:
                control_status = "Missing"
                requirement_has_gap = True

            control_rows.append({
                "control": control,
                "status": control_status,
                "policies": policy_refs,
                "documents": document_refs,
                "validated_evidence": validated_evidence,
                "invalid_evidence": invalid_evidence,
                "findings": finding_refs,
            })

        if requirement_has_valid_evidence:
            requirement_status = "Satisfied by Validated Evidence"
            score = 100
        elif requirement_has_documentation:
            requirement_status = "Documented / Needs Evidence"
            score = 50
        else:
            requirement_status = "Missing"
            score = 0

        if requirement_has_gap and requirement_status != "Missing":
            requirement_status += " with Gaps"

        rows.append({
            "requirement": requirement,
            "status": requirement_status,
            "score": score,
            "controls": control_rows,
        })

    return rows


def render_artifact_list(items, artifact_type):
    if not items:
        return "<span class='muted'>None mapped</span>"

    html_items = []

    for item in items:
        html_items.append(
            f"<li><strong>{esc(item.get('id'))}</strong> — {esc(item.get('filename'))}"
            f"<br><span class='muted'>{esc(item.get('scope'))}</span></li>"
        )

    return f"<ul>{''.join(html_items)}</ul>"


def render_evidence_list(items):
    if not items:
        return "<span class='muted'>No validated evidence</span>"

    html_items = []

    for item in items:
        html_items.append(
            f"<li><strong>{esc(item.get('evidence_id'))}</strong> — "
            f"{esc(item.get('asset_id'))} / {esc(item.get('collector'))}"
            f"<br><span class='muted'>{esc(item.get('created_at'))}</span></li>"
        )

    return f"<ul>{''.join(html_items)}</ul>"


def render_findings_list(items):
    if not items:
        return "<span class='muted'>No open findings</span>"

    html_items = []

    for item in items:
        html_items.append(
            f"<li><strong>{esc(item.get('severity'))}</strong> — {esc(item.get('title'))}"
            f"<br><span class='muted'>{esc(item.get('asset_id'))} / {esc(item.get('finding_id'))}</span></li>"
        )

    return f"<ul>{''.join(html_items)}</ul>"


def status_class(status):
    lower = status.lower()

    if "validated" in lower or "satisfied" in lower:
        return "validated"

    if "documented" in lower:
        return "documented"

    return "missing"


@router.get("/{framework}", response_class=HTMLResponse)
def generate_framework_report(framework: str):
    framework = normalize_framework(framework)
    rows = build_requirement_rows(framework)

    if not rows:
        raise HTTPException(status_code=404, detail=f"No mapped requirements found for {framework}")

    total = len(rows)
    satisfied = len([row for row in rows if row["score"] == 100])
    documented = len([row for row in rows if row["score"] == 50])
    missing = len([row for row in rows if row["score"] == 0])
    score = round(sum(row["score"] for row in rows) / total, 2) if total else 0

    generated_at = datetime.now(timezone.utc).isoformat()

    requirement_sections = []

    for row in rows:
        control_sections = []

        for control_row in row["controls"]:
            control = control_row["control"]

            explanation = (
                f"Control {esc(control.get('control_id'))} supports {esc(framework)} requirement "
                f"{esc(row['requirement'])}. "
            )

            if control_row["validated_evidence"]:
                explanation += "This control is satisfied through validated evidence."
            elif control_row["policies"] or control_row["documents"]:
                explanation += "This control is documented through mapped policies or supporting documents, but still needs validated technical evidence."
            else:
                explanation += "This control currently has no mapped policy, supporting document, or validated evidence."

            control_sections.append(f"""
              <tr>
                <td>
                  <strong>{esc(control.get("control_id"))}</strong><br>
                  {esc(control.get("title"))}<br>
                  <span class="muted">{esc(control.get("domain"))}</span>
                </td>
                <td><span class="pill {status_class(control_row["status"])}">{esc(control_row["status"])}</span></td>
                <td>{render_artifact_list(control_row["policies"], "policy")}</td>
                <td>{render_artifact_list(control_row["documents"], "document")}</td>
                <td>{render_evidence_list(control_row["validated_evidence"])}</td>
                <td>{render_findings_list(control_row["findings"])}</td>
                <td>{explanation}</td>
              </tr>
            """)

        requirement_sections.append(f"""
          <section class="requirement">
            <h2>{esc(framework)} Requirement: {esc(row["requirement"])}</h2>
            <p>
              Status:
              <span class="pill {status_class(row["status"])}">{esc(row["status"])}</span>
              <span class="score">Requirement Score: {row["score"]}%</span>
            </p>

            <table>
              <thead>
                <tr>
                  <th>Mapped Control</th>
                  <th>Status</th>
                  <th>Policies</th>
                  <th>Supporting Documents</th>
                  <th>Validated Evidence</th>
                  <th>Open Findings</th>
                  <th>How Requirement Is Satisfied</th>
                </tr>
              </thead>
              <tbody>
                {''.join(control_sections)}
              </tbody>
            </table>
          </section>
        """)

    html_body = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>{esc(framework)} Compliance Traceability Report</title>
        <style>
          body {{
            font-family: Arial, sans-serif;
            margin: 32px;
            color: #111827;
          }}

          h1 {{
            margin-bottom: 4px;
          }}

          .muted {{
            color: #6b7280;
            font-size: 0.9em;
          }}

          .summary {{
            display: grid;
            grid-template-columns: repeat(5, minmax(140px, 1fr));
            gap: 12px;
            margin: 24px 0;
          }}

          .summary-card {{
            border: 1px solid #d1d5db;
            border-radius: 8px;
            padding: 14px;
            background: #f9fafb;
          }}

          .summary-card strong {{
            display: block;
            font-size: 1.4em;
            margin-top: 4px;
          }}

          table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            table-layout: fixed;
          }}

          th, td {{
            border: 1px solid #d1d5db;
            padding: 8px;
            vertical-align: top;
            word-wrap: break-word;
          }}

          th {{
            background: #f3f4f6;
            text-align: left;
          }}

          .requirement {{
            margin-top: 30px;
            page-break-inside: avoid;
          }}

          .pill {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 999px;
            font-weight: 700;
            border: 1px solid #d1d5db;
          }}

          .validated {{
            background: #dcfce7;
          }}

          .documented {{
            background: #fef9c3;
          }}

          .missing {{
            background: #fee2e2;
          }}

          .score {{
            margin-left: 12px;
            font-weight: 700;
          }}

          ul {{
            padding-left: 18px;
            margin: 0;
          }}

          li {{
            margin-bottom: 8px;
          }}

          @media print {{
            body {{
              margin: 16px;
            }}

            .requirement {{
              page-break-inside: avoid;
            }}
          }}
        </style>
      </head>
      <body>
        <h1>{esc(framework)} Compliance Traceability Report</h1>
        <p class="muted">Generated at {esc(generated_at)}</p>

        <p>
          This report explains how each mapped compliance requirement is satisfied through
          control mappings, uploaded policies, supporting documents, validated evidence, and
          open findings. A requirement is considered satisfied when at least one mapped control
          has validated evidence. A requirement is considered documented when supporting policies
          or documents exist but validated evidence is still missing.
        </p>

        <div class="summary">
          <div class="summary-card">Overall Score<strong>{score}%</strong></div>
          <div class="summary-card">Requirements<strong>{total}</strong></div>
          <div class="summary-card">Satisfied<strong>{satisfied}</strong></div>
          <div class="summary-card">Documented<strong>{documented}</strong></div>
          <div class="summary-card">Missing<strong>{missing}</strong></div>
        </div>

        {''.join(requirement_sections)}
      </body>
    </html>
    """

    return HTMLResponse(content=html_body)
