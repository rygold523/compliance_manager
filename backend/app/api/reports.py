from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone
import html
import json
import re

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

            has_policy = bool(policy_refs)
            has_document = bool(document_refs)
            has_validated_evidence = bool(validated_evidence)

            score_value, status_key = control_score(
                control_id,
                has_policy=has_policy,
                has_document=has_document,
                has_validated_evidence=has_validated_evidence,
            )

            control_status = control_status_label(status_key)

            if score_value == 100:
                requirement_has_valid_evidence = True
            elif score_value == 50:
                requirement_has_documentation = True
            else:
                requirement_has_gap = True

            control_rows.append({
                "control": control,
                "status": control_status,
                "score": score_value,
                "policies": policy_refs,
                "documents": document_refs,
                "validated_evidence": validated_evidence,
                "invalid_evidence": invalid_evidence,
                "findings": finding_refs,
            })

        control_scores = [item.get("score", 0) for item in control_rows]

        if control_scores:
            score = max(control_scores)
        else:
            score = 0

        if score == 100:
            if any(item.get("status") == "Validated" for item in control_rows):
                requirement_status = "Satisfied by Validated Evidence"
            else:
                requirement_status = "Satisfied by Documentation"
        elif score == 50:
            requirement_status = "Documented / Needs Evidence"
        else:
            requirement_status = "Missing"

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

from fastapi.responses import FileResponse
from zipfile import ZipFile, ZIP_DEFLATED
import tempfile
import os
import shutil

from app.services.control_scoring import control_score, control_status_label

EVIDENCE_DIRS = [
    Path("/app/evidence"),
    Path("/var/lib/ai-vulnerability-management/evidence"),
]

POLICY_FILES_DIR = Path("/var/lib/ai-vulnerability-management/policies/files")
DOCUMENT_FILES_DIR = Path("/var/lib/ai-vulnerability-management/documents/files")


def find_evidence_file(evidence_id):
    if not evidence_id:
        return None

    for base in EVIDENCE_DIRS:
        if not base.exists():
            continue

        matches = list(base.rglob(f"{evidence_id}.json"))
        if matches:
            return matches[0]

        matches = list(base.rglob(f"*{evidence_id}*.json"))
        if matches:
            return matches[0]

    return None


def safe_zip_name(value):
    value = str(value or "unknown")
    return re.sub(r"[^A-Za-z0-9._/-]", "_", value)


def collect_report_artifacts(framework):
    framework = normalize_framework(framework)
    rows = build_requirement_rows(framework)

    policies = load_json(POLICIES_DB)
    documents = load_json(DOCUMENTS_DB)
    evidence = get_db_rows("Evidence")

    policy_by_id = {p.get("policy_id"): p for p in policies}
    document_by_id = {d.get("document_id"): d for d in documents}
    evidence_by_id = {e.get("evidence_id"): e for e in evidence}

    policy_ids = set()
    document_ids = set()
    evidence_ids = set()

    manifest = {
        "framework": framework,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "requirements": [],
    }

    for row in rows:
        requirement_entry = {
            "requirement": row["requirement"],
            "status": row["status"],
            "score": row["score"],
            "controls": [],
        }

        for control_row in row["controls"]:
            control = control_row["control"]
            control_entry = {
                "control_id": control.get("control_id"),
                "title": control.get("title"),
                "status": control_row["status"],
                "policies": [],
                "documents": [],
                "evidence": [],
                "findings": control_row.get("findings", []),
            }

            for policy in control_row.get("policies", []):
                pid = policy.get("id")
                if pid:
                    policy_ids.add(pid)
                    control_entry["policies"].append(pid)

            for document in control_row.get("documents", []):
                did = document.get("id")
                if did:
                    document_ids.add(did)
                    control_entry["documents"].append(did)

            for ev in control_row.get("validated_evidence", []):
                eid = ev.get("evidence_id")
                if eid:
                    evidence_ids.add(eid)
                    control_entry["evidence"].append(eid)

            requirement_entry["controls"].append(control_entry)

        manifest["requirements"].append(requirement_entry)

    return {
        "manifest": manifest,
        "policies": [policy_by_id[pid] for pid in sorted(policy_ids) if pid in policy_by_id],
        "documents": [document_by_id[did] for did in sorted(document_ids) if did in document_by_id],
        "evidence": [evidence_by_id[eid] for eid in sorted(evidence_ids) if eid in evidence_by_id],
    }


@router.get("/{framework}/package")
def download_report_package(framework: str):
    framework = normalize_framework(framework)
    artifacts = collect_report_artifacts(framework)

    tmpdir = tempfile.mkdtemp(prefix=f"{framework}_evidence_package_")
    zip_path = Path(tmpdir) / f"{framework}_evidence_package.zip"

    try:
        with ZipFile(zip_path, "w", ZIP_DEFLATED) as z:
            z.writestr(
                "manifest.json",
                json.dumps(artifacts["manifest"], indent=2, sort_keys=True),
            )

            for policy in artifacts["policies"]:
                stored = policy.get("stored_filename")
                source = POLICY_FILES_DIR / stored if stored else None

                if source and source.exists():
                    z.write(
                        source,
                        f"policies/{safe_zip_name(policy.get('policy_id'))}_{safe_zip_name(policy.get('filename'))}",
                    )
                else:
                    z.writestr(
                        f"policies/MISSING_{safe_zip_name(policy.get('policy_id'))}.txt",
                        json.dumps(policy, indent=2, sort_keys=True),
                    )

            for document in artifacts["documents"]:
                stored = document.get("stored_filename")
                source = DOCUMENT_FILES_DIR / stored if stored else None

                if source and source.exists():
                    z.write(
                        source,
                        f"documents/{safe_zip_name(document.get('document_id'))}_{safe_zip_name(document.get('filename'))}",
                    )
                else:
                    z.writestr(
                        f"documents/MISSING_{safe_zip_name(document.get('document_id'))}.txt",
                        json.dumps(document, indent=2, sort_keys=True),
                    )

            for ev in artifacts["evidence"]:
                source = find_evidence_file(ev.get("evidence_id"))

                if source and source.exists():
                    z.write(
                        source,
                        f"evidence/{safe_zip_name(ev.get('asset_id'))}/{safe_zip_name(ev.get('collector'))}/{safe_zip_name(source.name)}",
                    )
                else:
                    z.writestr(
                        f"evidence/MISSING_{safe_zip_name(ev.get('evidence_id'))}.json",
                        json.dumps(ev, indent=2, sort_keys=True),
                    )

        return FileResponse(
            zip_path,
            filename=f"{framework}_evidence_package.zip",
            media_type="application/zip",
        )
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise
