from collections import defaultdict
from pathlib import Path
import json

from app.services.control_catalog import list_controls
from app.services.environment_validation import environment_validations

POLICIES_DB = Path("/var/lib/ai-vulnerability-management/policies/policies.json")
DOCUMENTS_DB = Path("/var/lib/ai-vulnerability-management/documents/documents.json")


FRAMEWORK_STRICTNESS = {
    "pci_dss": "strict",
    "soc2": "moderate",
    "nist_800_53": "moderate",
    "iso_27001": "moderate",
    "iso_27002": "moderate",
}


HIGH_EVIDENCE_REQUIRED_CONTROLS = {
    "AC-02",
    "AC-04",
    "NS-01",
    "NS-02",
    "SI-01",
    "SI-03",
    "SI-05",
    "VM-01",
    "VM-02",
    "CP-05",
    "SD-04",
}


DOCUMENTATION_ACCEPTABLE_CONTROLS = {
    "AC-07",
    "AM-01",
    "AM-02",
    "AM-03",
    "AM-05",
    "CM-02",
    "CM-04",
    "CP-01",
    "CP-02",
    "CP-03",
    "CP-04",
    "IR-01",
    "IR-02",
    "IR-03",
    "IR-04",
    "IR-05",
    "NS-02",
    "RM-01",
    "SD-01",
    "SD-02",
    "SI-04",
    "VM-04",
    "VM-05",
}


AUDITOR_EXPECTATIONS = {
    "AC": "Auditors will expect access control evidence such as authentication logs, access reviews, privileged access approvals, MFA coverage, and user lifecycle records.",
    "AM": "Auditors will expect asset inventories, ownership records, classification evidence, and evidence that the inventory is maintained.",
    "CM": "Auditors will expect configuration baselines, change records, hardening standards, system inventories, and evidence of enforcement or review.",
    "CP": "Auditors will expect backup reports, restoration test evidence, availability monitoring records, and business continuity documentation.",
    "IR": "Auditors will expect incident response procedures, escalation records, investigation artifacts, and post-incident review documentation.",
    "NS": "Auditors will expect firewall rules, segmentation evidence, network exposure reviews, and documented approval for exposed services.",
    "SI": "Auditors will expect centralized logging, SIEM or monitoring validation, alert review evidence, time synchronization, and event response records.",
    "VM": "Auditors will expect vulnerability scans, patch records, remediation tracking, ASV reports where applicable, and dependency vulnerability evidence.",
    "SD": "Auditors will expect SDLC procedures, code review evidence, CI/CD controls, deployment approvals, and secure development records.",
    "EN": "Auditors will expect encryption configuration evidence, certificate inventories, TLS validation, and key management records.",
    "RM": "Auditors will expect risk registers, risk assessment records, treatment plans, and periodic review evidence.",
}


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


def latest_by_key(rows, key_fields):
    latest = {}

    for row in rows:
        key = tuple(row.get(field) for field in key_fields)
        ts = row.get("created_at") or row.get("updated_at") or row.get("collected_at") or ""

        old_ts = ""
        if key in latest:
            old_ts = latest[key].get("created_at") or latest[key].get("updated_at") or latest[key].get("collected_at") or ""

        if key not in latest or ts > old_ts:
            latest[key] = row

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
            })

    return indexed


def index_evidence_by_control(evidence):
    indexed = defaultdict(list)
    latest = latest_by_key(evidence, ["asset_id", "collector"])

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


def index_findings_by_control(findings):
    indexed = defaultdict(list)
    latest = latest_by_key(findings, ["asset_id", "control_id", "title"])

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


def control_prefix(control_id):
    return (control_id or "").split("-")[0]


def framework_controls(framework):
    controls = []

    for control in list_controls():
        mappings = dict(control.get("framework_mappings") or {})

        if "iso_27001" not in mappings and "iso_27002" in mappings:
            mappings["iso_27001"] = mappings["iso_27002"]

        if framework in mappings:
            controls.append(control)

    return controls


def classify_control(framework, control, policies, documents, evidence, findings):
    control_id = control.get("control_id")
    prefix = control_prefix(control_id)

    policy_refs = policies.get(control_id, [])
    document_refs = documents.get(control_id, [])
    evidence_refs = evidence.get(control_id, [])
    finding_refs = findings.get(control_id, [])

    validated_evidence = [item for item in evidence_refs if item.get("validated")]
    invalid_evidence = [item for item in evidence_refs if not item.get("validated")]

    has_policy = len(policy_refs) > 0
    has_document = len(document_refs) > 0
    has_validated_evidence = len(validated_evidence) > 0
    has_open_findings = len(finding_refs) > 0

    strict = FRAMEWORK_STRICTNESS.get(framework, "moderate") == "strict"
    evidence_required = control_id in HIGH_EVIDENCE_REQUIRED_CONTROLS
    documentation_acceptable = control_id in DOCUMENTATION_ACCEPTABLE_CONTROLS

    if has_open_findings and strict:
        risk = "high"
        estimated_outcome = "Likely audit exception or failure"
        issue = "Open findings exist for this control."
        action = "Resolve or formally risk-accept the open findings and attach supporting evidence."
    elif evidence_required and not has_validated_evidence:
        risk = "high" if strict else "moderate"
        estimated_outcome = "Likely audit exception"
        issue = "Control requires operational validation, but no validated evidence is present."
        action = "Collect and attach validated evidence from the relevant collector or system export."
    elif documentation_acceptable and (has_policy or has_document):
        risk = "low"
        estimated_outcome = "Likely acceptable if documentation is current and approved"
        issue = "Control appears document-supported."
        action = "Confirm the mapped policy or document is current, approved, and clearly addresses the control."
    elif not has_policy and not has_document and not has_validated_evidence:
        risk = "high" if strict else "moderate"
        estimated_outcome = "Likely audit gap"
        issue = "No policy, supporting document, or validated evidence is mapped to this control."
        action = "Map an approved policy/document and collect evidence where applicable."
    elif (has_policy or has_document) and not has_validated_evidence:
        risk = "moderate"
        estimated_outcome = "Possible audit exception"
        issue = "Control is documented but lacks operating evidence."
        action = "Add evidence showing the control operated during the audit period."
    elif has_validated_evidence:
        risk = "low"
        estimated_outcome = "Likely defensible"
        issue = "Validated evidence is present."
        action = "Confirm evidence is recent, complete, and tied to the audit period."
    else:
        risk = "moderate"
        estimated_outcome = "Needs review"
        issue = "Control state requires review."
        action = "Review mappings, evidence, and related findings."

    return {
        "framework": framework,
        "control_id": control_id,
        "title": control.get("title"),
        "domain": control.get("domain"),
        "risk": risk,
        "estimated_outcome": estimated_outcome,
        "issue": issue,
        "action": action,
        "priority": "Immediate" if risk == "high" else "Planned" if risk == "moderate" else "Monitor",
        "auditor_expectation": AUDITOR_EXPECTATIONS.get(prefix, "Auditors will expect documented control design and evidence of operating effectiveness."),
        "current_state": {
            "policies": policy_refs,
            "documents": document_refs,
            "validated_evidence": validated_evidence,
            "invalid_evidence": invalid_evidence,
            "open_findings": finding_refs,
        },
    }


def summarize(items):
    total = len(items)
    high = len([item for item in items if item["risk"] == "high"])
    moderate = len([item for item in items if item["risk"] == "moderate"])
    low = len([item for item in items if item["risk"] == "low"])

    if high > 0:
        readiness = "At Risk"
        outcome = "Fail or pass with major exceptions likely"
    elif moderate > 0:
        readiness = "Moderate"
        outcome = "Pass with exceptions possible"
    else:
        readiness = "Strong"
        outcome = "Likely defensible if evidence is current"

    defensible = round((low / total) * 100, 2) if total else 0
    partial = round((moderate / total) * 100, 2) if total else 0
    high_risk = round((high / total) * 100, 2) if total else 0

    return {
        "total_controls_reviewed": total,
        "high_risk": high,
        "moderate_risk": moderate,
        "low_risk": low,
        "fully_defensible_percent": defensible,
        "partially_defensible_percent": partial,
        "high_risk_gap_percent": high_risk,
        "readiness": readiness,
        "estimated_audit_outcome": outcome,
    }


def audit_readiness_for_framework(framework):
    policies = index_artifacts_by_control(load_json(POLICIES_DB), "policy_id")
    documents = index_artifacts_by_control(load_json(DOCUMENTS_DB), "document_id")
    evidence_rows = get_db_rows("Evidence")
    evidence = index_evidence_by_control(evidence_rows)
    findings = index_findings_by_control(get_db_rows("Finding"))

    env_validations = environment_validations(evidence_rows)

    for control_id, validation in env_validations.items():
        evidence[control_id].append({
            "evidence_id": "ENVIRONMENT-VALIDATION",
            "asset_id": "environment",
            "collector": validation.get("supporting_service"),
            "validated": True,
            "created_at": None,
            "validation_reason": validation.get("reason"),
        })

    controls = framework_controls(framework)

    items = [
        classify_control(
            framework=framework,
            control=control,
            policies=policies,
            documents=documents,
            evidence=evidence,
            findings=findings,
        )
        for control in controls
    ]

    risk_order = {"high": 0, "moderate": 1, "low": 2}

    items.sort(key=lambda item: (
        risk_order.get(item["risk"], 9),
        item["control_id"] or "",
    ))

    return {
        "framework": framework,
        "summary": summarize(items),
        "recommendations": items,
    }


def audit_readiness_all():
    frameworks = ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"]

    return {
        "frameworks": [
            audit_readiness_for_framework(framework)
            for framework in frameworks
        ]
    }
