from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import MetaData, Table, select

from app.core.database import get_db, engine
from app.models import Evidence, Finding
from app.services.control_catalog_v2 import CONTROL_CATALOG, CONTROL_STATUS_ORDER

router = APIRouter(prefix="/api/control-readiness-v2", tags=["control-readiness-v2"])


def _safe_get(obj, attr, default=None):
    if isinstance(obj, dict):
        return obj.get(attr, default)

    return getattr(obj, attr, default)


def _as_list(value):
    if not value:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    if isinstance(value, set):
        return list(value)

    return [value]


def _record_timestamp(obj):
    for attr in ("collected_at", "created_at", "updated_at", "id"):
        value = getattr(obj, attr, None)
        if value is not None:
            return value
    return ""


def _latest_evidence_records(evidence):
    latest = {}

    for ev in evidence:
        key = (
            _safe_get(ev, "asset_id"),
            _safe_get(ev, "collector"),
            _safe_get(ev, "control_id"),
        )

        if key not in latest or _record_timestamp(ev) > _record_timestamp(latest[key]):
            latest[key] = ev

    return list(latest.values())


def _framework_values(raw, framework):
    if not raw:
        return []

    if isinstance(raw, dict):
        value = raw.get(framework, [])
        return _as_list(value)

    return _as_list(raw)


def _evidence_matches_control(ev, control_id, framework=None):
    if _safe_get(ev, "control_id") == control_id:
        return True

    if framework and _framework_values(_safe_get(ev, "frameworks"), framework):
        return True

    return False


def _collector_set_for_control(evidence, control_id):
    collectors = set()

    for ev in evidence:
        if _evidence_matches_control(ev, control_id):
            collector = _safe_get(ev, "collector") or _safe_get(ev, "evidence_type")
            if collector:
                collectors.add(collector)

    return collectors


def _validated_evidence_for_control(evidence, control_id):
    return [
        ev for ev in evidence
        if _evidence_matches_control(ev, control_id)
        and bool(_safe_get(ev, "validated", False))
    ]


def _failed_evidence_for_control(evidence, control_id):
    return [
        ev for ev in evidence
        if _evidence_matches_control(ev, control_id)
        and not bool(_safe_get(ev, "validated", False))
    ]


def _finding_applies_to_control(finding, control_id):
    if _safe_get(finding, "status") != "open":
        return False

    return _safe_get(finding, "control_id") == control_id


def _table_rows(table_name):
    metadata = MetaData()

    try:
        table = Table(table_name, metadata, autoload_with=engine)
    except Exception:
        return []

    try:
        with engine.connect() as conn:
            rows = conn.execute(select(table)).mappings().all()
            return [dict(row) for row in rows]
    except Exception:
        return []


def _objects_for_model(db, model_name):
    # Legacy compatibility. Current policy/document storage is table-based.
    model_table_map = {
        "Policy": ["evidence_policies", "evidence_policy_requirements"],
        "Document": ["regulatory_documents"],
    }

    rows = []

    for table_name in model_table_map.get(model_name, []):
        rows.extend(_table_rows(table_name))

    return rows

def _object_references_control(obj, control_id):
    direct_attrs = [
        "control_id",
        "control",
        "controls",
        "control_ids",
        "mapped_controls",
        "associated_controls",
        "control_mappings",
        "framework_controls",
    ]

    for attr in direct_attrs:
        value = _safe_get(obj, attr)

        if value == control_id:
            return True

        if control_id in _as_list(value):
            return True

        if isinstance(value, dict):
            if control_id in value.keys():
                return True

            for nested_value in value.values():
                if control_id in _as_list(nested_value):
                    return True

    searchable_attrs = [
        "title",
        "name",
        "description",
        "content",
        "body",
        "text",
        "summary",
        "filename",
        "file_name",
        "document_type",
        "policy_type",
        "raw",
        "metadata",
    ]

    searchable_text = " ".join(
        _normalize_text(_safe_get(obj, attr))
        for attr in searchable_attrs
    ).lower()

    control_id_lower = control_id.lower()

    if control_id_lower in searchable_text:
        return True

    control_keywords = {
        "AC-01": ["mfa", "multi-factor", "multifactor", "authentication"],
        "AC-02": ["identity", "access management", "user account", "account management"],
        "AC-04": ["privileged access", "sudo", "administrator", "admin access"],
        "AC-05": ["provisioning", "user access provisioning", "new user access"],
        "AC-06": ["deprovisioning", "termination", "access removal", "remove access"],
        "AC-07": ["access review", "periodic access", "access recertification"],
        "AM-01": ["asset inventory", "asset management"],
        "AM-02": ["asset owner", "asset ownership", "system owner"],
        "AM-03": ["classification", "data sensitivity", "data classification"],
        "AM-04": ["software inventory", "software asset", "installed software"],
        "CM-01": ["baseline configuration", "secure configuration"],
        "CM-02": ["change management", "configuration change", "change control"],
        "CM-03": ["configuration review", "secure configuration review"],
        "CP-01": ["backup", "recovery", "business continuity", "disaster recovery"],
        "IR-01": ["incident response", "security incident", "incident handling"],
        "NS-01": ["network security", "firewall", "network segmentation"],
        "SD-01": ["secure development", "sdlc", "deployment", "change deployment"],
        "SI-01": ["logging", "monitoring", "audit log", "security monitoring"],
        "VM-01": ["vulnerability", "patch management", "security update"],
    }

    for keyword in control_keywords.get(control_id, []):
        if keyword in searchable_text:
            return True

    return False


def _documentation_evidence_for_control(db, control_id):
    policy_count = _policy_count(db, control_id)
    document_count = _document_count(db, control_id)

    return policy_count, document_count

def _policy_count(db, control_id):
    policies = _objects_for_model(db, "Policy")
    return len([p for p in policies if _object_references_control(p, control_id)])


def _document_count(db, control_id):
    documents = _objects_for_model(db, "Document")
    return len([d for d in documents if _object_references_control(d, control_id)])


def _status_for_control(definition, evidence, findings, policy_count, document_count):
    control_id = definition["control_id"]
    required_collectors = set(definition.get("required_collectors", []))
    documentation_sufficient = bool(definition.get("documentation_sufficient", False))

    validated_evidence = _validated_evidence_for_control(evidence, control_id)
    failed_evidence = _failed_evidence_for_control(evidence, control_id)
    open_findings = [f for f in findings if _finding_applies_to_control(f, control_id)]
    collector_set = _collector_set_for_control(validated_evidence, control_id)

    documented = policy_count > 0 or document_count > 0

    if documentation_sufficient and documented and not required_collectors:
        return "satisfied_by_documentation", 100

    if required_collectors and required_collectors.issubset(collector_set) and not failed_evidence:
        if open_findings:
            return "partially_validated", 70
        return "validated", 100

    if validated_evidence:
        return "partially_validated", 70

    if documented:
        return "documented", 50

    return "missing", 0


@router.get("/")
def control_readiness_v2(db: Session = Depends(get_db)):
    evidence = _latest_evidence_records(db.query(Evidence).all())
    findings = [
        f for f in db.query(Finding).all()
        if _safe_get(f, "status") == "open"
    ]

    results = []

    for control_id, control in CONTROL_CATALOG.items():
        definition = dict(control)
        definition["control_id"] = control_id

        policy_count, document_count = _documentation_evidence_for_control(db, control_id)

        status, score = _status_for_control(
            definition,
            evidence,
            findings,
            policy_count,
            document_count,
        )

        validated_evidence = _validated_evidence_for_control(evidence, control_id)
        failed_evidence = _failed_evidence_for_control(evidence, control_id)
        open_findings = [f for f in findings if _finding_applies_to_control(f, control_id)]

        results.append({
            "control_id": control_id,
            "title": control["title"],
            "domain": control["domain"],
            "frameworks": control["frameworks"],
            "status": status,
            "score": score,
            "policies": policy_count,
            "documents": document_count,
            "evidence": len(validated_evidence),
            "failed_evidence": len(failed_evidence),
            "open_findings": len(open_findings),
            "required_collectors": control.get("required_collectors", []),
            "supporting_collectors": control.get("supporting_collectors", []),
            "documentation_sufficient": control.get("documentation_sufficient", False),
        })

    return {
        "total_controls": len(results),
        "summary": {
            "validated": len([r for r in results if r["status"] == "validated"]),
            "satisfied_by_documentation": len([r for r in results if r["status"] == "satisfied_by_documentation"]),
            "partially_validated": len([r for r in results if r["status"] == "partially_validated"]),
            "documented": len([r for r in results if r["status"] == "documented"]),
            "missing": len([r for r in results if r["status"] == "missing"]),
        },
        "controls": sorted(
            results,
            key=lambda r: (r["domain"], r["control_id"]),
        ),
    }
