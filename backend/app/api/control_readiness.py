from fastapi import APIRouter
from pathlib import Path
from collections import defaultdict
import json

from app.services.control_catalog import list_controls, framework_mappings_for_controls

router = APIRouter(prefix="/api/compliance/control-readiness", tags=["control-readiness"])

POLICIES_DB = Path("/var/lib/ai-vulnerability-management/policies/policies.json")


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


def load_policies():
    if not POLICIES_DB.exists():
        return []

    try:
        return json.loads(POLICIES_DB.read_text())
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

        if key not in latest:
            latest[key] = row
            continue

        old_ts = latest[key].get("created_at") or latest[key].get("updated_at") or latest[key].get("collected_at") or ""
        if ts > old_ts:
            latest[key] = row

    return latest


def build_policy_index(policies):
    documented_controls = defaultdict(list)

    for policy in policies:
        for control_id in policy.get("mapped_controls", []) or []:
            documented_controls[control_id].append({
                "policy_id": policy.get("policy_id"),
                "filename": policy.get("filename"),
                "scope": policy.get("scope"),
                "updated_at": policy.get("updated_at"),
            })

    return documented_controls


def build_evidence_index(evidence):
    validated_controls = defaultdict(list)
    latest_evidence = latest_by_key(evidence, ["asset_id", "collector"])

    for ev in latest_evidence.values():
        if not normalize_bool(ev.get("validated")):
            continue

        control_id = ev.get("control_id")
        if not control_id:
            continue

        validated_controls[control_id].append({
            "evidence_id": ev.get("evidence_id"),
            "asset_id": ev.get("asset_id"),
            "collector": ev.get("collector"),
            "created_at": ev.get("created_at"),
        })

    return validated_controls


def score_control(has_policy, has_validated_evidence):
    if has_validated_evidence:
        return 100

    if has_policy:
        return 50

    return 0


@router.get("/")
def get_control_readiness():
    controls = list_controls()
    policies = load_policies()
    evidence = get_db_rows("Evidence")

    documented_controls = build_policy_index(policies)
    validated_controls = build_evidence_index(evidence)

    readiness = []

    for control in controls:
        control_id = control.get("control_id")
        policy_refs = documented_controls.get(control_id, [])
        evidence_refs = validated_controls.get(control_id, [])

        has_policy = len(policy_refs) > 0
        has_evidence = len(evidence_refs) > 0

        if has_evidence:
            status = "validated"
        elif has_policy:
            status = "documented"
        else:
            status = "missing"

        readiness.append({
            "control_id": control_id,
            "title": control.get("title"),
            "domain": control.get("domain"),
            "status": status,
            "score": score_control(has_policy, has_evidence),
            "policy_count": len(policy_refs),
            "evidence_count": len(evidence_refs),
            "policies": policy_refs,
            "evidence": evidence_refs,
            "framework_mappings": control.get("framework_mappings") or {},
        })

    # Framework scoring must be framework-specific.
    # Do not average the same global control list for every framework.
    # Instead:
    #   1. Expand each control into its mapped framework requirements.
    #   2. Score each framework requirement based on mapped control coverage.
    #   3. Average requirement scores per framework.
    framework_requirements = defaultdict(lambda: defaultdict(list))

    for item in readiness:
        mappings = item.get("framework_mappings") or {}

        for framework, requirements in mappings.items():
            if not requirements:
                framework_requirements[framework]["UNMAPPED"].append(item["score"])
                continue

            for requirement in requirements:
                framework_requirements[framework][requirement].append(item["score"])

    framework_scores = {}

    for framework, requirements in framework_requirements.items():
        requirement_scores = []

        for requirement, scores in requirements.items():
            if not scores:
                continue

            # Multiple controls can support one framework requirement.
            # Use the strongest supporting control score for that requirement.
            requirement_scores.append(max(scores))

        score = round(sum(requirement_scores) / len(requirement_scores), 2) if requirement_scores else 0

        framework_scores[framework] = {
            "label": framework,
            "readiness_score": score,
            "status": "ready" if score >= 90 else "partial" if score >= 50 else "needs_work",
            "control_count": len(requirement_scores),
            "requirement_count": len(requirement_scores),
        }

    summary = {
        "total_controls": len(readiness),
        "validated": len([item for item in readiness if item["status"] == "validated"]),
        "documented": len([item for item in readiness if item["status"] == "documented"]),
        "missing": len([item for item in readiness if item["status"] == "missing"]),
    }

    return {
        "summary": summary,
        "framework_scores": framework_scores,
        "controls": readiness,
    }
