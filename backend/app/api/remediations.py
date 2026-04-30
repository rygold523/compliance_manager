from fastapi import APIRouter
from collections import defaultdict
import re

router = APIRouter(prefix="/api/remediations", tags=["remediations"])


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


def framework_targets(control_id):
    control_id = control_id or ""
    prefix = control_id.split("-")[0] if "-" in control_id else control_id

    known_prefixes = {"AC", "AM", "CM", "CP", "IR", "SI", "VM", "NS", "EN", "SD"}

    if prefix in known_prefixes:
        return ["pci_dss", "soc2", "nist_800_53", "iso_27002"]

    return ["pci_dss", "soc2"]


def normalize_timestamp(row):
    return (
        row.get("created_at")
        or row.get("updated_at")
        or row.get("collected_at")
        or ""
    )


def collector_from_failed_finding(title):
    match = re.search(r"collector failed:\s*(.+)$", title or "", re.I)
    return match.group(1).strip() if match else None


def remediation_for_finding(finding):
    title = finding.get("title") or ""
    severity = finding.get("severity") or "medium"
    control_id = finding.get("control_id") or finding.get("control") or "UNMAPPED"
    asset_id = finding.get("asset_id") or finding.get("asset") or "unknown"

    lower = title.lower()

    if "collector failed" in lower:
        collector = collector_from_failed_finding(title) or "unknown"
        action = f"Fix and rerun the {collector} evidence collector for {asset_id}."
        rationale = "Collector failures prevent compliance validation and reduce evidence confidence."
        priority = "high"
    elif "available package updates" in lower or "updates detected" in lower:
        action = f"Patch available operating system packages on {asset_id}, then rerun package collectors."
        rationale = "Closing missing updates directly improves vulnerability management evidence."
        priority = "high" if severity in ["critical", "high"] else "medium"
    elif "held packages" in lower:
        action = f"Review held packages on {asset_id}; document business justification or release package holds."
        rationale = "Held packages can block vulnerability remediation and patch compliance."
        priority = "medium"
    elif "open ports" in lower or "listening services" in lower:
        action = f"Review exposed ports and listening services on {asset_id}; close or document approved services."
        rationale = "Network exposure findings affect segmentation and firewall control readiness."
        priority = "medium"
    elif "authentication failures" in lower:
        action = f"Review authentication failures on {asset_id}; validate lockout policy, MFA coverage, and suspicious source activity."
        rationale = "Authentication anomalies affect access control monitoring and audit readiness."
        priority = "medium"
    elif "time synchronization" in lower or "time sync" in lower:
        action = f"Validate NTP/time synchronization on {asset_id} and document the approved time source."
        rationale = "Reliable timestamps are required for log integrity and incident investigation."
        priority = "low"
    else:
        action = f"Resolve finding on {asset_id}: {title}"
        rationale = "Closing this finding improves mapped control readiness."
        priority = severity if severity in ["critical", "high", "medium", "low"] else "medium"

    return {
        "asset_id": asset_id,
        "control_id": control_id,
        "severity": severity,
        "priority": priority,
        "title": title,
        "action": action,
        "rationale": rationale,
        "frameworks": framework_targets(control_id),
        "source_finding_id": finding.get("finding_id"),
    }


def latest_evidence_by_asset_collector(evidence):
    latest = {}

    for ev in evidence:
        asset_id = ev.get("asset_id") or "unknown"
        collector = ev.get("collector") or ev.get("source") or "unknown"
        key = f"{asset_id}:{collector}"
        ts = normalize_timestamp(ev)

        if key not in latest or ts > normalize_timestamp(latest[key]):
            latest[key] = ev

    return latest


def latest_findings_by_asset_control_title(findings):
    latest = {}

    for finding in findings:
        asset_id = finding.get("asset_id") or finding.get("asset") or "unknown"
        control_id = finding.get("control_id") or finding.get("control") or "UNMAPPED"
        title = finding.get("title") or ""
        key = f"{asset_id}:{control_id}:{title.lower()}"
        ts = normalize_timestamp(finding)

        if key not in latest or ts > normalize_timestamp(latest[key]):
            latest[key] = finding

    return latest


def evidence_is_valid(ev):
    value = ev.get("validated")

    if value is True:
        return True

    if isinstance(value, str) and value.lower() in ["true", "yes", "1"]:
        return True

    return False


@router.get("/")
def list_remediations():
    findings = get_db_rows("Finding")
    evidence = get_db_rows("Evidence")

    latest_evidence = latest_evidence_by_asset_collector(evidence)
    latest_findings = latest_findings_by_asset_control_title(findings)

    valid_evidence_keys = {
        f"{ev.get('asset_id') or 'unknown'}:{ev.get('collector') or ev.get('source') or 'unknown'}"
        for ev in latest_evidence.values()
        if evidence_is_valid(ev)
    }

    remediations = []
    seen = set()

    for finding in latest_findings.values():
        status = (finding.get("status") or "open").lower()
        if status not in ["open", "active", "new"]:
            continue

        title = finding.get("title") or ""
        asset_id = finding.get("asset_id") or finding.get("asset") or "unknown"

        failed_collector = collector_from_failed_finding(title)
        if failed_collector:
            evidence_key = f"{asset_id}:{failed_collector}"
            if evidence_key in valid_evidence_keys:
                continue

        remediation = remediation_for_finding(finding)
        dedupe_key = (
            remediation.get("asset_id"),
            remediation.get("control_id"),
            remediation.get("title"),
            remediation.get("action"),
        )

        if dedupe_key not in seen:
            seen.add(dedupe_key)
            remediations.append(remediation)

    for ev in latest_evidence.values():
        if evidence_is_valid(ev):
            continue

        asset_id = ev.get("asset_id") or "unknown"
        collector = ev.get("collector") or ev.get("source") or "unknown"
        control_id = ev.get("control_id") or "UNMAPPED"

        remediation = {
            "asset_id": asset_id,
            "control_id": control_id,
            "severity": "high",
            "priority": "high",
            "title": f"Invalid evidence from {collector}",
            "action": f"Fix evidence collector output for {collector} on {asset_id}, then rerun the collector.",
            "rationale": "Invalid evidence cannot support compliance scoring.",
            "frameworks": framework_targets(control_id),
            "source_evidence_id": ev.get("evidence_id"),
        }

        dedupe_key = (
            remediation.get("asset_id"),
            remediation.get("control_id"),
            remediation.get("title"),
            remediation.get("action"),
        )

        if dedupe_key not in seen:
            seen.add(dedupe_key)
            remediations.append(remediation)

    grouped = defaultdict(list)
    for item in remediations:
        grouped[item["asset_id"]].append(item)

    return [
        {
            "asset_id": asset_id,
            "count": len(items),
            "remediations": items,
        }
        for asset_id, items in sorted(grouped.items())
    ]
