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

    mappings = {
        "AC": ["pci_dss", "soc2", "nist_800_53", "iso_27002"],
        "AM": ["pci_dss", "soc2", "nist_800_53", "iso_27002"],
        "CM": ["pci_dss", "soc2", "nist_800_53", "iso_27002"],
        "CP": ["pci_dss", "soc2", "nist_800_53", "iso_27002"],
        "IR": ["pci_dss", "soc2", "nist_800_53", "iso_27002"],
        "SI": ["pci_dss", "soc2", "nist_800_53", "iso_27002"],
        "VM": ["pci_dss", "soc2", "nist_800_53", "iso_27002"],
        "NS": ["pci_dss", "soc2", "nist_800_53", "iso_27002"],
        "EN": ["pci_dss", "soc2", "nist_800_53", "iso_27002"],
        "SD": ["pci_dss", "soc2", "nist_800_53", "iso_27002"],
    }

    prefix = control_id.split("-")[0] if "-" in control_id else control_id
    return mappings.get(prefix, ["pci_dss", "soc2"])


def remediation_for_finding(finding):
    title = finding.get("title") or ""
    severity = finding.get("severity") or "medium"
    control_id = finding.get("control_id") or finding.get("control") or "UNMAPPED"
    asset_id = finding.get("asset_id") or finding.get("asset") or "unknown"

    lower = title.lower()

    if "collector failed" in lower:
        match = re.search(r"collector failed:\s*(.+)$", title, re.I)
        collector = match.group(1).strip() if match else "unknown"
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


@router.get("/")
def list_remediations():
    findings = get_db_rows("Finding")
    evidence = get_db_rows("Evidence")

    remediations = []

    for finding in findings:
        status = (finding.get("status") or "open").lower()
        if status in ["open", "active", "new"]:
            remediations.append(remediation_for_finding(finding))

    for ev in evidence:
        validated = ev.get("validated")
        if validated is False or str(validated).lower() == "false":
            asset_id = ev.get("asset_id") or "unknown"
            collector = ev.get("collector") or ev.get("source") or "unknown"
            control_id = ev.get("control_id") or "UNMAPPED"
            remediations.append({
                "asset_id": asset_id,
                "control_id": control_id,
                "severity": "high",
                "priority": "high",
                "title": f"Invalid evidence from {collector}",
                "action": f"Fix evidence collector output for {collector} on {asset_id}, then rerun the collector.",
                "rationale": "Invalid evidence cannot support compliance scoring.",
                "frameworks": framework_targets(control_id),
                "source_evidence_id": ev.get("evidence_id"),
            })

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
