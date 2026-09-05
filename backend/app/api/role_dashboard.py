from collections import defaultdict
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Asset, Evidence, Finding

router = APIRouter(prefix="/api/role-dashboard", tags=["role-dashboard"])


EVIDENCE_CATEGORY_RULES = {
    "monitoring": [
        "prometheus",
        "grafana",
        "alertmanager",
        "monitoring",
    ],
    "logging_siem": [
        "wazuh",
        "siem",
        "log",
        "auth_success",
        "auth_failures",
        "sudo_activity",
    ],
    "endpoint_security": [
        "trend_micro",
        "ds_agent",
        "wazuh_agent",
        "malware",
        "edr",
    ],
    "patching": [
        "automox",
        "amagent",
        "package",
        "updates",
        "held_packages",
        "available_updates",
    ],
    "mfa_identity": [
        "duo",
        "mfa",
        "keycloak",
        "identity",
        "authentication",
    ],
    "network_exposure": [
        "ports",
        "listening",
        "firewall",
        "ssh",
        "sftp",
        "tls",
        "nginx",
        "apache",
    ],
    "configuration": [
        "config",
        "docker",
        "service",
        "application",
        "database",
    ],
    "backup_retention": [
        "backup",
        "retention",
        "storage",
        "disk",
    ],
}


FINDING_CATEGORY_RULES = {
    "access_control": [
        "authentication",
        "mfa",
        "duo",
        "access",
        "authorized keys",
    ],
    "network_exposure": [
        "open ports",
        "listening services",
        "firewall",
        "ssh",
        "sftp",
    ],
    "patching": [
        "updates",
        "packages",
        "held packages",
        "vulnerability",
    ],
    "logging_monitoring": [
        "time synchronization",
        "time sync",
        "log",
        "monitoring",
        "wazuh",
        "prometheus",
        "grafana",
    ],
    "configuration": [
        "configuration",
        "docker",
        "service",
        "baseline",
    ],
}


ROLE_FOCUS = {
    "monitoring_server": [
        "Prometheus/Grafana service health",
        "Alert routing and monitoring coverage",
        "Monitoring evidence retention",
    ],
    "central_log_server": [
        "Centralized log ingestion",
        "SIEM/Wazuh manager health",
        "Log retention and alert routing",
    ],
    "siem_server": [
        "SIEM manager health",
        "Alert rule coverage",
        "Log ingestion validation",
    ],
    "sftp_server": [
        "SFTP/SSH hardening",
        "Duo MFA enforcement",
        "Authorized key review",
        "File transfer audit logging",
    ],
    "storage_server": [
        "Storage access control",
        "Retention and backup evidence",
        "Disk and file integrity monitoring",
    ],
    "application_server": [
        "Application service health",
        "Application logging",
        "Deployment traceability",
    ],
    "web_server": [
        "TLS configuration",
        "HTTP service exposure",
        "Reverse proxy and web access logs",
    ],
    "database_server": [
        "Database listener exposure",
        "Privileged access review",
        "Backup and recovery evidence",
    ],
    "ci_cd_server": [
        "Pipeline audit logging",
        "Deployment access control",
        "Secrets and build artifact handling",
    ],
    "identity_provider": [
        "MFA enforcement",
        "Realm/federation configuration",
        "Authentication and admin event logging",
    ],
    "container_host": [
        "Container inventory",
        "Docker socket exposure",
        "Privileged container review",
    ],
}


def row_dict(row):
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


ROLE_FOCUS[
    "web_automation_server"
] = [
    "Browser automation runtime health",
    "Worker execution isolation",
    "RDP and SSH access review",
    "Automation service accounts",
    "Automation execution logging",
]

ROLE_FOCUS[
    "web_automation_orchestrator_server"
] = [
    "Automation orchestration health",
    "Worker routing and job isolation",
    "Pipeline and execution audit logging",
    "Credential and secret handling",
    "Remote execution access control",
]


def get_value(row, *keys, default=None):
    for key in keys:
        value = row.get(key)
        if value not in [None, ""]:
            return value
    return default


def categorize(value, rules, default="other"):
    text = str(value or "").lower()

    for category, terms in rules.items():
        if any(term in text for term in terms):
            return category

    return default


def normalize_roles(asset):
    roles = asset.asset_roles or []
    if isinstance(roles, str):
        return [item.strip() for item in roles.split(",") if item.strip()]
    return roles


def status_from_counts(validated, total):
    if total == 0:
        return "no evidence"
    if validated == total:
        return "validated"
    if validated > 0:
        return "partial"
    return "needs review"


@router.get("/summary")
def role_dashboard_summary(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    evidence = [row_dict(row) for row in db.query(Evidence).all()]
    findings = [row_dict(row) for row in db.query(Finding).all()]

    evidence_by_asset = defaultdict(list)
    findings_by_asset = defaultdict(list)

    for item in evidence:
        evidence_by_asset[get_value(item, "asset_id", "asset", default="unknown")].append(item)

    for item in findings:
        findings_by_asset[get_value(item, "asset_id", "asset", default="unknown")].append(item)

    response = []

    for asset in assets:
        asset_id = asset.asset_id
        roles = normalize_roles(asset)
        asset_evidence = evidence_by_asset.get(asset_id, [])
        asset_findings = findings_by_asset.get(asset_id, [])

        evidence_categories = defaultdict(lambda: {
            "total": 0,
            "validated": 0,
            "collectors": set(),
        })

        for item in asset_evidence:
            collector = get_value(item, "collector", "evidence_type", "source", default="unknown")
            category = categorize(collector, EVIDENCE_CATEGORY_RULES)

            evidence_categories[category]["total"] += 1
            evidence_categories[category]["collectors"].add(str(collector))

            if item.get("validated") is True or str(item.get("status", "")).lower() == "valid":
                evidence_categories[category]["validated"] += 1

        formatted_evidence_categories = []

        for category, data in sorted(evidence_categories.items()):
            formatted_evidence_categories.append({
                "category": category,
                "total": data["total"],
                "validated": data["validated"],
                "status": status_from_counts(data["validated"], data["total"]),
                "collectors": sorted(data["collectors"]),
            })

        finding_categories = defaultdict(lambda: {
            "total": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "titles": set(),
        })

        for item in asset_findings:
            status = str(get_value(item, "status", default="open")).lower()
            if status not in ["open", "active", "new"]:
                continue

            title = get_value(item, "title", default="Untitled finding")
            category = categorize(title, FINDING_CATEGORY_RULES)
            severity = str(get_value(item, "severity", default="medium")).lower()

            finding_categories[category]["total"] += 1
            finding_categories[category]["titles"].add(title)

            if severity in ["critical", "high"]:
                finding_categories[category]["high"] += 1
            elif severity == "low":
                finding_categories[category]["low"] += 1
            else:
                finding_categories[category]["medium"] += 1

        formatted_finding_categories = []

        for category, data in sorted(finding_categories.items()):
            formatted_finding_categories.append({
                "category": category,
                "total": data["total"],
                "high": data["high"],
                "medium": data["medium"],
                "low": data["low"],
                "titles": sorted(data["titles"]),
            })

        focus = []
        for role in roles:
            for item in ROLE_FOCUS.get(role, []):
                if item not in focus:
                    focus.append(item)

        response.append({
            "asset_id": asset_id,
            "hostname": asset.hostname,
            "environment": asset.environment,
            "asset_roles": roles,
            "data_classification": asset.data_classification or [],
            "evidence_total": len(asset_evidence),
            "finding_total": sum(item["total"] for item in formatted_finding_categories),
            "evidence_categories": formatted_evidence_categories,
            "finding_categories": formatted_finding_categories,
            "role_focus": focus,
        })

    return {
        "assets": response,
        "totals": {
            "assets": len(response),
            "evidence": sum(item["evidence_total"] for item in response),
            "findings": sum(item["finding_total"] for item in response),
        },
    }
