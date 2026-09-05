from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Evidence, Finding, Asset
from app.services.compliance import FRAMEWORKS, framework_label

router = APIRouter()


FRAMEWORK_REQUIREMENTS = {
    "pci_dss": {
        "label": "PCI DSS",
        "requirements": {
            "network_security": {"weight": 20, "controls": ["NS-01"], "evidence_types": ["open_ports", "listening_services", "firewall_status"]},
            "secure_configuration": {"weight": 15, "controls": ["CM-01"], "evidence_types": ["ssh_config", "packages", "docker_inventory"]},
            "vulnerability_management": {"weight": 20, "controls": ["VM-01"], "evidence_types": ["packages", "held_packages", "available_updates"]},
            "access_control": {"weight": 20, "controls": ["AC-01", "AC-02"], "evidence_types": ["user_changes", "auth_success", "auth_failure", "sudo_activity", "ssh_config"]},
            "logging_monitoring": {"weight": 15, "controls": ["SI-01"], "evidence_types": ["auth_success", "auth_failure", "sudo_activity", "time_sync"]},
            "incident_response": {"weight": 10, "controls": ["IR-01", "CP-01"], "evidence_types": ["disk_usage"]},
        },
    },
    "soc2": {
        "label": "SOC 2",
        "requirements": {
            "security_access": {"weight": 25, "controls": ["AC-01", "AC-02"], "evidence_types": ["user_changes", "auth_success", "auth_failure", "sudo_activity", "ssh_config"]},
            "security_monitoring": {"weight": 20, "controls": ["SI-01"], "evidence_types": ["auth_success", "auth_failure", "sudo_activity", "time_sync"]},
            "change_configuration": {"weight": 20, "controls": ["CM-01"], "evidence_types": ["ssh_config", "packages", "docker_inventory"]},
            "risk_vulnerability": {"weight": 20, "controls": ["VM-01"], "evidence_types": ["packages", "held_packages", "available_updates"]},
            "availability_continuity": {"weight": 15, "controls": ["CP-01", "NS-01"], "evidence_types": ["disk_usage", "open_ports", "listening_services"]},
        },
    },
    "nist_800_53": {
        "label": "NIST 800-53",
        "requirements": {
            "access_control_ac": {"weight": 20, "controls": ["AC-01", "AC-02"], "evidence_types": ["user_changes", "auth_success", "auth_failure", "sudo_activity", "ssh_config"]},
            "audit_accountability_au": {"weight": 20, "controls": ["SI-01"], "evidence_types": ["auth_success", "auth_failure", "sudo_activity", "time_sync"]},
            "configuration_management_cm": {"weight": 20, "controls": ["CM-01"], "evidence_types": ["ssh_config", "packages", "docker_inventory"]},
            "risk_assessment_ra_si": {"weight": 20, "controls": ["VM-01"], "evidence_types": ["packages", "held_packages", "available_updates"]},
            "system_communications_sc": {"weight": 10, "controls": ["NS-01", "EN-01"], "evidence_types": ["open_ports", "listening_services", "firewall_status"]},
            "contingency_cp": {"weight": 10, "controls": ["CP-01"], "evidence_types": ["disk_usage"]},
        },
    },
    "iso_27001": {
        "label": "ISO 27001",
        "requirements": {
            "identity_access": {"weight": 20, "controls": ["AC-01", "AC-02"], "evidence_types": ["user_changes", "auth_success", "auth_failure", "sudo_activity", "ssh_config"]},
            "logging_monitoring": {"weight": 15, "controls": ["SI-01"], "evidence_types": ["auth_success", "auth_failure", "sudo_activity", "time_sync"]},
            "technical_vulnerability": {"weight": 20, "controls": ["VM-01"], "evidence_types": ["packages", "held_packages", "available_updates"]},
            "configuration_management": {"weight": 15, "controls": ["CM-01"], "evidence_types": ["ssh_config", "packages", "docker_inventory"]},
            "network_security": {"weight": 15, "controls": ["NS-01"], "evidence_types": ["open_ports", "listening_services", "firewall_status"]},
            "continuity_resilience": {"weight": 15, "controls": ["CP-01", "IR-01"], "evidence_types": ["disk_usage"]},
        },
    },
    "iso_27002": {
        "label": "ISO 27002",
        "requirements": {
            "access_rights": {"weight": 18, "controls": ["AC-01", "AC-02"], "evidence_types": ["user_changes", "auth_success", "auth_failure", "sudo_activity", "ssh_config"]},
            "event_logging_monitoring": {"weight": 18, "controls": ["SI-01"], "evidence_types": ["auth_success", "auth_failure", "sudo_activity", "time_sync"]},
            "vulnerability_management": {"weight": 20, "controls": ["VM-01"], "evidence_types": ["packages", "held_packages", "available_updates"]},
            "configuration_information": {"weight": 14, "controls": ["CM-01"], "evidence_types": ["ssh_config", "packages", "docker_inventory"]},
            "network_security": {"weight": 15, "controls": ["NS-01"], "evidence_types": ["open_ports", "listening_services", "firewall_status"]},
            "backup_resilience": {"weight": 15, "controls": ["CP-01", "IR-01"], "evidence_types": ["disk_usage"]},
        },
    },
}


SEVERITY_PENALTIES = {"critical": 10, "high": 7, "medium": 3, "low": 1, "informational": 0}


def _asset_ids_for_environment(db: Session, environment: str | None):
    if not environment or environment == "all":
        return None

    return {
        a.asset_id
        for a in db.query(Asset).filter(Asset.environment == environment).all()
    }


def _filter_by_environment(records, asset_ids):
    if asset_ids is None:
        return records

    return [
        r for r in records
        if getattr(r, "asset_id", None) in asset_ids
    ]


def _framework_values(raw, framework):
    if not raw:
        return []

    if isinstance(raw, dict):
        value = raw.get(framework, [])
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    if isinstance(raw, list):
        return raw

    return [raw]


def _evidence_matches_requirement(ev, framework: str, requirement: dict) -> bool:
    return (
        ev.validated
        and ev.frameworks
        and _framework_values(ev.frameworks, framework)
        and ev.evidence_type in requirement["evidence_types"]
        and ev.control_id in requirement["controls"]
    )


def _failed_evidence_for_requirement(evidence: list, framework: str, requirement: dict) -> list:
    return [
        ev for ev in evidence
        if not ev.validated
        and ev.frameworks
        and _framework_values(ev.frameworks, framework)
        and (
            ev.evidence_type in requirement["evidence_types"]
            or ev.control_id in requirement["controls"]
        )
    ]


def _finding_applies_to_requirement(finding, framework: str, requirement: dict) -> bool:
    if finding.status != "open":
        return False

    if finding.control_id not in requirement["controls"]:
        return False

    if finding.framework_mappings and finding.framework_mappings.get(framework):
        return True

    if finding.affected_frameworks and framework in finding.affected_frameworks:
        return True

    return False


def _record_timestamp(obj):
    for attr in ("collected_at", "created_at", "updated_at", "id"):
        value = getattr(obj, attr, None)
        if value is not None:
            return value
    return ""


def _latest_evidence_records(evidence: list) -> list:
    latest = {}

    for ev in evidence:
        key = (
            getattr(ev, "asset_id", None),
            getattr(ev, "collector", None),
            getattr(ev, "control_id", None),
        )

        if key not in latest or _record_timestamp(ev) > _record_timestamp(latest[key]):
            latest[key] = ev

    return list(latest.values())


def _finding_evidence_id(finding):
    raw = getattr(finding, "raw", None) or {}

    if isinstance(raw, dict):
        evidence_id = raw.get("evidence_id")
        if evidence_id:
            return evidence_id

    finding_id = getattr(finding, "finding_id", "") or ""
    parts = finding_id.split("-")

    for i, part in enumerate(parts):
        if part == "EV" and i + 1 < len(parts):
            return f"EV-{parts[i + 1]}"

    return None


def _current_findings_only(findings: list, current_evidence_ids: set) -> list:
    current = []

    for finding in findings:
        evidence_id = _finding_evidence_id(finding)

        if evidence_id is None or evidence_id in current_evidence_ids:
            current.append(finding)

    return current


def _query_latest_evidence(
    db: Session,
    asset_ids: set | None,
) -> list:
    logical_collector = func.coalesce(
        Evidence.collector,
        Evidence.evidence_type,
        Evidence.source,
        "unknown",
    )

    ranked = (
        db.query(
            Evidence.id.label("evidence_row_id"),
            func.row_number()
            .over(
                partition_by=(
                    func.coalesce(
                        Evidence.asset_id,
                        "unknown",
                    ),
                    logical_collector,
                    func.coalesce(
                        Evidence.control_id,
                        "unknown",
                    ),
                ),
                order_by=(
                    Evidence.created_at.desc(),
                    Evidence.id.desc(),
                ),
            )
            .label("row_rank"),
        )
    )

    if asset_ids is not None:
        if not asset_ids:
            return []

        ranked = ranked.filter(
            Evidence.asset_id.in_(asset_ids)
        )

    ranked = ranked.subquery()

    return (
        db.query(Evidence)
        .join(
            ranked,
            Evidence.id
            == ranked.c.evidence_row_id,
        )
        .filter(ranked.c.row_rank == 1)
        .all()
    )


def _query_current_findings(
    db: Session,
    asset_ids: set | None,
) -> list:
    logical_type = func.coalesce(
        Finding.finding_type,
        Finding.title,
        Finding.finding_id,
    )

    ranked = (
        db.query(
            Finding.id.label("finding_row_id"),
            func.row_number()
            .over(
                partition_by=(
                    func.coalesce(
                        Finding.asset_id,
                        "unknown",
                    ),
                    logical_type,
                    func.coalesce(
                        Finding.control_id,
                        "unknown",
                    ),
                ),
                order_by=(
                    Finding.created_at.desc(),
                    Finding.id.desc(),
                ),
            )
            .label("row_rank"),
        )
        .filter(Finding.status == "open")
    )

    if asset_ids is not None:
        if not asset_ids:
            return []

        ranked = ranked.filter(
            Finding.asset_id.in_(asset_ids)
        )

    ranked = ranked.subquery()

    return (
        db.query(Finding)
        .join(
            ranked,
            Finding.id
            == ranked.c.finding_row_id,
        )
        .filter(ranked.c.row_rank == 1)
        .all()
    )


def _compliance_records(
    db: Session,
    environment: str | None,
) -> tuple:
    cache_key = environment or "all"

    cache = db.info.setdefault(
        "compliance_records",
        {},
    )

    if cache_key in cache:
        return cache[cache_key]

    asset_ids = _asset_ids_for_environment(
        db,
        environment,
    )

    evidence = _query_latest_evidence(
        db,
        asset_ids,
    )

    current_evidence_ids = {
        evidence_record.evidence_id
        for evidence_record in evidence
        if evidence_record.evidence_id
    }

    findings = _query_current_findings(
        db,
        asset_ids,
    )

    findings = _current_findings_only(
        findings,
        current_evidence_ids,
    )

    asset_scope_count = (
        len(asset_ids)
        if asset_ids is not None
        else db.query(Asset).count()
    )

    cache[cache_key] = (
        asset_ids,
        asset_scope_count,
        evidence,
        findings,
    )

    return cache[cache_key]


def calculate_score(framework: str, db: Session, environment: str | None = None) -> dict:
    if framework not in FRAMEWORK_REQUIREMENTS:
        return {
            "framework": framework,
            "label": framework_label(framework),
            "error": "Unknown framework",
        }

    (
        asset_ids,
        asset_scope_count,
        evidence,
        findings,
    ) = _compliance_records(
        db,
        environment,
    )

    profile = FRAMEWORK_REQUIREMENTS[framework]

    requirement_results = []
    weighted_score = 0.0

    for requirement_name, requirement in profile["requirements"].items():
        weight = requirement["weight"]

        matched_evidence = [
            ev for ev in evidence
            if _evidence_matches_requirement(ev, framework, requirement)
        ]

        failed_evidence = _failed_evidence_for_requirement(
            evidence,
            framework,
            requirement,
        )

        applicable_findings = [
            f for f in findings
            if _finding_applies_to_requirement(f, framework, requirement)
        ]

        base_completion = 100.0 if matched_evidence else 0.0
        failed_collector_penalty = min(len(failed_evidence) * 15, 40)

        finding_penalty = 0
        for finding in applicable_findings:
            finding_penalty += SEVERITY_PENALTIES.get(
                (finding.severity or "").lower(),
                2,
            )

        finding_penalty = min(finding_penalty, 50)

        requirement_score = max(
            0.0,
            base_completion - failed_collector_penalty - finding_penalty,
        )

        weighted_score += requirement_score * (weight / 100)

        requirement_results.append({
            "requirement": requirement_name,
            "weight": weight,
            "score": round(requirement_score, 2),
            "controls": requirement["controls"],
            "expected_evidence_types": requirement["evidence_types"],
            "matched_evidence_count": len(matched_evidence),
            "failed_evidence_count": len(failed_evidence),
            "open_findings_count": len(applicable_findings),
            "matched_evidence": [
                {
                    "evidence_id": ev.evidence_id,
                    "asset_id": ev.asset_id,
                    "collector": ev.collector,
                    "control_id": ev.control_id,
                    "validated": ev.validated,
                }
                for ev in matched_evidence
            ],
            "failed_evidence": [
                {
                    "evidence_id": ev.evidence_id,
                    "asset_id": ev.asset_id,
                    "collector": ev.collector,
                    "control_id": ev.control_id,
                    "validated": ev.validated,
                }
                for ev in failed_evidence
            ],
            "open_findings": [
                {
                    "finding_id": f.finding_id,
                    "asset_id": f.asset_id,
                    "severity": f.severity,
                    "control_id": f.control_id,
                    "status": f.status,
                }
                for f in applicable_findings
            ],
        })

    score = round(weighted_score, 2)

    return {
        "framework": framework,
        "label": profile["label"],
        "environment": environment or "all",
        "asset_scope_count": asset_scope_count,
        "readiness_score": score,
        "status": (
            "strong_readiness" if score >= 90 else
            "moderate_readiness" if score >= 75 else
            "at_risk" if score >= 50 else
            "not_ready"
        ),
        "requirements": requirement_results,
        "summary": {
            "total_requirements": len(requirement_results),
            "requirements_with_evidence": len([
                r for r in requirement_results
                if r["matched_evidence_count"] > 0
            ]),
            "requirements_with_failed_collectors": len([
                r for r in requirement_results
                if r["failed_evidence_count"] > 0
            ]),
            "requirements_with_open_findings": len([
                r for r in requirement_results
                if r["open_findings_count"] > 0
            ]),
        },
    }


@router.get("/environments")
def list_environments(db: Session = Depends(get_db)):
    environments = sorted({
        a.environment
        for a in db.query(Asset).all()
        if a.environment
    })

    return {
        "environments": ["all"] + environments
    }


@router.get("/score")
def all_scores(environment: str = "all", db: Session = Depends(get_db)):
    return {
        fw: calculate_score(fw, db, environment=environment)
        for fw in FRAMEWORKS
    }


@router.get("/score/{framework}")
def framework_score(
    framework: str,
    environment: str = "all",
    db: Session = Depends(get_db),
):
    return calculate_score(framework, db, environment=environment)


@router.get("/findings/{framework}")
def findings_by_framework(
    framework: str,
    environment: str = "all",
    db: Session = Depends(get_db),
):
    asset_ids = _asset_ids_for_environment(
        db,
        environment,
    )
    findings = _query_current_findings(
        db,
        asset_ids,
    )

    return [
        f for f in findings
        if getattr(f, "status", None) == "open"
        and (
            (f.framework_mappings and f.framework_mappings.get(framework))
            or (f.affected_frameworks and framework in f.affected_frameworks)
        )
    ]


@router.get("/evidence/{framework}")
def evidence_by_framework(
    framework: str,
    environment: str = "all",
    db: Session = Depends(get_db),
):
    asset_ids = _asset_ids_for_environment(
        db,
        environment,
    )
    evidence = _query_latest_evidence(
        db,
        asset_ids,
    )

    return [
        e for e in evidence
        if e.frameworks and _framework_values(e.frameworks, framework)
    ]
