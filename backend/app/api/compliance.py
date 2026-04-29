from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Evidence, Finding
from app.services.compliance import FRAMEWORKS, framework_label

router = APIRouter()


FRAMEWORK_REQUIREMENTS = {
    "pci_dss": {
        "label": "PCI DSS",
        "requirements": {
            "network_security": {
                "weight": 20,
                "controls": ["NS-01"],
                "evidence_types": ["open_ports", "listening_services", "firewall_status"],
            },
            "secure_configuration": {
                "weight": 15,
                "controls": ["CM-01"],
                "evidence_types": ["ssh_config", "packages", "docker_inventory"],
            },
            "vulnerability_management": {
                "weight": 20,
                "controls": ["VM-01"],
                "evidence_types": ["packages", "held_packages", "available_updates"],
            },
            "access_control": {
                "weight": 20,
                "controls": ["AC-01", "AC-02"],
                "evidence_types": ["user_changes", "auth_success", "auth_failure", "sudo_activity", "ssh_config"],
            },
            "logging_monitoring": {
                "weight": 15,
                "controls": ["SI-01"],
                "evidence_types": ["auth_success", "auth_failure", "sudo_activity", "time_sync"],
            },
            "incident_response": {
                "weight": 10,
                "controls": ["IR-01", "CP-01"],
                "evidence_types": ["disk_usage"],
            },
        },
    },
    "soc2": {
        "label": "SOC 2",
        "requirements": {
            "security_access": {
                "weight": 25,
                "controls": ["AC-01", "AC-02"],
                "evidence_types": ["user_changes", "auth_success", "auth_failure", "sudo_activity", "ssh_config"],
            },
            "security_monitoring": {
                "weight": 20,
                "controls": ["SI-01"],
                "evidence_types": ["auth_success", "auth_failure", "sudo_activity", "time_sync"],
            },
            "change_configuration": {
                "weight": 20,
                "controls": ["CM-01"],
                "evidence_types": ["ssh_config", "packages", "docker_inventory"],
            },
            "risk_vulnerability": {
                "weight": 20,
                "controls": ["VM-01"],
                "evidence_types": ["packages", "held_packages", "available_updates"],
            },
            "availability_continuity": {
                "weight": 15,
                "controls": ["CP-01", "NS-01"],
                "evidence_types": ["disk_usage", "open_ports", "listening_services"],
            },
        },
    },
    "nist_800_53": {
        "label": "NIST 800-53",
        "requirements": {
            "access_control_ac": {
                "weight": 20,
                "controls": ["AC-01", "AC-02"],
                "evidence_types": ["user_changes", "auth_success", "auth_failure", "sudo_activity", "ssh_config"],
            },
            "audit_accountability_au": {
                "weight": 20,
                "controls": ["SI-01"],
                "evidence_types": ["auth_success", "auth_failure", "sudo_activity", "time_sync"],
            },
            "configuration_management_cm": {
                "weight": 20,
                "controls": ["CM-01"],
                "evidence_types": ["ssh_config", "packages", "docker_inventory"],
            },
            "risk_assessment_ra_si": {
                "weight": 20,
                "controls": ["VM-01"],
                "evidence_types": ["packages", "held_packages", "available_updates"],
            },
            "system_communications_sc": {
                "weight": 10,
                "controls": ["NS-01", "EN-01"],
                "evidence_types": ["open_ports", "listening_services", "firewall_status"],
            },
            "contingency_cp": {
                "weight": 10,
                "controls": ["CP-01"],
                "evidence_types": ["disk_usage"],
            },
        },
    },
    "iso_27001": {
        "label": "ISO 27001",
        "requirements": {
            "identity_access": {
                "weight": 20,
                "controls": ["AC-01", "AC-02"],
                "evidence_types": ["user_changes", "auth_success", "auth_failure", "sudo_activity", "ssh_config"],
            },
            "logging_monitoring": {
                "weight": 15,
                "controls": ["SI-01"],
                "evidence_types": ["auth_success", "auth_failure", "sudo_activity", "time_sync"],
            },
            "technical_vulnerability": {
                "weight": 20,
                "controls": ["VM-01"],
                "evidence_types": ["packages", "held_packages", "available_updates"],
            },
            "configuration_management": {
                "weight": 15,
                "controls": ["CM-01"],
                "evidence_types": ["ssh_config", "packages", "docker_inventory"],
            },
            "network_security": {
                "weight": 15,
                "controls": ["NS-01"],
                "evidence_types": ["open_ports", "listening_services", "firewall_status"],
            },
            "continuity_resilience": {
                "weight": 15,
                "controls": ["CP-01", "IR-01"],
                "evidence_types": ["disk_usage"],
            },
        },
    },
    "iso_27002": {
        "label": "ISO 27002",
        "requirements": {
            "access_rights": {
                "weight": 18,
                "controls": ["AC-01", "AC-02"],
                "evidence_types": ["user_changes", "auth_success", "auth_failure", "sudo_activity", "ssh_config"],
            },
            "event_logging_monitoring": {
                "weight": 18,
                "controls": ["SI-01"],
                "evidence_types": ["auth_success", "auth_failure", "sudo_activity", "time_sync"],
            },
            "vulnerability_management": {
                "weight": 20,
                "controls": ["VM-01"],
                "evidence_types": ["packages", "held_packages", "available_updates"],
            },
            "configuration_information": {
                "weight": 14,
                "controls": ["CM-01"],
                "evidence_types": ["ssh_config", "packages", "docker_inventory"],
            },
            "network_security": {
                "weight": 15,
                "controls": ["NS-01"],
                "evidence_types": ["open_ports", "listening_services", "firewall_status"],
            },
            "backup_resilience": {
                "weight": 15,
                "controls": ["CP-01", "IR-01"],
                "evidence_types": ["disk_usage"],
            },
        },
    },
}


SEVERITY_PENALTIES = {
    "critical": 10,
    "high": 7,
    "medium": 3,
    "low": 1,
}


def _evidence_matches_requirement(ev, framework: str, requirement: dict) -> bool:
    if not ev.validated:
        return False

    if not ev.frameworks or not ev.frameworks.get(framework):
        return False

    if ev.evidence_type not in requirement["evidence_types"]:
        return False

    if ev.control_id not in requirement["controls"]:
        return False

    return True


def _failed_evidence_for_requirement(evidence: list, framework: str, requirement: dict) -> list:
    failed = []
    for ev in evidence:
        if ev.validated:
            continue
        if not ev.frameworks or not ev.frameworks.get(framework):
            continue
        if ev.evidence_type in requirement["evidence_types"] or ev.control_id in requirement["controls"]:
            failed.append(ev)
    return failed


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


def calculate_score(framework: str, db: Session) -> dict:
    if framework not in FRAMEWORK_REQUIREMENTS:
        return {
            "framework": framework,
            "label": framework_label(framework),
            "error": "Unknown framework",
        }

    profile = FRAMEWORK_REQUIREMENTS[framework]
    evidence = db.query(Evidence).all()
    findings = db.query(Finding).all()

    requirement_results = []
    weighted_score = 0.0

    for requirement_name, requirement in profile["requirements"].items():
        weight = requirement["weight"]

        matched_evidence = [
            ev for ev in evidence
            if _evidence_matches_requirement(ev, framework, requirement)
        ]

        failed_evidence = _failed_evidence_for_requirement(evidence, framework, requirement)

        applicable_findings = [
            f for f in findings
            if _finding_applies_to_requirement(f, framework, requirement)
        ]

        base_completion = 100.0 if matched_evidence else 0.0

        failed_collector_penalty = min(len(failed_evidence) * 15, 40)

        finding_penalty = 0
        for finding in applicable_findings:
            finding_penalty += SEVERITY_PENALTIES.get((finding.severity or "").lower(), 2)
        finding_penalty = min(finding_penalty, 50)

        requirement_score = max(0.0, base_completion - failed_collector_penalty - finding_penalty)
        weighted_score += requirement_score * (weight / 100)

        requirement_results.append({
            "requirement": requirement_name,
            "weight": weight,
            "score": round(requirement_score, 2),
            "controls": requirement["controls"],
            "expected_evidence_types": requirement["evidence_types"],
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
            "requirements_with_evidence": len([r for r in requirement_results if r["matched_evidence"]]),
            "requirements_with_failed_collectors": len([r for r in requirement_results if r["failed_evidence"]]),
            "requirements_with_open_findings": len([r for r in requirement_results if r["open_findings"]]),
        },
    }


@router.get("/score")
def all_scores(db: Session = Depends(get_db)):
    return {fw: calculate_score(fw, db) for fw in FRAMEWORKS}


@router.get("/score/{framework}")
def framework_score(framework: str, db: Session = Depends(get_db)):
    return calculate_score(framework, db)


@router.get("/findings/{framework}")
def findings_by_framework(framework: str, db: Session = Depends(get_db)):
    findings = db.query(Finding).all()
    return [
        f for f in findings
        if (f.framework_mappings and f.framework_mappings.get(framework))
        or (f.affected_frameworks and framework in f.affected_frameworks)
    ]


@router.get("/evidence/{framework}")
def evidence_by_framework(framework: str, db: Session = Depends(get_db)):
    evidence = db.query(Evidence).all()
    return [
        e for e in evidence
        if e.frameworks and e.frameworks.get(framework)
    ]
