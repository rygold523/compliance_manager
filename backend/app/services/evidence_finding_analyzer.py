from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import Evidence, Finding
from app.services.control_mapper import get_framework_mappings
from app.services.compliance import affected_frameworks_from_mappings


def _severity_score(severity: str) -> int:
    return {
        "critical": 100,
        "high": 80,
        "medium": 50,
        "low": 25,
        "informational": 5,
    }.get((severity or "").lower(), 10)


def _existing_finding(db: Session, finding_id: str):
    return db.query(Finding).filter(Finding.finding_id == finding_id).first()


def _create_finding(
    db: Session,
    evidence: Evidence,
    finding_type: str,
    title: str,
    description: str,
    severity: str,
    control_id: str,
    raw: dict,
):
    finding_id = f"EF-{evidence.evidence_id}-{finding_type}".replace("_", "-").upper()

    if _existing_finding(db, finding_id):
        return None

    mappings = get_framework_mappings(control_id)

    finding = Finding(
        finding_id=finding_id,
        asset_id=evidence.asset_id or "unknown",
        source="evidence_analyzer",
        title=title,
        description=description,
        severity=severity,
        cve=None,
        finding_type=finding_type,
        control_id=control_id,
        status="open",
        risk_score=_severity_score(severity),
        raw=raw,
        framework_mappings=mappings,
        affected_frameworks=affected_frameworks_from_mappings(mappings),
    )

    db.add(finding)
    return finding


def analyze_evidence_record(db: Session, evidence: Evidence):
    created = []

    collector = evidence.collector or evidence.evidence_type or "unknown"
    control_id = evidence.control_id or "CM-01"

    raw = {
        "evidence_id": evidence.evidence_id,
        "asset_id": evidence.asset_id,
        "collector": collector,
        "control_id": evidence.control_id,
        "validated": evidence.validated,
        "file_path": evidence.file_path,
        "frameworks": evidence.frameworks,
    }

    # Failed collectors are findings because they represent missing or unusable evidence.
    if not evidence.validated:
        severity = "medium"

        if collector in {"firewall_status", "ssh_config", "docker_inventory"}:
            severity = "high"

        f = _create_finding(
            db=db,
            evidence=evidence,
            finding_type=f"{collector}_collector_failed",
            title=f"Evidence collector failed: {collector}",
            description=(
                f"The {collector} evidence collector failed for asset {evidence.asset_id}. "
                "This reduces compliance confidence because required evidence could not be validated."
            ),
            severity=severity,
            control_id=control_id,
            raw=raw,
        )
        if f:
            created.append(f)

    # Available updates indicate patch/vulnerability management exposure.
    if collector == "available_updates" and evidence.validated:
        f = _create_finding(
            db=db,
            evidence=evidence,
            finding_type="available_updates_detected",
            title="Available package updates detected",
            description=(
                f"The asset {evidence.asset_id} has available package updates. "
                "This should be reviewed against vulnerability management requirements. "
                "Held packages must not be updated automatically."
            ),
            severity="medium",
            control_id="VM-01",
            raw=raw,
        )
        if f:
            created.append(f)

    # Held packages are not necessarily a vulnerability, but require exception tracking.
    if collector == "held_packages" and evidence.validated:
        f = _create_finding(
            db=db,
            evidence=evidence,
            finding_type="held_packages_require_review",
            title="Held packages require vulnerability management review",
            description=(
                f"The asset {evidence.asset_id} has held packages or held-package evidence. "
                "Held packages may be intentional, but they require review to ensure security updates are not being blocked."
            ),
            severity="low",
            control_id="VM-01",
            raw=raw,
        )
        if f:
            created.append(f)

    # Authentication failures can indicate access-control monitoring concerns.
    if collector == "auth_failure" and evidence.validated:
        f = _create_finding(
            db=db,
            evidence=evidence,
            finding_type="authentication_failures_observed",
            title="Authentication failures observed",
            description=(
                f"Failed authentication activity was collected for asset {evidence.asset_id}. "
                "Review the evidence to determine whether failures are expected, excessive, or suspicious."
            ),
            severity="medium",
            control_id="AC-02",
            raw=raw,
        )
        if f:
            created.append(f)

    # Open ports/listening services require review, not automatic closure.
    if collector in {"open_ports", "listening_services"} and evidence.validated:
        f = _create_finding(
            db=db,
            evidence=evidence,
            finding_type=f"{collector}_review_required",
            title=f"{collector.replace('_', ' ').title()} require review",
            description=(
                f"The {collector} collector identified network exposure information for asset {evidence.asset_id}. "
                "Review listening services and open ports against the approved service baseline."
            ),
            severity="low",
            control_id="NS-01",
            raw=raw,
        )
        if f:
            created.append(f)

    # Time sync evidence is important for PCI/SOC2 logging defensibility.
    if collector == "time_sync" and evidence.validated:
        f = _create_finding(
            db=db,
            evidence=evidence,
            finding_type="time_sync_review",
            title="Time synchronization evidence requires review",
            description=(
                f"Time synchronization evidence was collected for asset {evidence.asset_id}. "
                "Confirm the system clock is synchronized and aligned with centralized logging requirements."
            ),
            severity="informational",
            control_id="SI-01",
            raw=raw,
        )
        if f:
            created.append(f)

    return created


def analyze_all_evidence(db: Session):
    evidence_records = db.query(Evidence).all()
    created = []

    for evidence in evidence_records:
        created.extend(analyze_evidence_record(db, evidence))

    db.commit()

    return {
        "analyzed_evidence_count": len(evidence_records),
        "created_findings_count": len(created),
        "created_findings": [
            {
                "finding_id": f.finding_id,
                "asset_id": f.asset_id,
                "severity": f.severity,
                "control_id": f.control_id,
                "title": f.title,
            }
            for f in created
        ],
    }
