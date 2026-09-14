import hashlib
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from app.api.changelog import write_changelog
from app.auth.service import audit
from app.core.config import settings
from app.models.models import Evidence, GeneratedReport, GeneratedReportEvidence


REPORT_STATUSES = frozenset({"draft", "current", "issued", "superseded", "revoked"})
PROTECTED_REPORT_STATUSES = frozenset({"draft", "current", "issued"})
ALLOWED_TRANSITIONS = {
    "draft": frozenset({"current", "issued", "revoked"}),
    "current": frozenset({"issued", "superseded", "revoked"}),
    "issued": frozenset({"superseded", "revoked"}),
    "superseded": frozenset(),
    "revoked": frozenset(),
}


def serialize_report(row: GeneratedReport, evidence_ids: list[str] | None = None) -> dict:
    return {
        "report_id": row.report_id, "report_type": row.report_type,
        "framework": row.framework, "status": row.status,
        "protected": row.status in PROTECTED_REPORT_STATUSES,
        "generated_at": row.generated_at, "created_by": row.created_by,
        "file_path": row.file_path, "sha256": row.sha256,
        "size_bytes": row.size_bytes, "evidence_ids": evidence_ids or [],
    }


def register_report(db: Session, *, report_type: str, framework: str, actor: str,
                    content: bytes, extension: str, evidence_ids: list[str]) -> GeneratedReport:
    report_type = report_type.strip().lower()
    framework = framework.strip().lower()
    actor = (actor or "system").strip() or "system"
    if report_type not in {"pdf", "evidence_package"}:
        raise ValueError("Unsupported generated report type.")
    requested = sorted({value.strip() for value in evidence_ids if value and value.strip()})
    existing = {
        value for (value,) in db.query(Evidence.evidence_id)
        .filter(Evidence.evidence_id.in_(requested)).all()
    } if requested else set()
    missing = sorted(set(requested) - existing)
    if missing:
        raise ValueError(f"Report references unknown evidence IDs: {missing}")
    report_id = f"RPT-{uuid4().hex}"
    root = Path(settings.evidence_root) / "generated-reports" / framework
    root.mkdir(parents=True, exist_ok=True)
    target = root / f"{report_id}.{extension.lstrip('.')}"
    target.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    row = GeneratedReport(
        report_id=report_id, report_type=report_type, framework=framework,
        status="current", generated_at=datetime.now(timezone.utc), created_by=actor,
        file_path=str(target), sha256=digest, size_bytes=len(content),
    )
    db.add(row)
    db.flush()
    db.add_all([
        GeneratedReportEvidence(report_id=report_id, evidence_id=evidence_id)
        for evidence_id in requested
    ])
    audit(db, "generated_report_recorded", username=actor,
          detail={"report_id": report_id, "report_type": report_type,
                  "framework": framework, "evidence_count": len(requested), "sha256": digest})
    db.commit()
    db.refresh(row)
    write_changelog("generated_report_recorded", "compliance-dashboard",
                    f"Generated {report_type} report {report_id} was recorded.",
                    {"report_id": report_id, "report_type": report_type,
                     "framework": framework, "evidence_count": len(requested),
                     "sha256": digest, "actor_username": actor})
    return row


def update_status(db: Session, report_id: str, status: str, actor: str) -> GeneratedReport:
    status = status.strip().lower()
    if status not in REPORT_STATUSES:
        raise ValueError("Unsupported report status.")
    row = db.query(GeneratedReport).filter(GeneratedReport.report_id == report_id).first()
    if row is None:
        raise LookupError("Generated report not found.")
    if status == row.status:
        return row
    if status not in ALLOWED_TRANSITIONS[row.status]:
        raise ValueError(f"Report cannot transition from {row.status} to {status}.")
    previous = row.status
    row.status = status
    audit(db, "generated_report_status_changed", username=actor,
          detail={"report_id": report_id, "previous_status": previous, "status": status})
    db.commit()
    db.refresh(row)
    write_changelog("generated_report_status_changed", "compliance-dashboard",
                    f"Generated report {report_id} status changed from {previous} to {status}.",
                    {"report_id": report_id, "previous_status": previous,
                     "status": status, "actor_username": actor})
    return row


def protected_report_evidence_ids(db: Session) -> set[str]:
    return {
        value for (value,) in db.query(GeneratedReportEvidence.evidence_id)
        .join(GeneratedReport, GeneratedReport.report_id == GeneratedReportEvidence.report_id)
        .filter(GeneratedReport.status.in_(PROTECTED_REPORT_STATUSES)).distinct().all()
    }
