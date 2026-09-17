"""Read-only preview of redundant historical evidence snapshots."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.models import AssessmentEvidence, Evidence, GeneratedReportEvidence
from app.services.change_aware_evidence import evidence_hash


def preview_compaction(db: Session) -> dict:
    assessment_links = {
        value for (value,) in db.query(AssessmentEvidence.evidence_id).all()
    }
    report_links = {
        value for (value,) in db.query(GeneratedReportEvidence.evidence_id).all()
    }
    protected_links = assessment_links | report_links

    rows = db.query(Evidence).order_by(
        Evidence.asset_id, Evidence.collector, Evidence.created_at, Evidence.id
    ).all()
    latest_by_key: dict[tuple[str | None, str | None], int] = {}
    for row in rows:
        latest_by_key[(row.asset_id, row.collector)] = row.id

    previous_hash: dict[tuple[str | None, str | None], str] = {}
    candidates = []
    unreadable = []
    bytes_reclaimable = 0

    for row in rows:
        key = (row.asset_id, row.collector)
        try:
            path = Path(row.file_path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("evidence JSON is not an object")
            digest = row.baseline_hash or evidence_hash(payload)
            size = path.stat().st_size
        except (OSError, ValueError, TypeError) as exc:
            unreadable.append({"evidence_id": row.evidence_id, "error": str(exc)})
            previous_hash.pop(key, None)
            continue

        is_duplicate = previous_hash.get(key) == digest
        previous_hash[key] = digest
        protected_reasons = []
        if row.id == latest_by_key[key]:
            protected_reasons.append("latest_snapshot")
        if row.evidence_id in protected_links:
            protected_reasons.append("assessment_or_report_reference")
        if row.finding_id:
            protected_reasons.append("finding_reference")

        if is_duplicate and not protected_reasons:
            bytes_reclaimable += size
            candidates.append({
                "evidence_id": row.evidence_id,
                "asset_id": row.asset_id,
                "collector": row.collector,
                "created_at": str(row.created_at),
                "size_bytes": size,
                "baseline_hash": digest,
                "file_path": row.file_path,
            })

    return {
        "mode": "preview_only",
        "deletion_performed": False,
        "evidence_rows_scanned": len(rows),
        "duplicate_candidates": len(candidates),
        "bytes_reclaimable": bytes_reclaimable,
        "unreadable_records": unreadable,
        "candidates": candidates,
    }
