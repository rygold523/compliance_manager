import argparse
import json
from pathlib import Path

from app.core.config import settings
from app.core.database import SessionLocal
from app.services.evidence_retention_archive import create_archive
from app.services.evidence_retention_preview import PreviewPolicy


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Archive an unchanged, approved Changelog and evidence candidate set without deleting source data."
    )
    result.add_argument("--actor", required=True)
    result.add_argument("--approval-reference", required=True)
    result.add_argument("--candidate-fingerprint", required=True)
    result.add_argument("--changelog-days", type=int, default=settings.changelog_retention_days)
    result.add_argument("--validated-evidence-days", type=int, default=settings.validated_evidence_retention_days)
    result.add_argument("--unvalidated-evidence-days", type=int, default=settings.unvalidated_evidence_retention_days)
    result.add_argument("--evidence-root", default=settings.evidence_root)
    result.add_argument("--access-review-file", default="/app/evidence/access_reviews.json")
    result.add_argument("--archive-root", default=settings.evidence_retention_archive_root)
    result.add_argument("--legal-hold-file")
    return result


def main() -> int:
    args = parser().parse_args()
    db = SessionLocal()
    try:
        result = create_archive(
            db,
            PreviewPolicy(
                changelog_days=args.changelog_days,
                validated_evidence_days=args.validated_evidence_days,
                unvalidated_evidence_days=args.unvalidated_evidence_days,
            ),
            Path(args.evidence_root),
            Path(args.access_review_file),
            Path(args.archive_root),
            args.actor,
            args.approval_reference,
            args.candidate_fingerprint,
            legal_hold_file=Path(args.legal_hold_file) if args.legal_hold_file else None,
        )
    finally:
        db.close()
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
