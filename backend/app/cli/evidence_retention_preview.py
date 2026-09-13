import argparse
import json
from pathlib import Path

from app.core.config import settings
from app.core.database import SessionLocal
from app.services.evidence_retention_preview import PreviewPolicy, run_preview


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Preview Changelog and evidence retention candidates. This command cannot archive or delete data."
    )
    result.add_argument("--actor", required=True, help="Administrative username running the preview.")
    result.add_argument("--changelog-days", type=int, default=settings.changelog_retention_days)
    result.add_argument("--validated-evidence-days", type=int, default=settings.validated_evidence_retention_days)
    result.add_argument("--unvalidated-evidence-days", type=int, default=settings.unvalidated_evidence_retention_days)
    result.add_argument("--evidence-root", default=settings.evidence_root)
    result.add_argument("--access-review-file", default="/app/evidence/access_reviews.json")
    result.add_argument(
        "--legal-hold-file",
        help="Optional JSON hold inventory. If specified, a missing or malformed file fails closed.",
    )
    result.add_argument("--output", help="Optional path for the complete JSON preview report.")
    return result


def main() -> int:
    args = parser().parse_args()
    db = SessionLocal()
    try:
        result = run_preview(
            db,
            PreviewPolicy(
                changelog_days=args.changelog_days,
                validated_evidence_days=args.validated_evidence_days,
                unvalidated_evidence_days=args.unvalidated_evidence_days,
            ),
            Path(args.evidence_root),
            Path(args.access_review_file),
            args.actor,
            Path(args.legal_hold_file) if args.legal_hold_file else None,
        )
    finally:
        db.close()
    rendered = json.dumps(result, indent=2, sort_keys=True, default=str) + "\n"
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
