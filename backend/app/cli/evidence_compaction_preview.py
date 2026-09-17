import argparse
import json
from pathlib import Path

from app.core.database import SessionLocal
from app.services.evidence_compaction_preview import preview_compaction


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Preview duplicate evidence snapshots. This command cannot delete data."
    )
    parser.add_argument("--output", help="Optional JSON report path")
    args = parser.parse_args()
    with SessionLocal() as db:
        result = preview_compaction(db)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
