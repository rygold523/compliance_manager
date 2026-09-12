#!/usr/bin/env python3
import json
import sys

from app.api.changelog import reconcile_integrity
from app.core.database import SessionLocal


def main() -> int:
    db = SessionLocal()
    try:
        result = reconcile_integrity(db)
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    finally:
        db.close()

    print(json.dumps(result, default=str, sort_keys=True))
    return 0 if result["status"] == "healthy" else 2


if __name__ == "__main__":
    sys.exit(main())
