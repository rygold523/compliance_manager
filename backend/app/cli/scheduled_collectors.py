"""Run scheduled Linux collectors without traversing the authenticated HTTP API."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sys
import traceback
from typing import Any, Sequence

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models import Asset
from app.services.change_aware_evidence import record_collection
from app.services.evidence_collectors import COLLECTORS, run_collector


DEFAULT_COLLECTORS = (
    "iam_users",
    "user_changes",
    "auth_success",
    "auth_failure",
    "sudo_activity",
    "os_inventory",
    "firewall_status",
    "ssh_config",
    "disk_usage",
    "docker_inventory",
    "listening_ports",
    "package_inventory",
    "agent_lifecycle",
    "collector_health",
)


def _deployed_linux_assets(db: Session) -> list[Asset]:
    return [
        asset
        for asset in db.query(Asset).order_by(Asset.asset_id).all()
        if "deployed" in (asset.agent_status or "").lower()
        and (asset.os_family or "").strip().lower() != "windows"
    ]


def _collector_failure(
    asset: Asset,
    collector: str,
    exc: Exception,
) -> dict[str, Any]:
    return {
        "collector": collector,
        "asset_id": asset.asset_id,
        "status": "failed",
        "stderr": str(exc),
    }


def _validate_collectors(collectors: Sequence[str]) -> tuple[str, ...]:
    requested = tuple(dict.fromkeys(collectors))
    if not requested:
        raise ValueError("At least one collector is required")

    unknown = sorted(set(requested) - set(COLLECTORS))
    if unknown:
        raise ValueError(
            "Unknown collectors: " + ", ".join(unknown)
        )

    return requested


def run_scheduled_collections(
    db: Session,
    collectors: Sequence[str] = DEFAULT_COLLECTORS,
) -> dict[str, Any]:
    requested = _validate_collectors(collectors)
    assets = _deployed_linux_assets(db)
    all_results: list[dict[str, Any]] = []

    for asset in assets:
        asset_results: list[dict[str, Any]] = []

        for collector in requested:
            try:
                output = run_collector(asset, collector)
                if not isinstance(output, dict):
                    raise TypeError("Collector returned a non-dictionary result")
            except Exception as exc:
                traceback.print_exc(file=sys.stderr)
                output = _collector_failure(asset, collector, exc)

            if output.get("status") == "completed":
                asset.last_seen = datetime.now(timezone.utc)

            control_ids = output.get("control_ids") or []
            control_id = control_ids[0] if control_ids else None
            persisted = record_collection(
                db,
                asset_id=asset.asset_id,
                collector=collector,
                output=output,
                source="collector",
                control_id=control_id,
                frameworks=output.get("frameworks", {}),
                validated=output.get("status") == "completed",
                description=f"Scheduled collector output for {collector}",
            )

            asset_results.append({
                "run_id": persisted.run_id,
                "evidence_id": persisted.evidence_id,
                "collector": collector,
                "status": output.get("status", "failed"),
                "evidence_created": persisted.evidence_created,
                "change_detected": persisted.change_detected,
                "change_reason": persisted.reason,
            })

        all_results.append({
            "asset_id": asset.asset_id,
            "results": asset_results,
        })

    db.commit()
    return {
        "asset_id": "all",
        "asset_count": len(assets),
        "collectors": list(requested),
        "results": all_results,
    }


def _collectors_from_json(raw: str | None) -> tuple[str, ...]:
    if raw is None:
        return DEFAULT_COLLECTORS

    value = json.loads(raw)
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError("--collectors-json must be a JSON array of strings")
    return _validate_collectors(value)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run deployed Linux asset collectors internally.",
    )
    parser.add_argument(
        "--collectors-json",
        help="JSON array of collector names; defaults to the scheduled set.",
    )
    args = parser.parse_args()

    try:
        collectors = _collectors_from_json(args.collectors_json)
    except (ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    db = SessionLocal()
    try:
        result = run_scheduled_collections(db, collectors)
    except Exception:
        db.rollback()
        traceback.print_exc(file=sys.stderr)
        return 1
    finally:
        db.close()

    print(json.dumps(result, separators=(",", ":"), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
