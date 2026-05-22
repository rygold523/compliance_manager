from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Asset, Evidence

router = APIRouter(prefix="/api/collector-coverage", tags=["collector-coverage"])


REQUIRED_ENVIRONMENT_COLLECTORS = {
    "duo_mfa_linux": {
        "control_id": "AC-01",
        "title": "Duo MFA Linux Presence",
        "description": "Validates whether Duo MFA/PAM evidence has been collected from each managed Linux asset.",
        "frameworks": ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"],
    },
    "automox_amagent": {
        "control_id": "VM-02",
        "title": "Automox Agent Presence",
        "description": "Validates whether Automox agent evidence has been collected from each managed Linux asset.",
        "frameworks": ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"],
    },
    "trend_micro_ds_agent": {
        "control_id": "SI-03",
        "title": "Trend Micro Deep Security Agent Presence",
        "description": "Validates whether Trend Micro agent evidence has been collected from each managed Linux asset.",
        "frameworks": ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"],
    },
}


def _is_managed_asset(asset):
    status = getattr(asset, "agent_status", None) or ""

    return (
        "deployed" in status
        and getattr(asset, "asset_id", None)
    )


def _latest_evidence_for_asset_collector(db: Session, asset_id: str, collector: str):
    return (
        db.query(Evidence)
        .filter(Evidence.asset_id == asset_id)
        .filter(Evidence.collector == collector)
        .order_by(Evidence.id.desc())
        .first()
    )


@router.get("/")
def collector_coverage(db: Session = Depends(get_db)):
    assets = [
        asset
        for asset in db.query(Asset).all()
        if _is_managed_asset(asset)
    ]

    results = []

    for collector, definition in REQUIRED_ENVIRONMENT_COLLECTORS.items():
        covered_assets = []
        missing_assets = []
        failed_assets = []
        asset_results = []

        for asset in assets:
            latest = _latest_evidence_for_asset_collector(
                db,
                asset.asset_id,
                collector,
            )

            if latest is None:
                missing_assets.append(asset.asset_id)
                asset_results.append({
                    "asset_id": asset.asset_id,
                    "hostname": asset.hostname,
                    "address": asset.address,
                    "status": "missing_collector_run",
                    "evidence_id": None,
                    "validated": None,
                    "created_at": None,
                })
                continue

            if bool(latest.validated):
                covered_assets.append(asset.asset_id)
                status = "covered"
            else:
                failed_assets.append(asset.asset_id)
                status = "collector_ran_not_validated"

            asset_results.append({
                "asset_id": asset.asset_id,
                "hostname": asset.hostname,
                "address": asset.address,
                "status": status,
                "evidence_id": latest.evidence_id,
                "validated": latest.validated,
                "created_at": latest.created_at,
            })

        if missing_assets:
            status = "coverage_gap"
        elif failed_assets:
            status = "collector_failures"
        else:
            status = "covered"

        results.append({
            "collector": collector,
            "title": definition["title"],
            "description": definition["description"],
            "control_id": definition["control_id"],
            "frameworks": definition["frameworks"],
            "required_on": [asset.asset_id for asset in assets],
            "covered_assets": covered_assets,
            "missing_assets": missing_assets,
            "failed_assets": failed_assets,
            "status": status,
            "asset_results": asset_results,
        })

    return {
        "total_collectors": len(results),
        "managed_asset_count": len(assets),
        "summary": {
            "covered": len([r for r in results if r["status"] == "covered"]),
            "coverage_gap": len([r for r in results if r["status"] == "coverage_gap"]),
            "collector_failures": len([r for r in results if r["status"] == "collector_failures"]),
        },
        "collectors": results,
    }
