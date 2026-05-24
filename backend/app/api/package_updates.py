from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import re

from app.core.database import get_db
from app.models import Asset
from app.services.remote_executor import run_ssh_command
from app.api.changelog import write_changelog

router = APIRouter(prefix="/api/package-updates", tags=["package_updates"])


class PackageUpdateRequest(BaseModel):
    asset_id: str
    package_name: str
    was_held: bool = False


class BulkPackageUpdateRequest(BaseModel):
    asset_id: str
    include_held: bool = False


def validate_package_name(package_name: str) -> str:
    package_name = (package_name or "").strip()

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:-]*", package_name):
        raise HTTPException(status_code=400, detail="Invalid package name")

    return package_name


@router.post("/upgrade")
def upgrade_package(payload: PackageUpdateRequest, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == payload.asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    package = validate_package_name(payload.package_name)

    username = getattr(asset, "ssh_user", None) or getattr(asset, "username", None)
    port = getattr(asset, "ssh_port", None) or getattr(asset, "port", None) or 22

    if not username:
        raise HTTPException(status_code=400, detail="Asset has no SSH username configured")

    if payload.was_held:
        command = (
            f"sudo apt-mark unhold {package} && "
            f"sudo apt-get install --only-upgrade -y {package}; "
            f"sudo apt-mark hold {package}"
        )
    else:
        command = f"sudo apt-get install --only-upgrade -y {package}"

    result = run_ssh_command(
        host=asset.address,
        username=username,
        command=command,
        port=port,
        timeout=300,
    )

    write_changelog(
        event_type="package_update",
        asset_id=asset.asset_id,
        summary=f"Package update executed for {package}",
        details={
            "package_name": package,
            "was_held": payload.was_held,
            "command": command,
            "result": result,
        },
    )

    return {
        "asset_id": asset.asset_id,
        "package_name": package,
        "was_held": payload.was_held,
        "command": command,
        "result": result,
    }


@router.post("/upgrade-all")
def upgrade_all_packages(payload: BulkPackageUpdateRequest, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == payload.asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    username = getattr(asset, "ssh_user", None) or getattr(asset, "username", None)
    port = getattr(asset, "ssh_port", None) or getattr(asset, "port", None) or 22

    if not username:
        raise HTTPException(status_code=400, detail="Asset has no SSH username configured")

    if payload.include_held:
        command = (
            "HELD=$(apt-mark showhold); "
            "if [ -n \"$HELD\" ]; then sudo apt-mark unhold $HELD; fi; "
            "sudo apt-get upgrade -y; "
            "if [ -n \"$HELD\" ]; then sudo apt-mark hold $HELD; fi"
        )
    else:
        command = (
            "HELD=$(apt-mark showhold | tr '\\n' ' '); "
            "UPGRADES=$(apt list --upgradable 2>/dev/null "
            "| tail -n +2 "
            "| cut -d/ -f1 "
            "| awk -v held=\"$HELD\" "
            "'BEGIN { split(held,h,\" \"); for (i in h) skip[h[i]]=1 } !skip[$1] { print $1 }'); "
            "if [ -z \"$UPGRADES\" ]; then echo 'NO_NON_HELD_UPGRADES_AVAILABLE'; "
            "else sudo apt-get install --only-upgrade -y $UPGRADES; fi"
        )

    result = run_ssh_command(
        host=asset.address,
        username=username,
        command=command,
        port=port,
        timeout=1800,
    )

    success = result.get("exit_code") == 0

    write_changelog(
        event_type="bulk_package_update_success" if success else "bulk_package_update_failed",
        asset_id=asset.asset_id,
        summary=(
            "Bulk package update succeeded"
            if success
            else "Bulk package update failed"
        ),
        details={
            "include_held": payload.include_held,
            "command": command,
            "result": result,
        },
    )

    return {
        "asset_id": asset.asset_id,
        "include_held": payload.include_held,
        "success": success,
        "command": command,
        "result": result,
    }
