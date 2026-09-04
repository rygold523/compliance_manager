import re

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.changelog import write_changelog
from app.core.database import get_db
from app.models import Asset
from app.services.remote_executor import (
    BULK_EXCLUDE_HELD_COMMAND,
    BULK_INCLUDE_HELD_COMMAND,
    PACKAGE_MANAGER_PATH,
    run_ssh_command,
)


router = APIRouter(
    prefix="/api/package-updates",
    tags=["package_updates"],
)


class PackageUpdateRequest(BaseModel):
    asset_id: str
    package_name: str
    was_held: bool = False


class BulkPackageUpdateRequest(BaseModel):
    asset_id: str
    include_held: bool = False


def validate_package_name(
    package_name: str,
) -> str:
    package_name = (
        package_name
        or ""
    ).strip()

    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9+_.:-]*",
        package_name,
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid package name",
        )

    return package_name


def get_asset_connection(
    asset: Asset,
) -> tuple[str, int]:
    username = (
        getattr(
            asset,
            "ssh_user",
            None,
        )
        or getattr(
            asset,
            "username",
            None,
        )
    )

    port = (
        getattr(
            asset,
            "ssh_port",
            None,
        )
        or getattr(
            asset,
            "port",
            None,
        )
        or 22
    )

    if not username:
        raise HTTPException(
            status_code=400,
            detail=(
                "Asset has no SSH username "
                "configured"
            ),
        )

    return username, port


def failure_message(
    result: dict,
    operation: str,
) -> str:
    reason = (
        result.get("stderr")
        or result.get("reason")
        or result.get("stdout")
        or "Unknown remote execution failure"
    )

    return (
        f"{operation} failed with exit code "
        f"{result.get('exit_code')}: "
        f"{str(reason).strip()[:1000]}"
    )


@router.post("/upgrade")
def upgrade_package(
    payload: PackageUpdateRequest,
    db: Session = Depends(get_db),
):
    asset = (
        db.query(Asset)
        .filter(
            Asset.asset_id
            == payload.asset_id
        )
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found",
        )

    package = validate_package_name(
        payload.package_name
    )

    username, port = get_asset_connection(
        asset
    )

    action = (
        "upgrade-held"
        if payload.was_held
        else "upgrade"
    )

    command = (
        f"sudo {PACKAGE_MANAGER_PATH} "
        f"{action} {package}"
    )

    result = run_ssh_command(
        host=asset.address,
        username=username,
        command=command,
        port=port,
        timeout=300,
    )

    success = (
        result.get("exit_code")
        == 0
    )

    write_changelog(
        event_type=(
            "package_update_success"
            if success
            else "package_update_failed"
        ),
        asset_id=asset.asset_id,
        summary=(
            f"Package update succeeded for {package}"
            if success
            else f"Package update failed for {package}"
        ),
        details={
            "package_name": package,
            "was_held": payload.was_held,
            "command": command,
            "result": result,
        },
    )

    if not success:
        raise HTTPException(
            status_code=502,
            detail=failure_message(
                result,
                f"Package update for {package}",
            ),
        )

    return {
        "asset_id": asset.asset_id,
        "package_name": package,
        "was_held": payload.was_held,
        "success": True,
        "command": command,
        "result": result,
    }


@router.post("/upgrade-all")
def upgrade_all_packages(
    payload: BulkPackageUpdateRequest,
    db: Session = Depends(get_db),
):
    asset = (
        db.query(Asset)
        .filter(
            Asset.asset_id
            == payload.asset_id
        )
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found",
        )

    username, port = get_asset_connection(
        asset
    )

    command = (
        BULK_INCLUDE_HELD_COMMAND
        if payload.include_held
        else BULK_EXCLUDE_HELD_COMMAND
    )

    result = run_ssh_command(
        host=asset.address,
        username=username,
        command=command,
        port=port,
        timeout=1800,
    )

    success = (
        result.get("exit_code")
        == 0
    )

    write_changelog(
        event_type=(
            "bulk_package_update_success"
            if success
            else "bulk_package_update_failed"
        ),
        asset_id=asset.asset_id,
        summary=(
            "Bulk package update succeeded"
            if success
            else "Bulk package update failed"
        ),
        details={
            "include_held": (
                payload.include_held
            ),
            "command": command,
            "result": result,
        },
    )

    if not success:
        raise HTTPException(
            status_code=502,
            detail=failure_message(
                result,
                "Bulk package update",
            ),
        )

    return {
        "asset_id": asset.asset_id,
        "include_held": (
            payload.include_held
        ),
        "success": True,
        "command": command,
        "result": result,
    }
