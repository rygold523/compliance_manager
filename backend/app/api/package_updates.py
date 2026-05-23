from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import re

from app.core.database import get_db
from app.models import Asset
from app.services.remote_executor import run_ssh_command

router = APIRouter(prefix="/api/package-updates", tags=["package_updates"])


class PackageUpdateRequest(BaseModel):
    asset_id: str
    package_name: str
    was_held: bool = False


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

    return {
        "asset_id": asset.asset_id,
        "package_name": package,
        "was_held": payload.was_held,
        "command": command,
        "result": result,
    }
