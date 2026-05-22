from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import Asset, Evidence

router = APIRouter(prefix="/api/asset-details", tags=["asset-details"])


def _latest_evidence(db, asset_id, collector):
    return (
        db.query(Evidence)
        .filter(Evidence.asset_id == asset_id)
        .filter(Evidence.collector == collector)
        .order_by(Evidence.id.desc())
        .first()
    )


def _read_output(ev):
    if not ev:
        return ""

    try:
        import json
        with open(ev.file_path, "r") as f:
            data = json.load(f)
        return data.get("stdout") or data.get("output") or data.get("raw_output") or ""
    except Exception:
        return ""


def _parse_os_release(output):
    result = {
        "os_name": "Unknown",
        "os_version": "Unknown",
        "kernel_version": "Unknown",
    }

    for line in str(output).splitlines():
        if line.startswith("PRETTY_NAME="):
            result["os_name"] = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("VERSION_ID="):
            result["os_version"] = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("KERNEL_VERSION="):
            result["kernel_version"] = line.split("=", 1)[1].strip().strip('"')

    return result


def _parse_dpkg(output):
    packages = []

    for line in str(output).splitlines():
        if not line.startswith("ii "):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        packages.append({
            "name": parts[1],
            "installed_version": parts[2],
            "latest_candidate": "Latest version information not available",
            "update_available": "unknown",
        })

    return packages


def _parse_apt_policy(output):
    package_map = {}

    current = None

    for raw in str(output).splitlines():
        line = raw.rstrip()

        if line and not line.startswith(" ") and line.endswith(":"):
            current = line[:-1]
            package_map[current] = {
                "candidate": "Latest version information not available",
                "installed": None,
            }
            continue

        if not current:
            continue

        stripped = line.strip()

        if stripped.startswith("Installed:"):
            package_map[current]["installed"] = stripped.split(":", 1)[1].strip()

        if stripped.startswith("Candidate:"):
            package_map[current]["candidate"] = stripped.split(":", 1)[1].strip()

    return package_map


def _merge_package_status(packages, apt_policy):
    merged = []

    for pkg in packages:
        info = apt_policy.get(pkg["name"], {})
        candidate = info.get("candidate") or "Latest version information not available"
        installed = pkg["installed_version"]

        if candidate == "Latest version information not available":
            update_available = "unknown"
        elif candidate == installed:
            update_available = "no"
        else:
            update_available = "yes"

        merged.append({
            "name": pkg["name"],
            "installed_version": installed,
            "latest_candidate": candidate,
            "update_available": update_available,
        })

    return merged


@router.get("/")
def list_asset_details(db: Session = Depends(get_db)):
    results = []

    for asset in db.query(Asset).all():
        os_ev = _latest_evidence(db, asset.asset_id, "os_inventory")
        packages_ev = _latest_evidence(db, asset.asset_id, "packages")
        apt_policy_ev = _latest_evidence(db, asset.asset_id, "apt_policy")

        os_info = _parse_os_release(_read_output(os_ev))
        packages = _parse_dpkg(_read_output(packages_ev))
        apt_policy = _parse_apt_policy(_read_output(apt_policy_ev))
        package_status = _merge_package_status(packages, apt_policy)

        results.append({
            "asset_id": asset.asset_id,
            "hostname": asset.hostname,
            "address": asset.address,
            "environment": asset.environment,
            "agent_status": asset.agent_status,
            "os_family": getattr(asset, "os_family", None) or "linux",
            "os_name": os_info["os_name"],
            "os_version": os_info["os_version"],
            "kernel_version": os_info["kernel_version"],
            "package_count": len(package_status),
            "packages_with_updates": len([p for p in package_status if p["update_available"] == "yes"]),
            "packages_unknown_latest": len([p for p in package_status if p["update_available"] == "unknown"]),
            "packages": package_status,
        })

    return {
        "asset_count": len(results),
        "assets": results,
    }
