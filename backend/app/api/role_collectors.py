from datetime import datetime, timezone
from uuid import uuid4
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Asset, Evidence
from app.services.role_collector_profiles import collector_plan_for_asset
from app.services.ssh_host_keys import configured_ssh_client

router = APIRouter(prefix="/api/role-collectors", tags=["role-collectors"])


def now():
    return datetime.now(timezone.utc)


def evidence_id():
    return f"EV-{uuid4().hex[:12].upper()}"


def run_ssh_command(asset, command, password=None):
    username = asset.ssh_user or "compliance-agent"
    port = asset.ssh_port or 22

    client = configured_ssh_client()

    try:
        client.connect(
            asset.address,
            username=username,
            password=password,
            port=port,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
        )

        stdin, stdout, stderr = client.exec_command(command, timeout=60)

        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")

        exit_status = stdout.channel.recv_exit_status()

        return {
            "exit_status": exit_status,
            "stdout": out,
            "stderr": err,
        }
    finally:
        client.close()


def save_collector_evidence(db, asset, collector, result):
    raw_payload = {
        "collector": collector["collector"],
        "collector_label": collector.get("label"),
        "collector_role": collector.get("role"),
        "asset_id": asset.asset_id,
        "asset_roles": asset.asset_roles or [],
        "data_classification": asset.data_classification or [],
        "control_ids": collector.get("control_ids", []),
        "command": collector.get("command"),
        "result": result,
        "collected_at": now().isoformat(),
    }

    combined_output = (
        (result.get("stdout") or "")
        + "\n"
        + (result.get("stderr") or "")
    )

    validated = (
        result.get("exit_status") == 0
        and "missing" not in combined_output.lower()
        and "authentication failed" not in combined_output.lower()
    )

    primary_control = (collector.get("control_ids") or ["UNMAPPED"])[0]

    columns = set(Evidence.__table__.columns.keys())

    kwargs = {}

    def set_if_column(name, value):
        if name in columns:
            kwargs[name] = value

    set_if_column("evidence_id", evidence_id())
    set_if_column("asset_id", asset.asset_id)
    set_if_column("collector", collector["collector"])
    set_if_column("source", collector["collector"])
    set_if_column("control_id", primary_control)
    set_if_column("control", primary_control)
    set_if_column("framework", "multi")
    synthetic_filename = (
        f"{collector['collector']}_"
        f"{asset.asset_id}_"
        f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    )

    synthetic_path = (
        f"/var/lib/ai-vulnerability-management/evidence/"
        f"{asset.asset_id}/"
        f"{collector['collector']}/"
        f"{synthetic_filename}"
    )

    set_if_column("filename", synthetic_filename)
    set_if_column("file_path", synthetic_path)
    set_if_column("evidence_type", "collector_output")
    
    set_if_column(
        "frameworks",
        ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"]
    )
    set_if_column(
        "description",
        f"Role-aware collector evidence: {collector.get('label') or collector['collector']}"
    )
    set_if_column("validated", validated)
    set_if_column("status", "valid" if validated else "invalid")
    set_if_column("collected_at", now())
    set_if_column("created_at", now())
    set_if_column("updated_at", now())

    if "evidence_data" in columns:
        kwargs["evidence_data"] = raw_payload
    elif "data" in columns:
        kwargs["data"] = raw_payload
    elif "metadata" in columns:
        kwargs["metadata"] = raw_payload
    elif "details" in columns:
        kwargs["details"] = raw_payload
    elif "output" in columns:
        kwargs["output"] = json.dumps(raw_payload, default=str)
    elif "content" in columns:
        kwargs["content"] = json.dumps(raw_payload, default=str)

    ev = Evidence(**kwargs)

    db.add(ev)

    return ev

@router.get("/{asset_id}/plan")
def get_role_collector_plan(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return {
        "asset_id": asset.asset_id,
        "asset_roles": asset.asset_roles or [],
        "data_classification": asset.data_classification or [],
        "collectors": collector_plan_for_asset(asset),
    }


@router.get("/")
def list_role_collector_plans(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()

    return [
        {
            "asset_id": asset.asset_id,
            "asset_roles": asset.asset_roles or [],
            "data_classification": asset.data_classification or [],
            "collector_count": len(collector_plan_for_asset(asset)),
            "collectors": collector_plan_for_asset(asset),
        }
        for asset in assets
    ]


@router.post("/{asset_id}/run")
def run_role_collectors(asset_id: str, payload: dict | None = None, db: Session = Depends(get_db)):
    payload = payload or {}

    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    password = payload.get("password")
    requested_collectors = payload.get("collectors") or []

    plan = collector_plan_for_asset(asset)

    if requested_collectors:
        requested = set(requested_collectors)
        plan = [item for item in plan if item["collector"] in requested]

    results = []

    for collector in plan:
        try:
            result = run_ssh_command(asset, collector["command"], password=password)
            ev = save_collector_evidence(db, asset, collector, result)

            results.append({
                "collector": collector["collector"],
                "label": collector.get("label"),
                "role": collector.get("role"),
                "status": "completed",
                "validated": ev.validated,
                "evidence_id": ev.evidence_id,
            })
        except Exception as exc:
            result = {
                "exit_status": 1,
                "stdout": "",
                "stderr": str(exc),
            }

            ev = save_collector_evidence(db, asset, collector, result)

            results.append({
                "collector": collector["collector"],
                "label": collector.get("label"),
                "role": collector.get("role"),
                "status": "failed",
                "validated": False,
                "evidence_id": ev.evidence_id,
                "error": str(exc),
            })

    db.commit()

    return {
        "asset_id": asset.asset_id,
        "asset_roles": asset.asset_roles or [],
        "collector_count": len(plan),
        "results": results,
    }
