from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Asset, AgentDeployment
from app.schemas.schemas import AgentDeployRequest
from app.services.agent_deployer import deploy_agent
from app.services.remote_executor import run_ssh_command

router = APIRouter()


@router.post("/deploy")
def deploy(payload: AgentDeployRequest, db: Session = Depends(get_db)):
    deployment_id = f"AGENT-{uuid4().hex[:12].upper()}"

    record = AgentDeployment(
        deployment_id=deployment_id,
        asset_id=payload.asset_id,
        hostname=payload.hostname,
        address=payload.address,
        username=payload.username,
        port=payload.port,
        status="running",
    )
    db.add(record)
    db.commit()

    result = deploy_agent(
        address=payload.address,
        username=payload.username,
        password=payload.password,
        port=payload.port,
    )

    record.status = result["status"]
    record.output = str(result.get("output", ""))

    existing = db.query(Asset).filter(Asset.asset_id == payload.asset_id).first()

    if not existing:
        existing = Asset(
            asset_id=payload.asset_id,
            hostname=payload.hostname,
            address=payload.address,
            environment=payload.environment,
            role=payload.role,
            os_family="ubuntu",
            access_method="ssh",
            ssh_user="compliance-agent",
            ssh_port=payload.port,
            approval_tier="production" if payload.environment == "production" else "nonproduction",
            compliance_scope=payload.compliance_scope,
            allowed_actions={
                "collect_inventory": True,
                "collect_logs": True,
                "collect_nginx_config": True,
                "check_packages": True,
                "update_unheld_packages": "approval_required",
                "stage_nginx_config": "approval_required",
                "apply_nginx_config": "approval_required",
                "service_reload": "approval_required",
                "docker_image_rebuilds": False,
            },
            blocked_actions=[
                "docker_image_rebuilds",
                "destructive_commands",
                "direct_database_changes",
                "arbitrary_shell",
            ],
            agent_status=result["status"],
        )
        db.add(existing)
    else:
        # Preserve asset_id so previous findings/evidence/mappings remain linked.
        existing.hostname = payload.hostname
        existing.address = payload.address
        existing.environment = payload.environment
        existing.ssh_port = payload.port
        existing.compliance_scope = payload.compliance_scope
        existing.agent_status = result["status"]

    db.commit()

    return {
        "deployment_id": deployment_id,
        "asset_id": payload.asset_id,
        "status": result["status"],
        "output": result.get("output", []),
    }


@router.put("/{asset_id}")
def update_agent_asset(asset_id: str, payload: AgentDeployRequest, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # This updates inventory/connection metadata only.
    # It does not delete evidence/findings/mappings.
    asset.hostname = payload.hostname
    asset.address = payload.address
    asset.environment = payload.environment
    asset.ssh_port = payload.port
    asset.compliance_scope = payload.compliance_scope
    asset.role = payload.role

    db.commit()
    db.refresh(asset)

    return {
        "status": "updated",
        "asset": asset,
    }


@router.post("/{asset_id}/upgrade")
def upgrade_agent(asset_id: str, payload: AgentDeployRequest, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Upgrade preserves asset_id. Existing evidence/findings remain mapped.
    result = deploy_agent(
        address=payload.address,
        username=payload.username,
        password=payload.password,
        port=payload.port,
    )

    asset.hostname = payload.hostname
    asset.address = payload.address
    asset.environment = payload.environment
    asset.ssh_port = payload.port
    asset.role = payload.role
    asset.compliance_scope = payload.compliance_scope
    asset.agent_status = f"upgraded:{result['status']}"

    deployment_id = f"AGENT-UPGRADE-{uuid4().hex[:12].upper()}"
    db.add(AgentDeployment(
        deployment_id=deployment_id,
        asset_id=asset.asset_id,
        hostname=payload.hostname,
        address=payload.address,
        username=payload.username,
        port=payload.port,
        status=result["status"],
        output=str(result.get("output", "")),
    ))

    db.commit()

    return {
        "deployment_id": deployment_id,
        "asset_id": asset.asset_id,
        "status": result["status"],
        "message": "Agent upgraded. Existing findings, evidence, and mappings remain linked by asset_id.",
        "output": result.get("output", []),
    }


@router.delete("/{asset_id}")
def remove_agent(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # This removes the agent from the target, but does not delete asset/evidence/findings.
    result = run_ssh_command(
        host=asset.address,
        username=asset.ssh_user,
        command="sudo userdel compliance-agent",
        port=asset.ssh_port or 22,
    )

    # The current command allowlist may block userdel, so we still update platform state
    # only if execution succeeds. If blocked, return the reason.
    if result.get("exit_code") != 0:
        return {
            "asset_id": asset.asset_id,
            "status": "remove_failed",
            "message": "Agent removal failed or was blocked by command policy. Evidence/findings were not deleted.",
            "result": result,
        }

    asset.agent_status = "removed"
    db.commit()

    return {
        "asset_id": asset.asset_id,
        "status": "removed",
        "message": "Agent removed from target. Asset, findings, evidence, and mappings were retained.",
        "result": result,
    }


@router.get("/deployments")
def deployments(db: Session = Depends(get_db)):
    return db.query(AgentDeployment).order_by(AgentDeployment.id.desc()).all()


@router.post("/{asset_id}/test")
def test_agent(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return run_ssh_command(
        host=asset.address,
        username=asset.ssh_user,
        command="hostname",
        port=asset.ssh_port or 22,
    )
