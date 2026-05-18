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
    record = AgentDeployment(deployment_id=deployment_id, asset_id=payload.asset_id, hostname=payload.hostname, address=payload.address, username=payload.username, port=payload.port, status="running")
    db.add(record)
    db.commit()

    result = deploy_agent(payload.address, payload.username, payload.password, payload.port)
    record.status = result["status"]
    record.output = str(result.get("output", ""))

    existing = db.query(Asset).filter(Asset.asset_id == payload.asset_id).first()
    if not existing:
        existing = Asset(
            asset_id=payload.asset_id, hostname=payload.hostname, address=payload.address, environment=payload.environment,
            role=payload.role, os_family="ubuntu", access_method="ssh", ssh_user="compliance-agent", ssh_port=payload.port,
            approval_tier="production" if payload.environment == "production" else "nonproduction",
            compliance_scope=payload.compliance_scope,
            allowed_actions={"collect_inventory": True, "collect_logs": True, "check_packages": True, "update_unheld_packages": "approval_required", "service_reload": "approval_required", "docker_image_rebuilds": False},
            blocked_actions=["docker_image_rebuilds", "destructive_commands", "direct_database_changes", "arbitrary_shell"],
            agent_status=result["status"],
        )
        db.add(existing)
    else:
        existing.agent_status = result["status"]
        existing.address = payload.address
        existing.hostname = payload.hostname
        existing.environment = payload.environment
        existing.compliance_scope = payload.compliance_scope

    db.commit()
    return {"deployment_id": deployment_id, "status": result["status"], "output": result.get("output", [])}

@router.get("/deployments")
def deployments(db: Session = Depends(get_db)):
    return db.query(AgentDeployment).order_by(AgentDeployment.id.desc()).all()

@router.post("/{asset_id}/test")
def test_agent(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return run_ssh_command(asset.address, asset.ssh_user, "hostname", port=asset.ssh_port or 22)
