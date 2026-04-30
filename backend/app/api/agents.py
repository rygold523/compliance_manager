from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Asset, AgentDeployment
from app.schemas.schemas import AgentDeployRequest
from app.services.agent_deployer import deploy_agent
from app.services.remote_executor import run_ssh_command
from app.services.evidence_collectors import run_collector, COLLECTORS
from app.services.evidence_finding_analyzer import analyze_all_evidence
from app.models import Evidence, CollectorRun
from app.core.config import settings

from pathlib import Path
import json

router = APIRouter()


def run_initial_collection(db: Session, asset: Asset):
    results = []

    for collector_name in COLLECTORS.keys():
        run_id = f"COL-{uuid4().hex[:12].upper()}"
        output = run_collector(asset, collector_name)

        db.add(CollectorRun(
            run_id=run_id,
            asset_id=asset.asset_id,
            collector=collector_name,
            status=output["status"],
            output=output,
        ))

        evidence_id = f"EV-{uuid4().hex[:12].upper()}"
        evidence_dir = Path(settings.evidence_root) / asset.asset_id / collector_name
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = evidence_dir / f"{evidence_id}.json"
        evidence_path.write_text(json.dumps(output, indent=2, default=str))

        control_id = output.get("control_ids", [None])[0]

        db.add(Evidence(
            evidence_id=evidence_id,
            asset_id=asset.asset_id,
            control_id=control_id,
            filename=evidence_path.name,
            file_path=str(evidence_path),
            source="collector",
            description=f"Initial deployment collector output for {collector_name}",
            collector=collector_name,
            evidence_type=collector_name,
            frameworks=output.get("frameworks", {}),
            validated=output.get("status") == "completed",
        ))

        results.append({
            "run_id": run_id,
            "evidence_id": evidence_id,
            "collector": collector_name,
            "status": output["status"],
        })

    db.commit()

    finding_result = analyze_all_evidence(db)

    return {
        "collector_results": results,
        "finding_analysis": finding_result,
    }


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
        existing.hostname = payload.hostname
        existing.address = payload.address
        existing.environment = payload.environment
        existing.ssh_port = payload.port
        existing.compliance_scope = payload.compliance_scope
        existing.agent_status = result["status"]

    db.commit()
    db.refresh(existing)

    collection_result = None
    if result.get("status") in ["deployed", "upgraded:deployed"] or "deployed" in str(result.get("status", "")):
        collection_result = run_initial_collection(db, existing)

    return {
        "deployment_id": deployment_id,
        "asset_id": payload.asset_id,
        "status": result["status"],
        "message": "Agent deployed. Initial evidence collection and finding analysis completed." if collection_result else "Agent deployment did not complete successfully. Initial collection was not run.",
        "output": result.get("output", []),
        "initial_collection": collection_result,
    }


@router.put("/{asset_id}")
def update_agent_asset(asset_id: str, payload: AgentDeployRequest, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

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
        "message": "Agent metadata updated. Existing findings, evidence, and mappings remain linked by asset_id.",
    }


@router.post("/{asset_id}/upgrade")
def upgrade_agent(asset_id: str, payload: AgentDeployRequest, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

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
    db.refresh(asset)

    collection_result = None
    if result.get("status") in ["deployed", "upgraded:deployed"] or "deployed" in str(result.get("status", "")):
        collection_result = run_initial_collection(db, asset)

    return {
        "deployment_id": deployment_id,
        "asset_id": asset.asset_id,
        "status": result["status"],
        "message": "Agent upgraded. Existing findings, evidence, and mappings remain linked by asset_id. Evidence and findings were refreshed.",
        "output": result.get("output", []),
        "initial_collection": collection_result,
    }


@router.delete("/{asset_id}")
def remove_agent(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    result = run_ssh_command(
        host=asset.address,
        username=asset.ssh_user,
        command="sudo userdel compliance-agent",
        port=asset.ssh_port or 22,
    )

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
