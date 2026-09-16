from uuid import uuid4
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.services.agent_post_deploy import post_deploy_linux_agent_setup
from app.core.database import get_db
from app.models import Asset, AgentDeployment
from app.schemas.schemas import AgentDeployRequest
from app.services.agent_deployer import deploy_agent
from app.services.asset_roles import normalize_asset_roles
from app.services.remote_executor import run_ssh_command
from app.services.evidence_collectors import run_collector, COLLECTORS
from app.services.evidence_finding_analyzer import analyze_all_evidence
from app.models import Evidence, CollectorRun
from app.core.config import settings
from app.api.changelog import write_changelog
from app.services.windows_agent_credentials import (
    issue_credential,
    revoke_credential,
    revoke_other_credentials,
)

from pathlib import Path
import json

router = APIRouter()


def provision_windows_credential(db: Session, os_family: str, asset_id: str):
    if os_family.strip().lower() != "windows":
        return None, "", ""
    record, token = issue_credential(db, asset_id)
    return record, token, record.credential_id


def run_initial_collection(db: Session, asset: Asset):
    results = []

    for collector_name in COLLECTORS.keys():
        run_id = f"COL-{uuid4().hex[:12].upper()}"
        output = run_collector(asset, collector_name)

        if output.get("status") == "completed":
            asset.last_seen = datetime.now(timezone.utc)

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



def windows_bootstrap_script(asset_id: str, backend_url: str = "http://localhost:8000") -> str:
    return f"""powershell -NoProfile -ExecutionPolicy Bypass -Command "New-Item -ItemType Directory -Force -Path C:\\ProgramData\\ComplianceAgent | Out-Null"
# Copy scripts/bootstrap_windows_managed_target.ps1 to the Windows host, then run:
powershell -NoProfile -ExecutionPolicy Bypass -File C:\\ProgramData\\ComplianceAgent\\bootstrap_windows_managed_target.ps1 -BackendUrl '{backend_url}' -AssetId '{asset_id}'
"""

def deployment_username(
    username: str,
    hostname: str,
    os_family: str,
) -> str:
    normalized_username = username.strip()

    if os_family.strip().lower() != "windows":
        return normalized_username

    if (
        "\\" in normalized_username
        or "@" in normalized_username
    ):
        return normalized_username

    normalized_hostname = hostname.strip()

    if not normalized_hostname:
        return normalized_username

    return (
        f"{normalized_hostname}\\"
        f"{normalized_username}"
    )


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

    staged_windows_asset = None
    if payload.os_family.strip().lower() == "windows":
        staged_windows_asset = db.query(Asset).filter(
            Asset.asset_id == payload.asset_id
        ).one_or_none()
        if staged_windows_asset is None:
            staged_windows_asset = Asset(
                asset_id=payload.asset_id,
                hostname=payload.hostname,
                address=payload.address,
                environment=payload.environment,
                role=payload.role,
                asset_roles=normalize_asset_roles(
                    getattr(payload, "asset_roles", [])
                ),
                data_classification=getattr(payload, "data_classification", []),
                os_family="windows",
                access_method="winrm",
                ssh_user="",
                ssh_port=payload.port,
                approval_tier=(
                    "production"
                    if payload.environment == "production"
                    else "nonproduction"
                ),
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
                agent_status="deploying",
            )
            db.add(staged_windows_asset)
            db.commit()

    credential, ingest_token, credential_id = provision_windows_credential(
        db, payload.os_family, payload.asset_id
    )
    result = deploy_agent(
        address=payload.address,
        username=deployment_username(
            payload.username,
            payload.hostname,
            payload.os_family,
        ),
        password=payload.password,
        port=payload.port,
        os_family=payload.os_family,
        asset_id=payload.asset_id,
        backend_url=settings.public_backend_url,
        ingest_token=(ingest_token or settings.windows_agent_ingest_token),
        credential_id=credential_id,
    )

    record.status = result["status"]
    record.output = str(result.get("output", ""))

    if result.get("status") != "deployed":
        if credential is not None:
            revoke_credential(db, credential.credential_id)
        if (
            staged_windows_asset is not None
            and staged_windows_asset.agent_status == "deploying"
        ):
            db.delete(staged_windows_asset)
        db.commit()

        return {
            "deployment_id": deployment_id,
            "asset_id": payload.asset_id,
            "status": result.get("status", "failed"),
            "message": (
                "Agent deployment failed. No asset "
                "record was created."
            ),
            "output": result.get("output", []),
            "initial_collection": None,
        }

    existing = db.query(Asset).filter(Asset.asset_id == payload.asset_id).first()

    if not existing:
        existing = Asset(
            asset_id=payload.asset_id,
            hostname=payload.hostname,
            address=payload.address,
            environment=payload.environment,
            role=payload.role,
            asset_roles=normalize_asset_roles(getattr(payload, 'asset_roles', [])),
            data_classification=getattr(payload, 'data_classification', []),
            os_family=payload.os_family.lower(),
            access_method=(
                "winrm"
                if payload.os_family.lower() == "windows"
                else "ssh"
            ),
            ssh_user=(
                ""
                if payload.os_family.lower() == "windows"
                else "compliance-agent"
            ),
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
        existing.os_family = payload.os_family.lower()
        existing.access_method = (
            "winrm"
            if payload.os_family.lower() == "windows"
            else "ssh"
        )
        existing.ssh_user = (
            ""
            if payload.os_family.lower() == "windows"
            else "compliance-agent"
        )
        existing.ssh_port = payload.port
        existing.compliance_scope = payload.compliance_scope
        existing.asset_roles = normalize_asset_roles(getattr(payload, 'asset_roles', []))
        existing.data_classification = getattr(payload, 'data_classification', [])
        existing.agent_status = result["status"]

    db.commit()
    db.refresh(existing)

    if credential is not None:
        revoke_other_credentials(db, payload.asset_id, credential.credential_id)

    deployment_succeeded = (
        "deployed"
        in str(
            result.get("status", "")
        ).lower()
    )

    if deployment_succeeded:
        write_changelog(
            event_type="agent_deployed",
            asset_id=existing.asset_id,
            summary=(
                f"Compliance agent deployed successfully "
                f"to {existing.hostname or existing.asset_id}."
            ),
            details={
                "deployment_id": deployment_id,
                "hostname": existing.hostname,
                "address": existing.address,
                "environment": existing.environment,
                "status": result.get("status"),
            },
        )

    collection_result = None
    if (
        deployment_succeeded
        and payload.os_family.lower() != "windows"
    ):
        collection_result = run_initial_collection(
            db,
            existing,
        )

    return {
        "deployment_id": deployment_id,
        "asset_id": payload.asset_id,
        "status": result["status"],
        "message": (
            "Windows agent deployed successfully. "
            "Evidence will be submitted by the "
            "scheduled Windows collector."
            if (
                deployment_succeeded
                and payload.os_family.lower()
                == "windows"
            )
            else (
                "Agent deployed. Initial evidence "
                "collection and finding analysis "
                "completed."
                if collection_result
                else (
                    "Agent deployment did not complete "
                    "successfully. Initial collection "
                    "was not run."
                )
            )
        ),
        "output": result.get("output", []),
        "initial_collection": collection_result,
    }



@router.patch("/{asset_id}/classification")
def update_asset_classification(asset_id: str, payload: dict, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset.asset_roles = normalize_asset_roles(payload.get("asset_roles", []))
    asset.data_classification = payload.get("data_classification", [])

    db.commit()
    db.refresh(asset)


    # AUTO_INITIAL_BASELINE_COLLECTION
    if (asset.os_family or "").lower() != "windows":
        try:
            post_deploy_linux_agent_setup(asset)
        except Exception as exc:
            print(
                "Initial baseline collection failed for "
                f"{asset.asset_id}: {exc}"
            )

    return {
        "status": "updated",
        "asset_id": asset.asset_id,
        "asset_roles": asset.asset_roles or [],
        "data_classification": asset.data_classification or [],
    }


@router.put("/{asset_id}")
def update_agent_asset(asset_id: str, payload: AgentDeployRequest, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset.hostname = payload.hostname
    asset.address = payload.address
    asset.environment = payload.environment
    asset.os_family = payload.os_family.lower()
    asset.access_method = (
        "winrm"
        if payload.os_family.lower() == "windows"
        else "ssh"
    )
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

    credential, ingest_token, credential_id = provision_windows_credential(
        db, payload.os_family, asset.asset_id
    )
    result = deploy_agent(
        address=payload.address,
        username=deployment_username(
            payload.username,
            payload.hostname,
            payload.os_family,
        ),
        password=payload.password,
        port=payload.port,
        os_family=payload.os_family,
        asset_id=asset.asset_id,
        backend_url=settings.public_backend_url,
        ingest_token=(ingest_token or settings.windows_agent_ingest_token),
        credential_id=credential_id,
    )

    asset.hostname = payload.hostname
    asset.address = payload.address
    asset.environment = payload.environment
    asset.os_family = payload.os_family.lower()
    asset.access_method = (
        "winrm"
        if payload.os_family.lower() == "windows"
        else "ssh"
    )
    asset.ssh_user = (
        ""
        if payload.os_family.lower() == "windows"
        else "compliance-agent"
    )
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

    upgrade_succeeded = (
        "deployed"
        in str(
            result.get("status", "")
        ).lower()
    )

    if credential is not None:
        if upgrade_succeeded:
            revoke_other_credentials(db, asset.asset_id, credential.credential_id)
        else:
            revoke_credential(db, credential.credential_id)

    if upgrade_succeeded:
        write_changelog(
            event_type="agent_upgraded",
            asset_id=asset.asset_id,
            summary=(
                f"Compliance agent upgraded successfully "
                f"on {asset.hostname or asset.asset_id}."
            ),
            details={
                "deployment_id": deployment_id,
                "hostname": asset.hostname,
                "address": asset.address,
                "environment": asset.environment,
                "status": result.get("status"),
            },
        )

    collection_result = None
    if (
        upgrade_succeeded
        and payload.os_family.lower() != "windows"
    ):
        collection_result = run_initial_collection(
            db,
            asset,
        )

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

    if (
        asset.agent_status or ""
    ).lower() in {
        "failed",
        "not_deployed",
        "remove_failed",
    }:
        removed_asset_id = asset.asset_id
        removed_hostname = asset.hostname
        removed_address = asset.address
        removed_environment = asset.environment

        db.delete(asset)
        db.commit()

        write_changelog(
            event_type="failed_agent_record_removed",
            asset_id=removed_asset_id,
            summary=(
                "Failed agent record removed for "
                f"{removed_hostname or removed_asset_id}."
            ),
            details={
                "hostname": removed_hostname,
                "address": removed_address,
                "environment": removed_environment,
                "previous_status": "failed",
            },
        )

        return {
            "asset_id": removed_asset_id,
            "status": "removed",
            "message": (
                "Failed deployment record removed. "
                "No remote removal was required."
            ),
            "result": None,
        }

    result = run_ssh_command(
        host=asset.address,
        username=asset.ssh_user,
        command=(
            "sudo /usr/local/sbin/"
            "compliance-agent-command remove-agent"
        ),
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

    write_changelog(
        event_type="agent_removed",
        asset_id=asset.asset_id,
        summary=(
            f"Compliance agent removed successfully "
            f"from {asset.hostname or asset.asset_id}."
        ),
        details={
            "hostname": asset.hostname,
            "address": asset.address,
            "environment": asset.environment,
            "status": "removed",
        },
    )

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
