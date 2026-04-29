from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.config import settings
from app.models import Asset, Approval, RemoteJob, RemoteJobLog
from app.schemas.schemas import RemoteCommandRequest
from app.services.approval_engine import validate_action_policy
from app.services.remote_executor import run_ssh_command, validate_command

router = APIRouter()

@router.post("/validate-command")
def validate_remote_command(payload: RemoteCommandRequest):
    allowed, reason = validate_command(payload.command)
    return {"allowed": allowed, "reason": reason}

@router.post("/run")
def run_remote_command(payload: RemoteCommandRequest, db: Session = Depends(get_db)):
    if not settings.remote_exec_enabled:
        raise HTTPException(status_code=403, detail="Remote execution disabled")
    asset = db.query(Asset).filter(Asset.asset_id == payload.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    allowed, reason = validate_action_policy(asset, payload.action_type)
    if not allowed:
        if not payload.approval_id:
            raise HTTPException(status_code=403, detail=reason)
        approval = db.query(Approval).filter(Approval.approval_id == payload.approval_id).first()
        if not approval or approval.status != "approved":
            raise HTTPException(status_code=403, detail=f"{reason}. Approved approval_id required.")

    job_id = f"JOB-{uuid4().hex[:12].upper()}"
    job = RemoteJob(job_id=job_id, asset_id=asset.asset_id, action_type=payload.action_type, status="running", approval_id=payload.approval_id)
    db.add(job); db.commit()
    result = run_ssh_command(asset.address, asset.ssh_user, payload.command, port=asset.ssh_port or 22)
    job.status = "completed" if result["exit_code"] == 0 else "failed"
    db.add(RemoteJobLog(job_id=job_id, command=payload.command, stdout=result.get("stdout",""), stderr=result.get("stderr",""), exit_code=result.get("exit_code")))
    db.commit()
    return {"job_id": job_id, "status": job.status, "result": result}
