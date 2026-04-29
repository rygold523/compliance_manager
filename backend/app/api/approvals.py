from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import Approval
from app.schemas.schemas import ApprovalCreate, ApprovalDecision

router = APIRouter()

@router.get("/")
def list_approvals(db: Session = Depends(get_db)):
    return db.query(Approval).order_by(Approval.id.desc()).all()

@router.post("/")
def create_approval(payload: ApprovalCreate, db: Session = Depends(get_db)):
    approval = Approval(approval_id=f"APR-{uuid4().hex[:12].upper()}", **payload.model_dump())
    db.add(approval); db.commit(); db.refresh(approval)
    return approval

@router.post("/{approval_id}/decision")
def decide_approval(approval_id: str, payload: ApprovalDecision, db: Session = Depends(get_db)):
    approval = db.query(Approval).filter(Approval.approval_id == approval_id).first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.status != "pending":
        raise HTTPException(status_code=400, detail="Approval already decided")
    approval.status = {"approve": "approved", "deny": "denied", "review_in_depth": "review_required"}[payload.decision]
    approval.decision_reason = payload.reason
    approval.decided_by = payload.decided_by
    approval.decided_at = datetime.now(timezone.utc)
    db.commit(); db.refresh(approval)
    return approval
