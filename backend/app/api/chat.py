from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import ChatMessage, Finding, Evidence, Asset
from app.schemas.schemas import ChatRequest
from app.services.ai_provider import call_ai_json
from app.services.ai_guardrails import enforce_ai_guardrails

router = APIRouter()

PROMPT = "You are a defensive compliance platform assistant. Answer only from provided context. Return JSON with response, referenced_assets, referenced_findings, referenced_controls, recommended_next_steps, requires_approval."

@router.post("/")
def chat(payload: ChatRequest, db: Session = Depends(get_db)):
    db.add(ChatMessage(thread_id=payload.thread_id, role="user", message=payload.message, context=payload.model_dump()))
    assets = db.query(Asset).all()
    findings = db.query(Finding).all()
    evidence = db.query(Evidence).all()
    context = {
        "user_message": payload.message,
        "assets": [{"asset_id": a.asset_id, "hostname": a.hostname, "address": a.address, "environment": a.environment, "role": a.role} for a in assets],
        "findings": [{"finding_id": f.finding_id, "asset_id": f.asset_id, "title": f.title, "severity": f.severity, "control_id": f.control_id, "status": f.status} for f in findings],
        "evidence": [{"evidence_id": e.evidence_id, "asset_id": e.asset_id, "control_id": e.control_id, "collector": e.collector, "validated": e.validated} for e in evidence],
    }

    if not payload.message.strip():
        response = {"response": "Enter a question about assets, findings, evidence, controls, or compliance readiness.", "referenced_assets": [], "referenced_findings": [], "referenced_controls": [], "recommended_next_steps": [], "requires_approval": False}
    elif "asset" in payload.message.lower() and not __import__("app.core.config").core.config.settings.ai_enabled:
        response = {"response": "The following assets are present:", "referenced_assets": context["assets"], "referenced_findings": [], "referenced_controls": [], "recommended_next_steps": [], "requires_approval": False}
    else:
        response = enforce_ai_guardrails(call_ai_json(PROMPT, context))

    db.add(ChatMessage(thread_id=payload.thread_id, role="assistant", message=response.get("response",""), context=response))
    db.commit()
    return response
