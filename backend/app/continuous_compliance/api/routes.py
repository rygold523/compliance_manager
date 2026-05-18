from fastapi import APIRouter, HTTPException, Request

from app.continuous_compliance.config import (
    ENABLE_DRIFT_ENGINE,
    ENABLE_EVENT_MONITORING,
    ENABLE_POLICY_ENGINE,
    ENABLE_REGULATORY_ENGINE,
    ENABLE_TWILIO_VALIDATION,
)
from app.continuous_compliance.collectors.twilio.state_collector import TwilioStateCollector
from app.continuous_compliance.services.incident.twilio_event_normalizer import normalize_twilio_event

router = APIRouter(prefix="/api/v2/continuous-compliance", tags=["continuous-compliance"])


@router.get("/health")
def health():
    return {
        "status": "ok",
        "module": "continuous_compliance",
        "feature_flags": {
            "regulatory_engine": ENABLE_REGULATORY_ENGINE,
            "twilio_validation": ENABLE_TWILIO_VALIDATION,
            "drift_engine": ENABLE_DRIFT_ENGINE,
            "policy_engine": ENABLE_POLICY_ENGINE,
            "event_monitoring": ENABLE_EVENT_MONITORING,
        },
    }


@router.get("/twilio/state")
def twilio_state():
    if not ENABLE_TWILIO_VALIDATION:
        raise HTTPException(status_code=404, detail="Twilio validation module disabled")
    return TwilioStateCollector().collect()


@router.post("/twilio/events")
async def twilio_events(request: Request):
    if not ENABLE_EVENT_MONITORING:
        raise HTTPException(status_code=404, detail="Event monitoring module disabled")

    payload = await request.json()
    normalized = normalize_twilio_event(payload)

    # Placeholder for persistence/finding generation.
    return {
        "accepted": True,
        "normalized_event": normalized,
    }


@router.get("/drift")
def drift_summary():
    if not ENABLE_DRIFT_ENGINE:
        raise HTTPException(status_code=404, detail="Drift engine disabled")
    return {"items": []}


@router.get("/evidence-freshness")
def evidence_freshness():
    if not ENABLE_POLICY_ENGINE:
        raise HTTPException(status_code=404, detail="Evidence policy engine disabled")
    return {"items": []}


@router.get("/regulatory")
def regulatory_summary():
    if not ENABLE_REGULATORY_ENGINE:
        raise HTTPException(status_code=404, detail="Regulatory engine disabled")
    return {"items": []}


@router.get("/tasks")
def compliance_tasks():
    return {"items": []}


@router.get("/audit-readiness")
def audit_readiness():
    return {"items": []}
