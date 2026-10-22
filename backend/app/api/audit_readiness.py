from fastapi import APIRouter, HTTPException
from app.services.framework_registry import is_enabled, is_assessment_ready
from app.services.audit_readiness import audit_readiness_all, audit_readiness_for_framework

router = APIRouter(prefix="/api/audit-readiness", tags=["audit-readiness"])

SUPPORTED = {"pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"}


@router.get("/")
def get_all_audit_readiness():
    return audit_readiness_all()


@router.get("/{framework}")
def get_framework_audit_readiness(framework: str):
    if not is_enabled(framework):
        raise HTTPException(status_code=409, detail="Framework is disabled")
    if not is_assessment_ready(framework):
        raise HTTPException(status_code=409, detail="Framework assessment is unavailable")

    return audit_readiness_for_framework(framework)
