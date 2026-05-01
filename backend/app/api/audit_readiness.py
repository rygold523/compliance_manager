from fastapi import APIRouter, HTTPException
from app.services.audit_readiness import audit_readiness_all, audit_readiness_for_framework

router = APIRouter(prefix="/api/audit-readiness", tags=["audit-readiness"])

SUPPORTED = {"pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"}


@router.get("/")
def get_all_audit_readiness():
    return audit_readiness_all()


@router.get("/{framework}")
def get_framework_audit_readiness(framework: str):
    if framework not in SUPPORTED:
        raise HTTPException(status_code=404, detail=f"Unsupported framework: {framework}")

    return audit_readiness_for_framework(framework)
