from fastapi import APIRouter

from app.continuous_compliance.services.reporting.summary import (
    build_control_inventory,
    build_domain_summary,
)

router = APIRouter(
    prefix="/api/v2/continuous-compliance/reporting",
    tags=["continuous-compliance-reporting"],
)


@router.get("/domains")
def reporting_domains():
    return {
        "domains": build_domain_summary()
    }


@router.get("/controls")
def reporting_controls():
    return {
        "controls": build_control_inventory()
    }
