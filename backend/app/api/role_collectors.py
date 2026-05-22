from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Asset
from app.services.role_collector_profiles import collector_plan_for_asset

router = APIRouter(prefix="/api/role-collectors", tags=["role-collectors"])


@router.get("/{asset_id}/plan")
def get_role_collector_plan(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return {
        "asset_id": asset.asset_id,
        "asset_roles": asset.asset_roles or [],
        "data_classification": asset.data_classification or [],
        "collectors": collector_plan_for_asset(asset),
    }


@router.get("/")
def list_role_collector_plans(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()

    return [
        {
            "asset_id": asset.asset_id,
            "asset_roles": asset.asset_roles or [],
            "data_classification": asset.data_classification or [],
            "collector_count": len(collector_plan_for_asset(asset)),
            "collectors": collector_plan_for_asset(asset),
        }
        for asset in assets
    ]
