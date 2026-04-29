import yaml
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import Asset
from app.schemas.schemas import AssetCreate

router = APIRouter()

@router.get("/")
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.id.desc()).all()

@router.post("/")
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    existing = db.query(Asset).filter(Asset.asset_id == payload.asset_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Asset already exists")
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset

@router.post("/load-from-inventory")
def load_from_inventory(db: Session = Depends(get_db)):
    path = Path("/app/inventory/assets.yml")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Inventory file not found")
    data = yaml.safe_load(path.read_text()) or {}
    loaded = 0
    for item in data.get("assets", []):
        if db.query(Asset).filter(Asset.asset_id == item["asset_id"]).first():
            continue
        db.add(Asset(**item))
        loaded += 1
    db.commit()
    return {"loaded": loaded}
