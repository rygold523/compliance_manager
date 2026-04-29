from pathlib import Path
from uuid import uuid4
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.models import Asset, Evidence, CollectorRun
from app.schemas.schemas import CollectorRunRequest
from app.services.evidence_collectors import run_collector, COLLECTORS

router = APIRouter()

@router.get("/")
def list_collectors():
    return {"collectors": [{"name": name, "control_ids": spec["control_ids"], "frameworks": spec["frameworks"]} for name, spec in COLLECTORS.items()]}

@router.post("/run")
def run_collectors(payload: CollectorRunRequest, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == payload.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    results = []
    for collector_name in payload.collectors:
        run_id = f"COL-{uuid4().hex[:12].upper()}"
        output = run_collector(asset, collector_name)
        db.add(CollectorRun(run_id=run_id, asset_id=asset.asset_id, collector=collector_name, status=output["status"], output=output))

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
            description=f"Collector output for {collector_name}",
            collector=collector_name,
            evidence_type=collector_name,
            frameworks=output.get("frameworks", {}),
            validated=output.get("status") == "completed",
        ))
        results.append({"run_id": run_id, "evidence_id": evidence_id, "collector": collector_name, "status": output["status"]})
    db.commit()
    return {"asset_id": asset.asset_id, "results": results}
