from uuid import uuid4
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import ScannerResult, Finding
from app.schemas.schemas import ScannerImportRequest
from app.services.control_mapper import map_finding_to_control, get_framework_mappings
from app.services.compliance import affected_frameworks_from_mappings

router = APIRouter()

@router.post("/import")
def import_scanner_result(payload: ScannerImportRequest, db: Session = Depends(get_db)):
    scanner_result_id = f"SCAN-{uuid4().hex[:12].upper()}"
    imported = 0
    items = payload.raw.get("findings") or payload.raw.get("vulnerabilities") or []
    for item in items:
        finding_id = item.get("finding_id") or item.get("id") or f"F-{uuid4().hex[:12].upper()}"
        if db.query(Finding).filter(Finding.finding_id == finding_id).first():
            continue
        title = item.get("title") or item.get("name") or item.get("plugin_name") or "Scanner Finding"
        severity = item.get("severity") or item.get("risk") or "medium"
        cve = item.get("cve")
        finding_type = "cve" if cve else item.get("finding_type", "scanner_finding")
        asset_id = payload.asset_id or item.get("asset_id") or "unknown"
        control_id = map_finding_to_control(finding_type, title, cve)
        mappings = get_framework_mappings(control_id)
        db.add(Finding(finding_id=finding_id, asset_id=asset_id, source=payload.scanner, title=title, description=item.get("description"), severity=str(severity).lower(), cve=cve, finding_type=finding_type, control_id=control_id, framework_mappings=mappings, affected_frameworks=affected_frameworks_from_mappings(mappings), raw=item, risk_score={"critical":100,"high":80,"medium":50,"low":25}.get(str(severity).lower(), 10)))
        imported += 1
    db.add(ScannerResult(scanner_result_id=scanner_result_id, scanner=payload.scanner, asset_id=payload.asset_id, raw=payload.raw, imported_findings=imported))
    db.commit()
    return {"scanner_result_id": scanner_result_id, "imported_findings": imported}

@router.get("/results")
def scanner_results(db: Session = Depends(get_db)):
    return db.query(ScannerResult).order_by(ScannerResult.id.desc()).all()
