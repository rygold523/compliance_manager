from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models import Asset, Evidence, CollectorRun


router = APIRouter(prefix="/api/windows-agent", tags=["windows-agent"])


COLLECTOR_CONTROL_MAP = {
    "duo_mfa_windows": {
        "control_id": "AC-01",
        "frameworks": {
            "pci_dss": ["8.4"],
            "soc2": ["CC6.1"],
            "nist_800_53": ["IA-2"],
            "iso_27001": ["A.5.17"],
            "iso_27002": ["5.17"],
        },
    },
    "automox_windows_agent": {
        "control_id": "VM-02",
        "frameworks": {
            "pci_dss": ["6.3.3"],
            "soc2": ["CC7.1"],
            "nist_800_53": ["SI-2"],
            "iso_27001": ["A.8.8"],
            "iso_27002": ["8.8"],
        },
    },
    "trend_micro_windows_agent": {
        "control_id": "SI-03",
        "frameworks": {
            "pci_dss": ["5.2"],
            "soc2": ["CC7.2"],
            "nist_800_53": ["SI-3"],
            "iso_27001": ["A.8.7"],
            "iso_27002": ["8.7"],
        },
    },
    "open_ports_windows": {
        "control_id": "NS-01",
        "frameworks": {
            "pci_dss": ["1.2", "1.3"],
            "soc2": ["CC6.6"],
            "nist_800_53": ["SC-7"],
            "iso_27001": ["A.8.20"],
            "iso_27002": ["8.20"],
        },
    },
}


class WindowsCollectorResult(BaseModel):
    status: str = "unknown"
    validated: bool = False
    raw: object | None = None


class WindowsAgentPayload(BaseModel):
    asset_id: str
    os_family: str = "windows"
    collected_at: str | None = None
    collectors: dict[str, WindowsCollectorResult] = Field(default_factory=dict)


@router.post("/ingest")
def ingest_windows_agent(payload: WindowsAgentPayload, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == payload.asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset.os_family = "windows"
    asset.agent_status = "deployed"
    asset.last_seen = datetime.now(timezone.utc)

    results = []

    for collector_name, result in payload.collectors.items():
        mapping = COLLECTOR_CONTROL_MAP.get(collector_name)

        if not mapping:
            continue

        run_id = f"COL-{uuid4().hex[:12].upper()}"
        evidence_id = f"EV-{uuid4().hex[:12].upper()}"

        output = {
            "collector": collector_name,
            "asset_id": payload.asset_id,
            "os_family": payload.os_family,
            "collected_at": payload.collected_at,
            "status": result.status,
            "validated": result.validated,
            "raw": result.raw,
        }

        db.add(CollectorRun(
            run_id=run_id,
            asset_id=payload.asset_id,
            collector=collector_name,
            status="completed" if result.validated else "failed",
            output=output,
        ))

        evidence_dir = Path(settings.evidence_root) / payload.asset_id / collector_name
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = evidence_dir / f"{evidence_id}.json"
        evidence_path.write_text(json.dumps(output, indent=2, default=str))

        db.add(Evidence(
            evidence_id=evidence_id,
            asset_id=payload.asset_id,
            control_id=mapping["control_id"],
            filename=evidence_path.name,
            file_path=str(evidence_path),
            source="windows_agent",
            description=f"Windows agent collector output for {collector_name}",
            collector=collector_name,
            evidence_type=collector_name,
            frameworks=mapping["frameworks"],
            validated=bool(result.validated),
        ))

        results.append({
            "collector": collector_name,
            "run_id": run_id,
            "evidence_id": evidence_id,
            "validated": bool(result.validated),
        })

    db.commit()

    return {
        "asset_id": payload.asset_id,
        "ingested": len(results),
        "results": results,
    }
