from datetime import datetime, timezone
import hmac
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models import Asset, CollectorRun, Evidence
from app.services.path_security import contained_path
from app.services.windows_agent_credentials import verify_credential


router = APIRouter(
    prefix="/api/windows-agent",
    tags=["windows-agent"],
)


COLLECTOR_CONTROL_MAP = {
    "os_inventory": {
        "control_id": "AM-01",
        "frameworks": {
            "pci_dss": ["12.5"],
            "soc2": ["CC6.1", "CC8.1"],
            "nist_800_53": ["CM-8"],
            "iso_27001": ["A.5.9"],
            "iso_27002": ["5.9"],
        },
    },
    "disk_usage": {
        "control_id": "CP-01",
        "frameworks": {
            "pci_dss": ["12.10.1"],
            "soc2": ["A1.2"],
            "nist_800_53": ["CP-9"],
            "iso_27001": ["A.8.13"],
            "iso_27002": ["8.13"],
        },
    },
    "package_inventory": {
        "control_id": "CM-01",
        "frameworks": {
            "pci_dss": ["6.3.3", "12.5"],
            "soc2": ["CC7.1", "CC8.1"],
            "nist_800_53": ["CM-8", "SI-2"],
            "iso_27001": ["A.5.9", "A.8.8"],
            "iso_27002": ["5.9", "8.8"],
        },
    },
    "available_updates": {
        "control_id": "VM-01",
        "frameworks": {
            "pci_dss": ["6.3.3", "11.3.1"],
            "soc2": ["CC7.1"],
            "nist_800_53": ["RA-5", "SI-2"],
            "iso_27001": ["A.8.8"],
            "iso_27002": ["8.8"],
        },
    },
    "agent_lifecycle": {
        "control_id": "CM-08",
        "frameworks": {
            "pci_dss": ["2.4"],
            "soc2": ["CC7.1"],
            "nist_800_53": ["CM-8"],
            "iso_27001": ["A.5.9"],
            "iso_27002": ["5.9"],
        },
    },
    "collector_health": {
        "control_id": "SI-07",
        "frameworks": {
            "pci_dss": ["11.5.2"],
            "soc2": ["CC7.1"],
            "nist_800_53": ["SI-7"],
            "iso_27001": ["A.8.9"],
            "iso_27002": ["8.9"],
        },
    },
    "iam_users": {
        "control_id": "AC-02",
        "frameworks": {
            "pci_dss": ["7.2", "8.2"],
            "soc2": ["CC6.1", "CC6.2"],
            "nist_800_53": ["AC-2"],
            "iso_27001": ["A.5.15", "A.5.16"],
            "iso_27002": ["5.15", "5.16"],
        },
    },
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
    raw: Any | None = None


class WindowsAgentPayload(BaseModel):
    asset_id: str
    os_family: str = "windows"
    collected_at: str | None = None
    collectors: dict[str, WindowsCollectorResult] = Field(
        default_factory=dict
    )


def build_evidence_output(
    payload: WindowsAgentPayload,
    collector_name: str,
    result: WindowsCollectorResult,
) -> dict[str, Any]:
    output: dict[str, Any] = {
        "collector": collector_name,
        "asset_id": payload.asset_id,
        "os_family": payload.os_family,
        "collected_at": payload.collected_at,
        "status": result.status,
        "validated": server_validated(result),
        "raw": result.raw,
    }

    if isinstance(result.raw, dict):
        output.update(result.raw)

    return output


def server_validated(result: WindowsCollectorResult) -> bool:
    return result.status.strip().lower() in {
        "completed", "healthy", "present", "success",
    }


def validate_windows_agent_token(token: str | None) -> None:
    expected_token = settings.windows_agent_ingest_token

    if token:
        if not expected_token or not hmac.compare_digest(token, expected_token):
            raise HTTPException(status_code=401, detail="Invalid Windows agent token.")
        return

    if settings.windows_agent_ingest_enforce_auth:
        if not expected_token:
            raise HTTPException(
                status_code=503,
                detail="Windows agent ingestion is not configured.",
            )
        raise HTTPException(status_code=401, detail="Windows agent token required.")


def validate_windows_agent_auth(
    db: Session,
    asset_id: str,
    token: str | None,
    credential_id: str | None,
) -> str:
    if credential_id:
        if not token or verify_credential(db, credential_id, token, asset_id) is None:
            raise HTTPException(status_code=401, detail="Invalid Windows agent credential.")
        return "asset_credential"
    if settings.windows_agent_legacy_auth_enabled:
        validate_windows_agent_token(token)
        return "legacy"
    raise HTTPException(status_code=401, detail="Windows agent credential required.")


class WindowsAgentAuthCheck(BaseModel):
    asset_id: str = Field(min_length=1, max_length=128)


@router.post("/auth-check")
def check_windows_agent_auth(
    payload: WindowsAgentAuthCheck,
    x_windows_agent_token: str | None = Header(default=None),
    x_windows_agent_credential_id: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    if not x_windows_agent_credential_id:
        raise HTTPException(status_code=401, detail="Windows agent credential required.")
    validate_windows_agent_auth(
        db, payload.asset_id, x_windows_agent_token, x_windows_agent_credential_id
    )
    db.commit()
    return {"status": "ok", "asset_id": payload.asset_id}


@router.post("/ingest")
def ingest_windows_agent(
    payload: WindowsAgentPayload,
    x_windows_agent_token: str | None = Header(default=None),
    x_windows_agent_credential_id: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    validate_windows_agent_auth(
        db, payload.asset_id, x_windows_agent_token, x_windows_agent_credential_id
    )

    asset = (
        db.query(Asset)
        .filter(Asset.asset_id == payload.asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found",
        )

    asset.os_family = "windows"
    asset.agent_status = "deployed"
    asset.last_seen = datetime.now(timezone.utc)

    results = []

    try:
        for collector_name, result in payload.collectors.items():
            mapping = COLLECTOR_CONTROL_MAP.get(collector_name)

            if not mapping:
                continue

            run_id = f"COL-{uuid4().hex[:12].upper()}"
            evidence_id = f"EV-{uuid4().hex[:12].upper()}"

            output = build_evidence_output(
                payload,
                collector_name,
                result,
            )

            validated = server_validated(result)
            run_status = "completed" if validated else "failed"

            db.add(
                CollectorRun(
                    run_id=run_id,
                    asset_id=payload.asset_id,
                    collector=collector_name,
                    status=run_status,
                    output=output,
                )
            )

            try:
                evidence_dir = contained_path(
                    settings.evidence_root,
                    payload.asset_id,
                    collector_name,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Invalid asset path.") from exc
            evidence_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            evidence_path = (
                evidence_dir
                / f"{evidence_id}.json"
            )
            evidence_path.write_text(
                json.dumps(
                    output,
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )

            db.add(
                Evidence(
                    evidence_id=evidence_id,
                    asset_id=payload.asset_id,
                    control_id=mapping["control_id"],
                    filename=evidence_path.name,
                    file_path=str(evidence_path),
                    source="windows_agent",
                    description=(
                        "Windows agent collector output "
                        f"for {collector_name}"
                    ),
                    collector=collector_name,
                    evidence_type=collector_name,
                    frameworks=mapping["frameworks"],
                    validated=validated,
                )
            )

            results.append(
                {
                    "collector": collector_name,
                    "run_id": run_id,
                    "evidence_id": evidence_id,
                    "validated": validated,
                }
            )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "asset_id": payload.asset_id,
        "ingested": len(results),
        "results": results,
    }
