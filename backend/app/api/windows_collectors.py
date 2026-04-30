from fastapi import APIRouter
from fastapi.responses import FileResponse
from pathlib import Path

router = APIRouter(prefix="/api/windows-collectors", tags=["windows-collectors"])

SCRIPT_PATH = Path("/var/lib/ai-vulnerability-management/windows_collectors/windows_evidence_collectors.ps1")


@router.get("/")
def list_windows_collectors():
    return {
        "collectors": [
            {"name": "windows_local_users", "control_ids": ["AC-02"]},
            {"name": "windows_local_groups", "control_ids": ["AC-02"]},
            {"name": "windows_defender_status", "control_ids": ["SI-01", "VM-01"]},
            {"name": "windows_firewall_status", "control_ids": ["NS-01"]},
            {"name": "windows_hotfixes", "control_ids": ["VM-01"]},
            {"name": "windows_listening_ports", "control_ids": ["NS-01"]},
            {"name": "windows_logon_events", "control_ids": ["AC-02", "SI-01"]},
            {"name": "windows_time_sync", "control_ids": ["SI-01"]},
            {"name": "windows_disk_usage", "control_ids": ["CP-01"]},
            {"name": "windows_services", "control_ids": ["CM-01"]},
        ]
    }


@router.get("/script")
def download_script():
    return FileResponse(
        SCRIPT_PATH,
        filename="windows_evidence_collectors.ps1",
        media_type="text/plain",
    )
