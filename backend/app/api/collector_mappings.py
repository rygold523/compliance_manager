from fastapi import APIRouter
from app.services.control_catalog import list_controls

router = APIRouter(prefix="/api/collector-mappings", tags=["collector-mappings"])

COLLECTOR_CONTROL_MAP = {
    "user_changes": ["AC-02", "AC-05", "AC-06", "SI-01"],
    "auth_success": ["AC-02", "SI-01"],
    "auth_failure": ["AC-02", "SI-01"],
    "sudo_activity": ["AC-02", "AC-04", "SI-01"],
    "open_ports": ["NS-01", "NS-02", "CM-01"],
    "listening_services": ["NS-01", "NS-02", "CM-01"],
    "packages": ["VM-01", "CM-01"],
    "held_packages": ["VM-01", "CM-01"],
    "available_updates": ["VM-01"],
    "firewall_status": ["NS-01", "NS-02"],
    "ssh_config": ["AC-02", "AC-04", "CM-01"],
    "time_sync": ["SI-01", "SI-05", "CM-01"],
    "disk_usage": ["CP-01", "CP-05", "CM-01"],
    "docker_inventory": ["CM-01", "CM-02", "CP-05", "SI-03", "VM-01"],
    "cicd_security": ["SD-04"],
    "windows_local_users": ["AC-02", "AC-05", "AC-06"],
    "windows_local_groups": ["AC-02", "AC-04"],
    "windows_defender_status": ["SI-01", "VM-01"],
    "windows_firewall_status": ["NS-01", "NS-02"],
    "windows_hotfixes": ["VM-01"],
    "windows_listening_ports": ["NS-01", "NS-02"],
    "windows_logon_events": ["AC-02", "SI-01"],
    "windows_time_sync": ["SI-01", "SI-05", "CM-01"],
    "windows_disk_usage": ["CP-01", "CP-05", "CM-01"],
    "windows_services": ["CM-01", "CM-02", "CP-05", "SI-03"],
}


@router.get("/")
def list_collector_mappings():
    controls = {control["control_id"]: control for control in list_controls()}
    rows = []

    for collector, control_ids in sorted(COLLECTOR_CONTROL_MAP.items()):
        mapped_controls = []

        for control_id in control_ids:
            control = controls.get(control_id)

            mapped_controls.append({
                "control_id": control_id,
                "title": control.get("title") if control else "Unmapped control",
                "domain": control.get("domain") if control else "",
                "exists_in_catalog": control is not None,
            })

        rows.append({
            "name": collector,
            "control_ids": control_ids,
            "mapped_controls": mapped_controls,
            "unmapped_control_ids": [
                item["control_id"]
                for item in mapped_controls
                if not item["exists_in_catalog"]
            ],
        })

    return {
        "collectors": rows,
    }
