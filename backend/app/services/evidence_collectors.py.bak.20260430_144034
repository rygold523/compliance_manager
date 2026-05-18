from datetime import datetime, timezone
from app.services.remote_executor import run_ssh_command

COLLECTORS = {
    "user_changes": {
        "command": "sudo grep -E 'useradd|userdel|usermod|groupadd|groupdel|passwd' /var/log/auth.log /var/log/auth.log.1 2>/dev/null | tail -200",
        "control_ids": ["AC-02", "SI-01"],
        "frameworks": {"pci_dss": ["7.2", "8.2", "10.2"], "soc2": ["CC6.1", "CC7.2"], "nist_800_53": ["AC-2", "AU-6"], "iso_27001": ["A.5.15", "A.8.15"], "iso_27002": ["5.15", "8.15"]},
    },
    "auth_success": {
        "command": "sudo grep -Ei 'accepted password|accepted publickey|session opened' /var/log/auth.log /var/log/auth.log.1 2>/dev/null | tail -200",
        "control_ids": ["AC-02", "SI-01"],
        "frameworks": {"pci_dss": ["8.2", "10.2"], "soc2": ["CC6.1", "CC7.2"], "nist_800_53": ["AU-6", "AC-2"], "iso_27001": ["A.8.15", "A.8.16"], "iso_27002": ["8.15", "8.16"]},
    },
    "auth_failure": {
        "command": "sudo grep -Ei 'failed password|authentication failure|invalid user' /var/log/auth.log /var/log/auth.log.1 2>/dev/null | tail -200",
        "control_ids": ["AC-02", "SI-01"],
        "frameworks": {"pci_dss": ["8.2", "10.2", "10.6"], "soc2": ["CC6.1", "CC7.2"], "nist_800_53": ["AU-6", "SI-4"], "iso_27001": ["A.8.15", "A.8.16"], "iso_27002": ["8.15", "8.16"]},
    },
    "sudo_activity": {
        "command": "sudo grep -Ei 'sudo:|COMMAND=' /var/log/auth.log /var/log/auth.log.1 2>/dev/null | tail -200",
        "control_ids": ["AC-02", "SI-01"],
        "frameworks": {"pci_dss": ["7.2", "10.2"], "soc2": ["CC6.1", "CC7.2"], "nist_800_53": ["AC-6", "AU-6"], "iso_27001": ["A.5.15", "A.8.15"], "iso_27002": ["5.15", "8.15"]},
    },
    "open_ports": {
        "command": "ss -tulpn",
        "control_ids": ["NS-01", "CM-01"],
        "frameworks": {"pci_dss": ["1.2", "2.2"], "soc2": ["CC6.6"], "nist_800_53": ["SC-7", "CM-6"], "iso_27001": ["A.8.20", "A.8.9"], "iso_27002": ["8.20", "8.9"]},
    },
    "listening_services": {
        "command": "ss -tulpn",
        "control_ids": ["NS-01", "CM-01"],
        "frameworks": {"pci_dss": ["1.2", "2.2"], "soc2": ["CC6.6", "CC8.1"], "nist_800_53": ["SC-7", "CM-6"], "iso_27001": ["A.8.20", "A.8.9"], "iso_27002": ["8.20", "8.9"]},
    },
    "packages": {
        "command": "dpkg -l | head -500",
        "control_ids": ["VM-01", "CM-01"],
        "frameworks": {"pci_dss": ["6.3.3", "11.3.1"], "soc2": ["CC7.1", "CC8.1"], "nist_800_53": ["RA-5", "CM-8"], "iso_27001": ["A.8.8", "A.8.9"], "iso_27002": ["8.8", "8.9"]},
    },
    "held_packages": {
        "command": "apt-mark showhold",
        "control_ids": ["VM-01", "CM-01"],
        "frameworks": {"pci_dss": ["6.3.3"], "soc2": ["CC7.1"], "nist_800_53": ["SI-2", "CM-6"], "iso_27001": ["A.8.8"], "iso_27002": ["8.8"]},
    },
    "available_updates": {
        "command": "apt list --upgradable",
        "control_ids": ["VM-01"],
        "frameworks": {"pci_dss": ["6.3.3", "11.3.1"], "soc2": ["CC7.1"], "nist_800_53": ["RA-5", "SI-2"], "iso_27001": ["A.8.8"], "iso_27002": ["8.8"]},
    },
    "firewall_status": {
        "command": "sudo ufw status verbose",
        "control_ids": ["NS-01"],
        "frameworks": {"pci_dss": ["1.2", "1.3"], "soc2": ["CC6.6"], "nist_800_53": ["SC-7"], "iso_27001": ["A.8.20"], "iso_27002": ["8.20"]},
    },
    "ssh_config": {
        "command": "sudo cat /etc/ssh/sshd_config",
        "control_ids": ["AC-02", "CM-01"],
        "frameworks": {"pci_dss": ["2.2", "8.2"], "soc2": ["CC6.1", "CC8.1"], "nist_800_53": ["AC-2", "CM-6"], "iso_27001": ["A.5.15", "A.8.9"], "iso_27002": ["5.15", "8.9"]},
    },
    "time_sync": {
        "command": "timedatectl",
        "control_ids": ["SI-01", "CM-01"],
        "frameworks": {"pci_dss": ["10.4"], "soc2": ["CC7.2"], "nist_800_53": ["AU-8"], "iso_27001": ["A.8.17"], "iso_27002": ["8.17"]},
    },
    "disk_usage": {
        "command": "df -h",
        "control_ids": ["CP-01", "CM-01"],
        "frameworks": {"pci_dss": ["12.10.1"], "soc2": ["A1.2"], "nist_800_53": ["CP-9"], "iso_27001": ["A.8.13"], "iso_27002": ["8.13"]},
    },
    "docker_inventory": {
        "command": "sudo docker ps --format '{{json .}}'",
        "control_ids": ["CM-01", "VM-01"],
        "frameworks": {"pci_dss": ["2.2", "6.3.3"], "soc2": ["CC7.1", "CC8.1"], "nist_800_53": ["CM-8", "RA-5"], "iso_27001": ["A.8.8", "A.8.9"], "iso_27002": ["8.8", "8.9"]},
    },
}


def run_collector(asset, collector_name: str) -> dict:
    if collector_name not in COLLECTORS:
        return {"collector": collector_name, "status": "failed", "error": "Unknown collector"}

    spec = COLLECTORS[collector_name]
    result = run_ssh_command(host=asset.address, username=asset.ssh_user, command=spec["command"], timeout=120, port=asset.ssh_port or 22)

    return {
        "collector": collector_name,
        "asset_id": asset.asset_id,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "command": spec["command"],
        "control_ids": spec["control_ids"],
        "frameworks": spec["frameworks"],
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "exit_code": result.get("exit_code"),
        "status": "completed" if result.get("exit_code") == 0 else "failed",
    }
