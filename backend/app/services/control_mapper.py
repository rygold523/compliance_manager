from pathlib import Path
import yaml

CONTROL_RULES = {
    "cve": "VM-01",
    "outdated_package": "VM-01",
    "missing_patch": "VM-01",
    "scanner_finding": "VM-01",
    "weak_cipher": "EN-01",
    "tls": "EN-01",
    "certificate": "EN-01",
    "open_port": "NS-01",
    "firewall": "NS-01",
    "segmentation": "NS-01",
    "missing_logs": "SI-01",
    "logging": "SI-01",
    "mfa_disabled": "AC-01",
    "unauthorized_access": "AC-02",
    "misconfiguration": "CM-01",
    "nginx_config": "CM-01",
    "incident": "IR-01",
    "backup": "CP-01",
}


def load_control(control_id: str, controls_dir: str = "/app/controls") -> dict:
    path = Path(controls_dir) / f"{control_id}.yml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def map_finding_to_control(finding_type: str, title: str = "", cve: str | None = None) -> str:
    if cve:
        return "VM-01"
    key = (finding_type or "").lower().strip()
    if key in CONTROL_RULES:
        return CONTROL_RULES[key]
    combined = f"{finding_type} {title}".lower()
    for token, control_id in CONTROL_RULES.items():
        if token in combined:
            return control_id
    return "CM-01"


def get_framework_mappings(control_id: str) -> dict:
    control = load_control(control_id)
    return control.get("framework_mappings", {})
