import yaml
from pathlib import Path
from typing import Any, Dict, List


CONTROL_FILE = Path("controls/internal/continuous_compliance_controls.yml")


def load_internal_controls() -> List[Dict[str, Any]]:
    if not CONTROL_FILE.exists():
        return []

    with open(CONTROL_FILE, "r") as handle:
        data = yaml.safe_load(handle) or {}

    return data.get("controls", [])


def build_domain_summary() -> List[Dict[str, Any]]:
    controls = load_internal_controls()

    domains = {}

    for control in controls:
        domain = control.get("domain", "Unknown")

        if domain not in domains:
            domains[domain] = {
                "domain": domain,
                "total_controls": 0,
                "satisfied_controls": 0,
                "deficient_controls": 0,
                "stale_controls": 0,
                "open_findings": 0,
                "readiness_score": 100.0,
            }

        domains[domain]["total_controls"] += 1

    return list(domains.values())


def build_control_inventory() -> List[Dict[str, Any]]:
    controls = load_internal_controls()

    inventory = []

    for control in controls:
        inventory.append({
            "control_id": control.get("control_id"),
            "title": control.get("title"),
            "domain": control.get("domain"),
            "status": "unknown",
            "evidence_coverage": None,
            "freshness_status": None,
            "open_findings": 0,
            "mapped_frameworks": control.get("maps_to", []),
        })

    return inventory
