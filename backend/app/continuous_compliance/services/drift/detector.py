from typing import Any, Dict, List
from app.continuous_compliance.services.hash_utils import sha256_json


def detect_drift(
    source_id: str,
    current_state: Dict[str, Any],
    approved_baseline: Dict[str, Any],
) -> Dict[str, Any]:
    current_hash = sha256_json(current_state)
    baseline_hash = sha256_json(approved_baseline)

    changed = current_hash != baseline_hash

    differences: List[Dict[str, Any]] = []

    for key in sorted(set(current_state.keys()) | set(approved_baseline.keys())):
        current_value = current_state.get(key)
        baseline_value = approved_baseline.get(key)
        if current_value != baseline_value:
            differences.append({
                "field": key,
                "current": current_value,
                "baseline": baseline_value,
            })

    return {
        "source_id": source_id,
        "drift_detected": changed,
        "current_hash": current_hash,
        "baseline_hash": baseline_hash,
        "differences": differences,
    }
