from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def parse_freshness_seconds(value: str) -> int:
    value = value.strip().lower()
    if value.endswith("d"):
        return int(value[:-1]) * 86400
    if value.endswith("h"):
        return int(value[:-1]) * 3600
    if value.endswith("m"):
        return int(value[:-1]) * 60
    return int(value)


def is_stale(collected_at: datetime, freshness_seconds: int) -> bool:
    now = datetime.now(timezone.utc)
    if collected_at.tzinfo is None:
        collected_at = collected_at.replace(tzinfo=timezone.utc)
    return (now - collected_at).total_seconds() > freshness_seconds


def evaluate_control_evidence(
    control_id: str,
    policy_requirements: List[Dict[str, Any]],
    evidence_items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    results = {
        "control_id": control_id,
        "status": "satisfied",
        "missing_evidence": [],
        "stale_evidence": [],
        "satisfied_evidence": [],
    }

    for requirement in policy_requirements:
        name = requirement.get("name")
        scope_requirement = requirement.get("scope_requirement")
        authoritative_source = requirement.get("authoritative_source")
        freshness = requirement.get("freshness")

        matches = [
            item for item in evidence_items
            if item.get("evidence_name") == name
            and item.get("control_id") == control_id
            and (
                not scope_requirement
                or item.get("scope_requirement") == scope_requirement
                or item.get("evidence_scope") == scope_requirement
                or item.get("coverage_basis") == scope_requirement
            )
            and (
                not authoritative_source
                or item.get("source_id") == authoritative_source
                or item.get("authoritative_source") == authoritative_source
            )
        ]

        if not matches:
            results["missing_evidence"].append(requirement)
            results["status"] = "deficient"
            continue

        freshness_seconds: Optional[int] = None
        if freshness:
            freshness_seconds = parse_freshness_seconds(freshness)

        freshest_valid = None
        stale_matches = []

        for item in matches:
            collected_at_raw = item.get("collected_at")
            if not collected_at_raw or not freshness_seconds:
                freshest_valid = item
                continue

            collected_at = datetime.fromisoformat(collected_at_raw.replace("Z", "+00:00"))
            if is_stale(collected_at, freshness_seconds):
                stale_matches.append(item)
            else:
                freshest_valid = item

        if freshest_valid:
            results["satisfied_evidence"].append(freshest_valid)
        else:
            results["stale_evidence"].extend(stale_matches)
            results["status"] = "deficient"

    return results
