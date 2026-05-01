def normalize_text(value):
    return str(value or "").lower()


def evidence_contains_any(evidence_items, keywords):
    haystack_parts = []

    for item in evidence_items:
        haystack_parts.append(normalize_text(item.get("collector")))
        haystack_parts.append(normalize_text(item.get("source")))
        haystack_parts.append(normalize_text(item.get("raw_output")))
        haystack_parts.append(normalize_text(item.get("data")))
        haystack_parts.append(normalize_text(item.get("parsed_data")))

    haystack = " ".join(haystack_parts)

    return any(keyword.lower() in haystack for keyword in keywords)


def environment_validations(evidence_rows):
    """
    Environment-level validations.

    These controls are satisfied if supporting technology exists on at least
    one server in the environment because the platform/service supports the
    broader environment rather than a single asset.
    """

    validations = {}

    if evidence_contains_any(evidence_rows, ["wazuh", "wazuh-agent", "wazuh-manager"]):
        validations["SI-03"] = {
            "control_id": "SI-03",
            "validated": True,
            "validation_type": "environment",
            "reason": "Wazuh/SIEM presence was detected on at least one asset in the environment.",
            "supporting_service": "Wazuh",
        }

    if evidence_contains_any(evidence_rows, ["prometheus", "grafana", "node_exporter", "blackbox_exporter"]):
        validations["CP-05"] = {
            "control_id": "CP-05",
            "validated": True,
            "validation_type": "environment",
            "reason": "Prometheus/Grafana monitoring presence was detected on at least one asset in the environment.",
            "supporting_service": "Prometheus/Grafana",
        }

    if evidence_contains_any(evidence_rows, ["jenkins", "gitlab-runner", "github actions", "runner", "ci/cd", "pipeline"]):
        validations["SD-04"] = {
            "control_id": "SD-04",
            "validated": True,
            "validation_type": "environment",
            "reason": "CI/CD tooling was detected on at least one asset in the environment.",
            "supporting_service": "CI/CD",
        }

    return validations
