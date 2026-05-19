ROLE_CONTROL_MAP = {
    "application_server": ["AC", "CM", "SI", "VM", "SD", "NS"],
    "web_server": ["AC", "CM", "SI", "VM", "NS"],
    "database_server": ["AC", "CM", "SI", "VM", "CP"],
    "monitoring_server": ["AC", "CM", "SI", "VM"],
    "central_log_server": ["AC", "CM", "SI", "VM", "IR"],
    "siem_server": ["AC", "CM", "SI", "VM", "IR"],
    "ci_cd_server": ["AC", "CM", "SI", "VM", "SD"],
    "identity_provider": ["AC", "CM", "SI", "VM"],
    "sftp_server": ["AC", "CM", "SI", "VM", "NS"],
    "storage_server": ["AC", "CM", "SI", "VM", "CP"],
    "container_host": ["AC", "CM", "SI", "VM", "NS"],
    "jumpbox": ["AC", "CM", "SI", "VM", "NS"],
    "backup_server": ["AC", "CM", "SI", "VM", "CP"],
    "vulnerability_scanner": ["AC", "CM", "SI", "VM"],
    "firewall": ["AC", "CM", "SI", "NS"],
    "dns_server": ["AC", "CM", "SI", "NS"],
    "mail_server": ["AC", "CM", "SI", "VM", "NS"],
}

ROLE_FINDING_TITLE_ALLOW = {
    "monitoring_server": [
        "authentication",
        "time synchronization",
        "available package updates",
        "held packages",
        "monitoring",
        "prometheus",
        "grafana",
        "wazuh",
        "log",
    ],
    "central_log_server": [
        "authentication",
        "time synchronization",
        "available package updates",
        "held packages",
        "log",
        "wazuh",
        "siem",
        "audit",
    ],
    "sftp_server": [
        "authentication",
        "time synchronization",
        "available package updates",
        "held packages",
        "open ports",
        "listening services",
        "ssh",
        "sftp",
        "authorized keys",
        "duo",
    ],
    "storage_server": [
        "authentication",
        "time synchronization",
        "available package updates",
        "held packages",
        "backup",
        "storage",
        "disk",
    ],
    "application_server": [
        "authentication",
        "time synchronization",
        "available package updates",
        "held packages",
        "open ports",
        "listening services",
        "application",
        "service",
        "docker",
    ],
}

ROLE_REMEDIATION_HINTS = {
    "monitoring_server": [
        "Validate Prometheus/Grafana or equivalent monitoring services.",
        "Confirm monitoring data retention and alerting coverage.",
    ],
    "central_log_server": [
        "Validate centralized log ingestion, retention, and alert routing.",
        "Confirm Wazuh/SIEM agent and manager health.",
    ],
    "sftp_server": [
        "Validate SFTP/SSH hardening, authorized key review, Duo MFA enforcement, and file transfer audit logging.",
        "Confirm external file exchange access is restricted and reviewed.",
    ],
    "storage_server": [
        "Validate storage access controls, backup coverage, and retention evidence.",
    ],
    "application_server": [
        "Validate application service status, deployment traceability, and application logs.",
    ],
}

BASELINE_EXPECTED_COLLECTORS = [
    "trend_micro_ds_agent",
    "automox_amagent",
    "duo_mfa",
    "wazuh_agent",
    "listening_ports",
]


def normalize_roles(asset):
    roles = getattr(asset, "asset_roles", None) or []

    if isinstance(roles, str):
        return [r.strip() for r in roles.split(",") if r.strip()]

    return roles


def control_applies_to_asset(control_id, asset):
    roles = normalize_roles(asset)

    if not roles:
        return True

    prefix = str(control_id or "").split("-", 1)[0]

    allowed_prefixes = set()

    for role in roles:
        allowed_prefixes.update(ROLE_CONTROL_MAP.get(role, []))

    return prefix in allowed_prefixes


def finding_applies_to_asset(finding, asset):
    roles = normalize_roles(asset)

    if not roles:
        return True

    control_id = ""
    title = ""

    if isinstance(finding, dict):
        control_id = finding.get("control_id") or ""
        title = finding.get("title") or ""
    else:
        control_id = getattr(finding, "control_id", "") or ""
        title = getattr(finding, "title", "") or ""

    if not control_applies_to_asset(control_id, asset):
        return False

    title_lower = str(title).lower()

    allowed_terms = set()
    for role in roles:
        allowed_terms.update(ROLE_FINDING_TITLE_ALLOW.get(role, []))

    if not allowed_terms:
        return True

    return any(term in title_lower for term in allowed_terms)


def expected_collectors_for_asset(asset):
    roles = normalize_roles(asset)
    expected = list(BASELINE_EXPECTED_COLLECTORS)

    from app.services.asset_roles import ROLE_EXPECTED_COLLECTORS

    for role in roles:
        for collector in ROLE_EXPECTED_COLLECTORS.get(role, []):
            if collector not in expected:
                expected.append(collector)

    return expected


def remediation_hints_for_asset(asset):
    roles = normalize_roles(asset)
    hints = []

    for role in roles:
        for hint in ROLE_REMEDIATION_HINTS.get(role, []):
            if hint not in hints:
                hints.append(hint)

    return hints
