ROLE_CONTROL_MAP = {
    "application_server": ["AC", "CM", "SI", "VM", "SD", "NS"],
    "web_server": ["AC", "CM", "SI", "VM", "NS"],
    "database_server": ["AC", "CM", "SI", "VM", "CP"],
    "monitoring_server": ["AC", "CM", "SI", "VM"],
    "central_log_server": ["AC", "CM", "SI", "VM"],
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

ROLE_REMEDIATION_HINTS = {
    "monitoring_server": [
        "Validate Prometheus/Grafana or equivalent monitoring services.",
        "Confirm monitoring data retention and alerting coverage.",
    ],
    "central_log_server": [
        "Validate centralized log ingestion, retention, and alert routing.",
        "Confirm Wazuh/SIEM agent and manager health.",
    ],
    "ci_cd_server": [
        "Validate CI/CD job audit logging, build restrictions, and deployment access controls.",
        "Confirm pipeline secrets are protected and deployment jobs are reviewed.",
    ],
    "sftp_server": [
        "Validate SFTP/SSH hardening, authorized key review, and file transfer audit logging.",
        "Confirm external file exchange access is restricted and reviewed.",
    ],
    "database_server": [
        "Validate database listener exposure, backup evidence, privileged access, and patching.",
    ],
    "web_server": [
        "Validate TLS, reverse proxy configuration, listening ports, and web service logging.",
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
        hints.extend(ROLE_REMEDIATION_HINTS.get(role, []))

    return hints
