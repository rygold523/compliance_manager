SUPPORTED_ASSET_ROLES = [
    "application_server",
    "web_server",
    "database_server",
    "monitoring_server",
    "central_log_server",
    "siem_server",
    "ci_cd_server",
    "identity_provider",
    "sftp_server",
    "storage_server",
    "container_host",
    "jumpbox",
    "backup_server",
    "vulnerability_scanner",
    "firewall",
    "dns_server",
    "mail_server",
]

ROLE_EXPECTED_COLLECTORS = {
    "application_server": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "listening_ports",
    ],
    "web_server": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "listening_ports",
        "web_service_status",
    ],
    "database_server": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "listening_ports",
        "database_service_status",
    ],
    "monitoring_server": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "monitoring_stack_status",
        "listening_ports",
    ],
    "central_log_server": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "log_stack_status",
        "listening_ports",
    ],
    "siem_server": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "log_stack_status",
        "listening_ports",
    ],
    "ci_cd_server": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "cicd_service_status",
        "listening_ports",
    ],
    "identity_provider": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "identity_service_status",
        "listening_ports",
    ],
    "sftp_server": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "sftp_configuration",
        "ssh_hardening",
        "authorized_keys_review",
        "listening_ports",
    ],
    "storage_server": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "listening_ports",
    ],
    "container_host": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "docker_inventory",
        "listening_ports",
    ],
    "jumpbox": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "ssh_hardening",
        "authorized_keys_review",
        "listening_ports",
    ],
    "backup_server": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "backup_service_status",
        "listening_ports",
    ],
    "vulnerability_scanner": [
        "trend_micro_ds_agent",
        "automox_amagent",
        "duo_mfa",
        "wazuh_agent",
        "scanner_service_status",
        "listening_ports",
    ],
}

BASELINE_COLLECTORS = [
    "trend_micro_ds_agent",
    "automox_amagent",
    "duo_mfa",
    "wazuh_agent",
    "listening_ports",
]


def normalize_asset_roles(value):
    if not value:
        return []

    if isinstance(value, str):
        value = [item.strip() for item in value.split(",") if item.strip()]

    roles = []
    for role in value:
        normalized = str(role).strip().lower().replace(" ", "_").replace("-", "_")
        if normalized in SUPPORTED_ASSET_ROLES and normalized not in roles:
            roles.append(normalized)

    return roles


def collectors_for_roles(asset_roles):
    roles = normalize_asset_roles(asset_roles)
    collectors = list(BASELINE_COLLECTORS)

    for role in roles:
        for collector in ROLE_EXPECTED_COLLECTORS.get(role, []):
            if collector not in collectors:
                collectors.append(collector)

    return collectors
