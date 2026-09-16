from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_env: str = "production"
    database_url: str
    evidence_root: str = "/app/evidence"
    public_backend_url: str = "http://localhost:8000"
    windows_agent_ingest_token: str = ""
    windows_agent_ingest_enforce_auth: bool = False
    windows_agent_legacy_auth_enabled: bool = True
    ssh_known_hosts_file: str = "/app/remote-cache/known_hosts"

    auth_provider: str = "local"
    auth_session_hours: int = 12
    auth_cookie_name: str = "compliance_session"
    auth_cookie_secure: bool = True
    auth_cookie_samesite: str = "strict"
    auth_max_failed_attempts: int = 5
    auth_lockout_minutes: int = 15
    auth_login_source_max_attempts: int = 50
    auth_login_throttle_window_minutes: int = 15
    auth_login_initial_backoff_seconds: int = 30
    auth_login_max_backoff_seconds: int = 900
    auth_cors_origins: str = "http://localhost:3000"
    auth_allowed_hosts: str = "localhost,127.0.0.1"
    auth_trusted_proxy_networks: str = ""
    auth_service_paths: str = "/api/health,/api/live,/api/ready,/api/iam/db-ingest,/api/windows-agent/ingest,/api/windows-agent/auth-check"
    auth_session_retention_days: int = 30
    auth_audit_retention_days: int = 400
    auth_retention_archive_root: str = "/app/evidence/retention/auth"
    changelog_retention_days: int = 400
    validated_evidence_retention_days: int = 400
    unvalidated_evidence_retention_days: int = 400
    evidence_retention_archive_root: str = "/app/evidence/retention/changelog-evidence-archives"

    remote_exec_enabled: bool = True
    remote_exec_user: str = "compliance-agent"
    remote_exec_key: str = "/home/aivuln/.ssh/aivuln_remote_exec"
    remote_exec_timeout_seconds: int = 120
    remote_exec_require_approval: bool = True
    remote_exec_allow_arbitrary_commands: bool = False

    allow_docker_image_rebuilds: bool = False
    allow_auto_nginx_changes: bool = False
    allow_package_updates: bool = True
    require_approval_for_config_changes: bool = True
    require_approval_for_service_reloads: bool = True
    require_approval_for_production: bool = True

    ai_enabled: bool = False
    ai_provider: str = "ollama"
    ai_model: str = "llama3.2:3b"
    ai_base_url: str = "http://host.docker.internal:11434"
    ai_temperature: float = 0.1
    ai_max_tokens: int = 1500

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
