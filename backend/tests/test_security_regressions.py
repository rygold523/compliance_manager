import ast
import inspect
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.windows_agent import (
    WindowsCollectorResult,
    server_validated,
    validate_windows_agent_token,
)
from app.api import agents
from app.core.config import settings
from app.services import agent_deployer
from app.services import evidence_collectors
from app.services.agent_deployer import deploy_agent
from app.services.remote_executor import is_command_allowed
from app.services.path_security import contained_path
from app.models import WindowsAgentCredential
from app.services.windows_agent_credentials import issue_credential, verify_credential


def test_contained_path_accepts_normal_components(tmp_path):
    expected = tmp_path / "asset-01" / "AC-02"
    assert contained_path(tmp_path, "asset-01", "AC-02") == expected


@pytest.mark.parametrize(
    "components",
    [
        ("../outside", "AC-02"),
        ("asset-01", "../../outside"),
        ("/tmp/outside", "AC-02"),
        ("asset-01", "/tmp/outside"),
        (".", "AC-02"),
    ],
)
def test_contained_path_rejects_escape(tmp_path, components):
    with pytest.raises(ValueError):
        contained_path(tmp_path, *components)


def test_windows_deployment_requires_ingest_token():
    result = deploy_agent(
        address="192.0.2.10",
        username="Administrator",
        password="temporary-password",
        port=5985,
        os_family="windows",
        asset_id="windows-01",
        backend_url="http://backend.example.test:8000",
        ingest_token="",
    )

    assert result["status"] == "failed"
    assert "WINDOWS_AGENT_INGEST_TOKEN" in result["output"][0]["stderr"]


def test_windows_upgrade_issues_asset_credential():
    source = inspect.getsource(agents.upgrade_agent)
    tree = ast.parse(source)
    deploy_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "deploy_agent"
    ]

    assert len(deploy_calls) == 1
    keywords = {
        keyword.arg: keyword.value
        for keyword in deploy_calls[0].keywords
    }
    assert "credential_id" in keywords
    source = inspect.getsource(agents.upgrade_agent)
    assert "provision_windows_credential" in source
    assert "revoke_credential" in source
    assert "revoke_other_credentials" in source


def test_windows_upload_uses_unique_verified_temporary_file():
    source = inspect.getsource(agent_deployer.deploy_windows_agent)

    assert "uuid4().hex" in source
    assert "Verify Windows bootstrap upload" in source
    assert "Bootstrap length mismatch" in source
    assert "Bootstrap SHA256 mismatch" in source
    assert "Finalize Windows bootstrap upload" in source
    assert "-CredentialId" in source


def test_windows_validation_is_computed_server_side():
    assert server_validated(
        WindowsCollectorResult(status="completed", validated=False, raw={})
    )
    assert not server_validated(
        WindowsCollectorResult(status="missing", validated=True, raw={})
    )


def test_windows_bootstrap_switches_config_after_preflight():
    source = Path("/app/scripts/bootstrap_windows_managed_target.ps1").read_text()
    assert "agent-config.json.new" in source
    assert "/api/windows-agent/auth-check" in source
    assert "X-Windows-Agent-Credential-ID" in source
    assert source.index("/api/windows-agent/auth-check") < source.index(
        "Move-Item"
    )


def test_asset_credential_is_hashed_and_bound_to_one_asset():
    engine = create_engine("sqlite://")
    WindowsAgentCredential.__table__.create(engine)
    session = sessionmaker(bind=engine)()
    try:
        record, token = issue_credential(session, "windows-01")
        assert record.token_hash != token
        assert verify_credential(
            session, record.credential_id, token, "windows-01"
        ) is record
        assert verify_credential(
            session, record.credential_id, token, "windows-02"
        ) is None
    finally:
        session.close()


def test_linux_privileged_collectors_use_dispatcher():
    commands = {
        name: specification["command"]
        for name, specification in evidence_collectors.COLLECTORS.items()
    }

    for name in {
        "iam_users",
        "user_changes",
        "auth_success",
        "auth_failure",
        "sudo_activity",
        "os_inventory",
        "firewall_status",
        "ssh_config",
        "disk_usage",
        "docker_inventory",
        "listening_ports",
        "package_inventory",
        "agent_lifecycle",
        "collector_health",
    }:
        assert commands[name].startswith(
            "sudo /usr/local/sbin/compliance-agent-command "
        )


@pytest.mark.parametrize(
    "command",
    [
        "sudo /usr/bin/find / -exec /bin/sh \\;",
        "sudo /usr/bin/apt-get changelog apt",
        "sudo /usr/bin/cat /etc/shadow",
        "sudo /usr/bin/docker run --privileged alpine sh",
        "sudo /usr/local/lib/compliance/collectors/install_collectors.py",
        "sudo /usr/local/lib/compliance/collectors/iam_users.py",
    ],
)
def test_dangerous_legacy_commands_are_denied(command):
    assert not is_command_allowed(command)


@pytest.mark.parametrize(
    "command",
    [
        "sudo /usr/local/sbin/compliance-agent-command collect-iam-users",
        "sudo /usr/local/sbin/compliance-agent-command collect-auth-failure",
        "sudo /usr/local/sbin/compliance-agent-command collect-firewall-status",
        "sudo /usr/local/sbin/compliance-agent-command manage-packages upgrade openssl",
        "sudo /usr/local/sbin/compliance-agent-command remove-agent",
    ],
)
def test_dispatcher_commands_are_allowed(command):
    assert is_command_allowed(command)


def test_linux_deployer_removes_legacy_policy_after_validation():
    source = inspect.getsource(agent_deployer.deploy_linux_agent)

    assert "visudo -cf /etc/sudoers.d/.compliance-agent.new" in source
    assert "compliance-agent-collectors" in source
    assert source.index("visudo -cf /etc/sudoers.d/.compliance-agent.new") < source.index(
        "compliance-agent-collectors"
    )


def test_windows_ingest_allows_legacy_agent_during_migration(monkeypatch):
    monkeypatch.setattr(settings, "windows_agent_ingest_token", "expected-token")
    monkeypatch.setattr(settings, "windows_agent_ingest_enforce_auth", False)
    validate_windows_agent_token(None)


def test_windows_ingest_rejects_missing_token_after_enforcement(monkeypatch):
    monkeypatch.setattr(settings, "windows_agent_ingest_token", "expected-token")
    monkeypatch.setattr(settings, "windows_agent_ingest_enforce_auth", True)
    with pytest.raises(HTTPException) as raised:
        validate_windows_agent_token(None)
    assert raised.value.status_code == 401


def test_windows_ingest_rejects_wrong_token_during_migration(monkeypatch):
    monkeypatch.setattr(settings, "windows_agent_ingest_token", "expected-token")
    monkeypatch.setattr(settings, "windows_agent_ingest_enforce_auth", False)
    with pytest.raises(HTTPException) as raised:
        validate_windows_agent_token("wrong-token")
    assert raised.value.status_code == 401
