from types import SimpleNamespace

from app.api.windows_agent import COLLECTOR_CONTROL_MAP
from app.services import evidence_collectors


def test_windows_inventory_collectors_are_registered_for_ingestion():
    assert {
        "os_inventory",
        "disk_usage",
        "package_inventory",
        "available_updates",
    }.issubset(COLLECTOR_CONTROL_MAP)


def test_linux_ssh_collector_is_skipped_for_windows_asset(monkeypatch):
    asset = SimpleNamespace(
        asset_id="windows-a",
        address="192.0.2.20",
        ssh_user="",
        ssh_port=5985,
        os_family="windows",
    )

    def unexpected_ssh_call(**kwargs):
        raise AssertionError("SSH must not run for a Windows asset")

    monkeypatch.setattr(
        evidence_collectors,
        "run_ssh_command",
        unexpected_ssh_call,
    )

    result = evidence_collectors.run_collector(
        asset,
        "os_inventory",
    )

    assert result["status"] == "skipped"
    assert result["asset_id"] == "windows-a"
