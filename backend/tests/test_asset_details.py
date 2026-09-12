import json

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.api import asset_details
from app.core.database import Base
from app.models import Asset, Evidence


def _write_payload(path, collector, payload):
    path.write_text(
        json.dumps(
            {
                "collector": collector,
                "status": "completed",
                "stdout": json.dumps(payload),
            }
        )
    )


def test_asset_details_uses_bulk_latest_evidence_queries(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    asset = Asset(
        asset_id="asset-a",
        hostname="host-a",
        address="192.0.2.10",
        environment="test",
        agent_status="deployed",
    )
    session.add(asset)
    session.flush()

    old_path = tmp_path / "old-os.json"
    new_path = tmp_path / "new-os.json"
    package_path = tmp_path / "packages.json"
    disk_path = tmp_path / "disk.json"
    _write_payload(old_path, "os_inventory", {"os_name": "Old OS"})
    _write_payload(
        new_path,
        "os_inventory",
        {
            "os_release": {
                "PRETTY_NAME": "Current OS",
                "VERSION_ID": "1",
            },
            "kernel": "6.0",
        },
    )
    _write_payload(
        package_path,
        "package_inventory",
        {
            "packages": [
                {
                    "name": "example",
                    "installed_version": "1",
                    "latest_candidate": "2",
                    "update_available": "yes",
                    "held": "no",
                }
            ]
        },
    )
    _write_payload(disk_path, "disk_usage", {"disk_total": "20G"})

    for index, (collector, path) in enumerate(
        (
            ("os_inventory", old_path),
            ("os_inventory", new_path),
            ("package_inventory", package_path),
            ("disk_usage", disk_path),
        ),
        start=1,
    ):
        session.add(
            Evidence(
                evidence_id=f"EV-{index}",
                asset_id="asset-a",
                filename=path.name,
                file_path=str(path),
                source="collector",
                collector=collector,
                validated=True,
            )
        )
    session.commit()

    asset_details._DETAIL_CACHE.update(state=None, response=None)
    select_count = 0

    @event.listens_for(engine, "before_cursor_execute")
    def count_selects(
        connection,
        cursor,
        statement,
        parameters,
        context,
        executemany,
    ):
        nonlocal select_count
        if statement.lstrip().upper().startswith("SELECT"):
            select_count += 1

    response = asset_details.list_asset_details(session)

    assert select_count == 3
    assert response["asset_count"] == 1
    assert response["assets"][0]["os_name"] == "Current OS"
    assert response["assets"][0]["package_count"] == 1
    assert response["assets"][0]["packages_with_updates"] == 1
    assert response["assets"][0]["resources"]["disk_total"] == "20G"

    select_count = 0
    cached = asset_details.list_asset_details(session)
    assert select_count == 2
    assert cached == response


def test_asset_details_parses_windows_inventory(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    session.add(
        Asset(
            asset_id="windows-a",
            hostname="WIN-TEST",
            address="192.0.2.20",
            environment="test",
            agent_status="deployed",
            os_family="windows",
        )
    )
    session.flush()

    payloads = {
        "os_inventory": {
            "os_name": "Microsoft Windows Server 2019 Standard",
            "os_version": "10.0.17763",
            "kernel_version": "10.0.17763 (Build 17763)",
        },
        "disk_usage": {
            "cpu_cores": 8,
            "memory_total_mb": 16384,
            "disk_total": "100G",
        },
        "package_inventory": {
            "packages": [
                {
                    "name": "Example Application",
                    "installed_version": "1.0",
                    "latest_candidate": "1.0",
                    "update_available": "no",
                    "held": "no",
                }
            ]
        },
        "available_updates": {
            "query_succeeded": True,
            "available_count": 3,
            "updates": [],
        },
    }

    for index, (collector, payload) in enumerate(
        payloads.items(),
        start=1,
    ):
        path = tmp_path / f"{collector}.json"
        path.write_text(
            json.dumps(
                {
                    "collector": collector,
                    "status": "completed",
                    "validated": True,
                    "raw": payload,
                    **payload,
                }
            )
        )
        session.add(
            Evidence(
                evidence_id=f"EV-WIN-{index}",
                asset_id="windows-a",
                filename=path.name,
                file_path=str(path),
                source="windows_agent",
                collector=collector,
                validated=True,
            )
        )

    session.commit()
    asset_details._DETAIL_CACHE.update(state=None, response=None)

    response = asset_details.list_asset_details(session)
    result = response["assets"][0]

    assert result["os_name"] == "Microsoft Windows Server 2019 Standard"
    assert result["os_version"] == "10.0.17763"
    assert result["kernel_version"] == "10.0.17763 (Build 17763)"
    assert result["resources"]["cpu_cores"] == "8"
    assert result["resources"]["memory_total_mb"] == "16384"
    assert result["resources"]["disk_total"] == "100G"
    assert result["package_count"] == 1
    assert result["packages_with_updates"] == 3
