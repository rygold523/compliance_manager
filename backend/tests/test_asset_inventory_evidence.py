from types import SimpleNamespace

from app.api.control_readiness_v2 import (
    _collector_set_for_control,
    _validated_evidence_for_control,
)
from app.services.control_catalog_v2 import CONTROL_CATALOG
from app.services.evidence_collectors import COLLECTORS


def test_os_inventory_primary_control_is_asset_inventory():
    assert COLLECTORS["os_inventory"]["control_ids"][0] == "AM-01"


def test_asset_inventory_requires_os_inventory():
    required_collectors = set(
        CONTROL_CATALOG["AM-01"]["required_collectors"]
    )

    assert required_collectors == {"os_inventory"}


def test_asset_details_collectors_are_identified_as_supporting():
    supporting_collectors = set(
        CONTROL_CATALOG["AM-01"]["supporting_collectors"]
    )

    assert supporting_collectors == {
        "package_inventory",
        "packages",
        "docker_inventory",
    }


def test_validated_os_inventory_evidence_supports_am_01():
    evidence = [
        SimpleNamespace(
            asset_id="linux-server-01",
            collector="os_inventory",
            evidence_type="os_inventory",
            control_id="AM-01",
            frameworks={
                "pci_dss": ["12.5"],
                "soc2": ["CC6.1", "CC8.1"],
                "nist_800_53": ["CM-8"],
                "iso_27001": ["A.5.9"],
                "iso_27002": ["5.9"],
            },
            validated=True,
        )
    ]

    validated = _validated_evidence_for_control(
        evidence,
        "AM-01",
    )
    collectors = _collector_set_for_control(
        validated,
        "AM-01",
    )

    assert len(validated) == 1
    assert collectors == {"os_inventory"}
