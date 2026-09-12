from types import SimpleNamespace

from app.api.control_readiness_v2 import (
    _collector_set_for_control,
    _validated_evidence_for_control,
)
from app.services.control_catalog_v2 import CONTROL_CATALOG
from app.services.evidence_collectors import COLLECTORS


def test_iam_users_primary_control_is_user_access_management():
    assert COLLECTORS["iam_users"]["control_ids"][0] == "AC-02"


def test_user_access_management_requires_iam_users_evidence():
    required_collectors = set(
        CONTROL_CATALOG["AC-02"]["required_collectors"]
    )

    assert "iam_users" in required_collectors


def test_validated_iam_users_evidence_supports_ac_02():
    evidence = [
        SimpleNamespace(
            asset_id="linux-server-01",
            collector="iam_users",
            evidence_type="iam_users",
            control_id="AC-02",
            frameworks={
                "pci_dss": ["7.2", "8.2"],
                "soc2": ["CC6.1", "CC6.2"],
                "nist_800_53": ["AC-2"],
                "iso_27001": ["A.5.15", "A.5.16"],
                "iso_27002": ["5.15", "5.16"],
            },
            validated=True,
        )
    ]

    validated = _validated_evidence_for_control(
        evidence,
        "AC-02",
    )
    collectors = _collector_set_for_control(
        validated,
        "AC-02",
    )

    assert len(validated) == 1
    assert collectors == {"iam_users"}
