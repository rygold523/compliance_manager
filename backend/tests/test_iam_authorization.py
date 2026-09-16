import inspect
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import iam, iam_db


def _role_dependency(endpoint):
    for parameter in inspect.signature(endpoint).parameters.values():
        if parameter.name not in {"_reviewer", "_admin"}:
            continue
        default = parameter.default
        dependency = getattr(default, "dependency", None)
        if dependency is not None:
            return dependency
    raise AssertionError(f"No role dependency found on {endpoint.__name__}")


def _request(role):
    return SimpleNamespace(
        state=SimpleNamespace(
            auth_user=SimpleNamespace(role=role)
        )
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        iam.snapshot,
        iam.users,
        iam.service_accounts,
        iam.access_matrix,
        iam.group_matrix,
        iam.service_account_matrix,
        iam_db.database_sources,
        iam_db.database_access,
        iam_db.database_collector_status,
    ],
)
def test_raw_iam_reads_allow_admin_and_auditor_but_reject_viewer(endpoint):
    dependency = _role_dependency(endpoint)
    assert dependency(_request("admin")).role == "admin"
    assert dependency(_request("auditor")).role == "auditor"

    with pytest.raises(HTTPException) as raised:
        dependency(_request("viewer"))
    assert raised.value.status_code == 403


def test_database_collection_trigger_is_admin_only():
    dependency = _role_dependency(iam_db.collect_database_iam)
    assert dependency(_request("admin")).role == "admin"

    for role in ("auditor", "viewer"):
        with pytest.raises(HTTPException) as raised:
            dependency(_request(role))
        assert raised.value.status_code == 403


def test_database_ingestion_remains_collector_token_authenticated():
    parameters = inspect.signature(iam_db.ingest_database_iam).parameters
    assert all(
        getattr(parameter.default, "dependency", None) is None
        for parameter in parameters.values()
    )
