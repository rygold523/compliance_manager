"""Offline API contract regression tests; no database or HTTP client needed."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.api import requirements_management as api
from app.services import requirements_registry as registry
from app.services import requirements_lifecycle as lifecycle


def test_routes_admin_protected():
    paths = {route.path: route for route in api.router.routes}
    assert len(paths) == 8
    assert all(path.startswith('/api/admin/frameworks/') for path in paths)
    for route in paths.values():
        assert any(dep.call.__name__ == 'dependency' for dep in route.dependant.dependencies)


def test_auth_denies_missing_and_nonadmin():
    for route in api.router.routes:
        auth = next(dep.call for dep in route.dependant.dependencies if dep.call.__name__ == 'dependency')
        req = Request({'type': 'http', 'method': 'GET', 'path': '/'})
        with pytest.raises(HTTPException) as exc:
            auth(req)
        assert exc.value.status_code == 401
        req.state.auth_user = SimpleNamespace(username='auditor', role='auditor')
        with pytest.raises(HTTPException) as exc:
            auth(req)
        assert exc.value.status_code == 403
        req.state.auth_user = SimpleNamespace(username='admin', role='admin')
        assert auth(req).username == 'admin'


def test_offline_lifecycle_api(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, 'ROOT', tmp_path / 'requirements')
    admin = SimpleNamespace(username='operator')
    reqs = [{'id': 'R1', 'title': 'Test requirement'}]
    source = {'publisher': 'Test publisher'}
    assert api.get_requirements_status('pci_dss', admin)['published_version'] is None
    a = api.stage_requirements('pci_dss', api.StageRequest(version='v1', requirements=reqs, source=source), admin)
    assert a['actor'] == 'operator'
    with pytest.raises(HTTPException) as exc:
        api.stage_requirements('pci_dss', api.StageRequest(version='v1', requirements=reqs, source=source), admin)
    assert exc.value.status_code == 409
    reason = api.ReasonRequest(reason='Verified source and change')
    with pytest.raises(HTTPException) as exc:
        api.publish_requirements('pci_dss', 'v1', reason, admin)
    assert exc.value.status_code == 409
    assert api.get_requirements_versions('pci_dss', admin)['versions'][0]['status'] == 'staged'
    api.approve_requirements('pci_dss', 'v1', reason, admin)
    api.publish_requirements('pci_dss', 'v1', reason, admin)
    assert api.get_requirements_status('pci_dss', admin)['published_version'] == 'v1'
    api.stage_requirements('pci_dss', api.StageRequest(version='v2', requirements=reqs, source=source), admin)
    api.approve_requirements('pci_dss', 'v2', reason, admin)
    api.publish_requirements('pci_dss', 'v2', reason, admin)
    api.rollback_requirements('pci_dss', 'v1', reason, admin)
    assert api.get_requirements_status('pci_dss', admin)['published_version'] == 'v1'
    assert api.get_requirements_audit_gaps('pci_dss', admin)['audit_gaps'] == []
    with pytest.raises(HTTPException) as exc:
        api.reconcile_requirements_audit('pci_dss', 'v1', reason, admin)
    assert exc.value.status_code == 409


def test_unknown_framework_and_invalid_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, 'ROOT', tmp_path / 'requirements')
    admin = SimpleNamespace(username='operator')
    with pytest.raises(HTTPException) as exc:
        api.get_requirements_status('unknown', admin)
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException) as exc:
        api.stage_requirements('pci_dss', api.StageRequest(version='../bad', requirements=[{'id': 'R1'}], source={'publisher': 'test'}), admin)
    assert exc.value.status_code == 422
    assert not (tmp_path / 'requirements').exists()


def test_reconciliation(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, 'ROOT', tmp_path / 'requirements')
    admin = SimpleNamespace(username='operator')
    api.stage_requirements('soc2', api.StageRequest(version='v1', requirements=[{'id': 'CC1'}], source={'publisher': 'Test'}), admin)
    (registry.ROOT / 'audit.jsonl').unlink()
    assert api.get_requirements_audit_gaps('soc2', admin)['audit_gaps'] == ['v1']
    with pytest.raises(HTTPException) as exc:
        api.approve_requirements('soc2', 'v1', api.ReasonRequest(reason='Reviewed'), admin)
    assert exc.value.status_code == 409
    api.reconcile_requirements_audit('soc2', 'v1', api.ReasonRequest(reason='Recovered failed audit append'), admin)
    assert api.get_requirements_audit_gaps('soc2', admin)['audit_gaps'] == []
