"""Offline API contract tests for read-only requirements comparison."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.api import requirements_comparison as api
from app.services import requirements_registry as registry


def _admin():
    return SimpleNamespace(username='operator', role='admin')


def _stage(root, version, requirements):
    registry.stage_version('pci_dss', version, requirements,
                           {'publisher': 'Test publisher'}, 'operator', root=root)


def test_single_admin_protected_get_route():
    assert len(api.router.routes) == 1
    route = api.router.routes[0]
    assert route.path == '/api/admin/frameworks/{framework_id}/requirements/compare'
    assert 'GET' in route.methods
    auth = next(dep.call for dep in route.dependant.dependencies
                if dep.call.__name__ == 'dependency')
    req = Request({'type': 'http', 'method': 'GET', 'path': '/'})
    with pytest.raises(HTTPException) as exc:
        auth(req)
    assert exc.value.status_code == 401
    req.state.auth_user = SimpleNamespace(username='auditor', role='auditor')
    with pytest.raises(HTTPException) as exc:
        auth(req)
    assert exc.value.status_code == 403
    req.state.auth_user = _admin()
    assert auth(req).role == 'admin'


def test_read_only_comparison_and_identical_versions(tmp_path, monkeypatch):
    root = tmp_path / 'registry'
    monkeypatch.setattr(registry, 'ROOT', root)
    _stage(root, 'v1', [{'id': 'A', 'title': 'Old'}, {'id': 'B'}])
    _stage(root, 'v2', [{'id': 'A', 'title': 'New'}, {'id': 'C'}])
    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    result = api.compare_requirements('pci_dss', 'v1', 'v2', _admin())
    assert result['added'] == ['C']
    assert result['removed'] == ['B']
    assert result['modified'] == ['A']
    assert result['read_only'] is True
    assert result['publisher_version_verified'] is False
    same = api.compare_requirements('pci_dss', 'v1', 'v1', _admin())
    assert same['counts'] == {'added': 0, 'removed': 0, 'modified': 0, 'unchanged': 2}
    after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert before == after


@pytest.mark.parametrize('framework,from_v,to_v,code', [
    ('unknown', 'v1', 'v2', 404),
    ('pci_dss', '../bad', 'v2', 422),
    ('pci_dss', 'v1', '../bad', 422),
    ('pci_dss', 'missing', 'v2', 409),
])
def test_invalid_inputs(tmp_path, monkeypatch, framework, from_v, to_v, code):
    root = tmp_path / 'registry'
    monkeypatch.setattr(registry, 'ROOT', root)
    _stage(root, 'v1', [{'id': 'A'}])
    _stage(root, 'v2', [{'id': 'B'}])
    with pytest.raises(HTTPException) as exc:
        api.compare_requirements(framework, from_v, to_v, _admin())
    assert exc.value.status_code == code


def test_missing_staging_audit_blocks(tmp_path, monkeypatch):
    root = tmp_path / 'registry'
    monkeypatch.setattr(registry, 'ROOT', root)
    _stage(root, 'v1', [{'id': 'A'}])
    _stage(root, 'v2', [{'id': 'B'}])
    (root / 'audit.jsonl').unlink()
    with pytest.raises(HTTPException) as exc:
        api.compare_requirements('pci_dss', 'v1', 'v2', _admin())
    assert exc.value.status_code == 409


def test_corrupt_version_blocks(tmp_path, monkeypatch):
    root = tmp_path / 'registry'
    monkeypatch.setattr(registry, 'ROOT', root)
    _stage(root, 'v1', [{'id': 'A'}])
    _stage(root, 'v2', [{'id': 'B'}])
    (root / 'pci_dss' / 'v2.json').write_text('{}', encoding='utf-8')
    with pytest.raises(HTTPException) as exc:
        api.compare_requirements('pci_dss', 'v1', 'v2', _admin())
    assert exc.value.status_code == 409


def test_invalid_lifecycle_chain_blocks(tmp_path, monkeypatch):
    root = tmp_path / 'registry'
    monkeypatch.setattr(registry, 'ROOT', root)
    _stage(root, 'v1', [{'id': 'A'}])
    _stage(root, 'v2', [{'id': 'B'}])
    (root / 'lifecycle.jsonl').write_text('{"seq": 2}\n', encoding='utf-8')
    with pytest.raises(HTTPException) as exc:
        api.compare_requirements('pci_dss', 'v1', 'v2', _admin())
    assert exc.value.status_code == 409
