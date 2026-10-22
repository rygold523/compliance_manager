import pytest
from fastapi import HTTPException
from app.services import requirements_update_check as checks
from app.api import requirements_update_check as api


def test_no_outbound_network_by_default(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Outbound networking must not occur')
    monkeypatch.setattr('socket.getaddrinfo', forbidden)
    monkeypatch.setattr(checks.requests, 'get', forbidden)
    result = checks.check_framework('pci_dss', enabled=True)
    assert result['status'] == 'manual_verification_required'
    assert result['requirements_current'] is None
    assert result['requirements_version_verified'] is False


def test_disabled_framework_skipped():
    assert checks.check_framework('pci_dss', enabled=False)['status'] == 'disabled'


def test_soc2_requires_manual_verification():
    assert checks.check_framework('soc2', enabled=True)['status'] == 'manual_verification_required'


def test_all_checks_only_enabled():
    settings = [{'id': 'pci_dss', 'enabled': True}, {'id': 'soc2', 'enabled': False}]
    result = checks.check_all(settings=settings)
    assert [item['framework'] for item in result['results']] == ['pci_dss']


def test_unknown_framework_rejected():
    with pytest.raises(ValueError):
        checks.check_framework('not_a_framework', enabled=True)
    with pytest.raises(HTTPException) as err:
        api.check_updates('not_a_framework', _admin=object())
    assert err.value.status_code == 404


def test_routes_require_admin():
    from fastapi.routing import APIRoute
    routes = [r for r in api.router.routes if isinstance(r, APIRoute)]
    assert len(routes) == 2
    assert all(r.methods == {'POST'} for r in routes)
    assert all(any(dep.call.__name__ == 'dependency' for dep in r.dependant.dependencies) for r in routes)


def test_mock_publisher_check_never_claims_current():
    result = checks.check_framework('pci_dss', enabled=True, fetcher=lambda url: {'status': 'reachable'})
    assert result['status'] == 'publisher_reachable'
    assert result['requirements_current'] is None
    assert result['requirements_changed'] is None


def test_mock_failure_is_fail_closed():
    result = checks.check_framework('pci_dss', enabled=True, fetcher=lambda url: (_ for _ in ()).throw(OSError('fail')))
    assert result['status'] == 'check_failed'
    assert result['requirements_version_verified'] is False


def test_source_urls_are_https_exact_hosts():
    for host, path in checks.SOURCES.values():
        assert host and not host.startswith('.') and '/' not in host
        assert path.startswith('/') and not path.startswith('//')


def test_static_route_precedes_framework_route():
    from fastapi.routing import APIRoute
    routes = [r.path for r in api.router.routes if isinstance(r, APIRoute)]
    assert routes == [
        '/api/admin/frameworks/requirements/check-all-updates',
        '/api/admin/frameworks/{framework_id}/requirements/check-updates',
    ]
