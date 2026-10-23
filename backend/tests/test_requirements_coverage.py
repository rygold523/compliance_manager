"""Offline tests; no persistent registry or control catalog writes."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.api import requirements_coverage as api
from app.services import requirements_coverage as svc


def test_admin_protection():
    route = api.router.routes[0]
    assert route.path == '/api/admin/frameworks/pci_dss/requirements/coverage'
    dep = route.dependant.dependencies[0].call
    req = Request({'type': 'http', 'method': 'GET', 'path': '/'})
    with pytest.raises(HTTPException) as exc:
        dep(req)
    assert exc.value.status_code == 401
    req.state.auth_user = SimpleNamespace(username='auditor', role='auditor')
    with pytest.raises(HTTPException) as exc:
        dep(req)
    assert exc.value.status_code == 403


def test_no_catalog_does_not_claim_zero_coverage(monkeypatch):
    monkeypatch.setattr(svc.lifecycle, 'lifecycle_status', lambda _: {'published_version': None, 'audit_gaps': [], 'versions': []})
    monkeypatch.setattr(svc, 'list_controls', lambda: [{'control_id': 'A', 'framework_mappings': {'pci_dss': ['1.2']}}])
    result = svc.coverage()
    assert result['catalog_status'] == 'catalog_unavailable'
    assert result['coverage_percentage'] is None
    assert result['compliance_determination'] is False


def test_exact_mapping_no_parent_expansion(monkeypatch):
    monkeypatch.setattr(svc.lifecycle, 'lifecycle_status', lambda _: {'published_version': 'v1', 'audit_gaps': [], 'versions': [{'version': 'v1'}]})
    monkeypatch.setattr(svc.comparison, '_load', lambda *args: {'framework': 'pci_dss', 'version': 'v1', 'requirements': [{'id': '6.3'}, {'id': '6.3.3'}, {'id': '8.2'}]})
    monkeypatch.setattr(svc, 'list_controls', lambda: [
        {'control_id': 'A', 'framework_mappings': {'pci_dss': ['6.3', '9.9', '9.9']}},
        {'control_id': 'B', 'framework_mappings': {'pci_dss': ['8.2']}},
    ])
    result = svc.coverage()
    assert result['total_requirements'] == 3
    assert result['mapped_requirements'] == 2
    assert result['unmapped_requirements'] == 1
    assert result['coverage_percentage'] == 66.67
    assert result['unmatched_mappings'] == [{'id': '9.9', 'controls': ['A']}]
    assert next(row for row in result['requirements'] if row['id'] == '6.3.3')['mapping_status'] == 'unmapped'


def test_audit_gap_fails_closed(monkeypatch):
    monkeypatch.setattr(svc.lifecycle, 'lifecycle_status', lambda _: {'published_version': None, 'audit_gaps': ['v1']})
    with pytest.raises(ValueError, match='audit gaps'):
        svc.coverage()


def test_corrupt_record_fails_closed(monkeypatch):
    monkeypatch.setattr(svc.lifecycle, 'lifecycle_status', lambda _: {'published_version': 'v1', 'audit_gaps': [], 'versions': [{'version': 'v1'}]})
    def bad_load(*args):
        raise ValueError('integrity mismatch')
    monkeypatch.setattr(svc.comparison, '_load', bad_load)
    with pytest.raises(ValueError, match='integrity'):
        svc.coverage()


# STEP 128K-56 ADDITIONAL REGRESSION TESTS


def test_duplicate_control_mappings_are_deduplicated(monkeypatch):
    monkeypatch.setattr(
        svc.lifecycle,
        'lifecycle_status',
        lambda _: {
            'published_version': 'v1',
            'audit_gaps': [],
            'versions': [{'version': 'v1'}],
        },
    )
    monkeypatch.setattr(
        svc.comparison,
        '_load',
        lambda *args: {
            'framework': 'pci_dss',
            'version': 'v1',
            'requirements': [{'id': '1.2'}],
        },
    )
    monkeypatch.setattr(
        svc,
        'list_controls',
        lambda: [
            {
                'control_id': 'A',
                'framework_mappings': {
                    'pci_dss': ['1.2', '1.2'],
                },
            },
            {
                'control_id': 'B',
                'framework_mappings': {
                    'pci_dss': ['1.2'],
                },
            },
        ],
    )

    result = svc.coverage()

    assert result['total_requirements'] == 1
    assert result['mapped_requirements'] == 1
    assert result['coverage_percentage'] == 100.0
    assert result['requirements'][0]['mapped_controls'] == ['A', 'B']


@pytest.mark.parametrize(
    'invalid_reference',
    ['', None, True, {}, []],
)
def test_invalid_requirement_references_fail_closed(
    monkeypatch,
    invalid_reference,
):
    monkeypatch.setattr(
        svc.lifecycle,
        'lifecycle_status',
        lambda _: {
            'published_version': None,
            'audit_gaps': [],
            'versions': [],
        },
    )
    monkeypatch.setattr(
        svc,
        'list_controls',
        lambda: [
            {
                'control_id': 'A',
                'framework_mappings': {
                    'pci_dss': [invalid_reference],
                },
            },
        ],
    )

    with pytest.raises(ValueError):
        svc.coverage()


def test_missing_published_version_fails_closed(monkeypatch):
    monkeypatch.setattr(
        svc.lifecycle,
        'lifecycle_status',
        lambda _: {
            'published_version': 'missing',
            'audit_gaps': [],
            'versions': [{'version': 'v1'}],
        },
    )

    with pytest.raises(ValueError, match='missing'):
        svc.coverage()


def test_registry_integrity_error_fails_closed(monkeypatch):
    def corrupt_registry(_):
        raise ValueError('Lifecycle integrity failure')

    monkeypatch.setattr(
        svc.lifecycle,
        'lifecycle_status',
        corrupt_registry,
    )

    with pytest.raises(ValueError, match='integrity'):
        svc.coverage()


def test_api_returns_conflict_on_validation_error(monkeypatch):
    def invalid_coverage(_):
        raise ValueError('Invalid requirements registry')

    monkeypatch.setattr(api, 'coverage', invalid_coverage)

    with pytest.raises(HTTPException) as exc:
        api.pci_dss_requirements_coverage()

    assert exc.value.status_code == 409
    assert exc.value.detail == 'Requirements coverage validation failed'


def test_api_returns_read_only_coverage(monkeypatch):
    expected = {
        'framework': 'pci_dss',
        'catalog_status': 'catalog_unavailable',
        'coverage_percentage': None,
        'read_only': True,
        'compliance_determination': False,
    }

    monkeypatch.setattr(
        api,
        'coverage',
        lambda _: expected,
    )

    result = api.pci_dss_requirements_coverage()

    assert result == expected
    assert result['compliance_determination'] is False


# STEP 128K-59 RECORD INTEGRITY TESTS


@pytest.mark.parametrize(
    'framework,version',
    [
        ('soc2', 'v1'),
        ('pci_dss', 'v2'),
    ],
)
def test_published_record_identity_mismatch_fails_closed(
    monkeypatch,
    framework,
    version,
):
    monkeypatch.setattr(
        svc.lifecycle,
        'lifecycle_status',
        lambda _: {
            'published_version': 'v1',
            'audit_gaps': [],
            'versions': [{'version': 'v1'}],
        },
    )

    monkeypatch.setattr(
        svc.comparison,
        '_load',
        lambda *args: {
            'framework': framework,
            'version': version,
            'requirements': [{'id': '1.2'}],
        },
    )

    with pytest.raises(ValueError, match='mismatch'):
        svc.coverage()


def test_published_record_requires_dictionary(monkeypatch):
    monkeypatch.setattr(
        svc.lifecycle,
        'lifecycle_status',
        lambda _: {
            'published_version': 'v1',
            'audit_gaps': [],
            'versions': [{'version': 'v1'}],
        },
    )

    monkeypatch.setattr(
        svc.comparison,
        '_load',
        lambda *args: None,
    )

    with pytest.raises(ValueError, match='Invalid published'):
        svc.coverage()
