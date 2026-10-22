import json
import pytest
from app.services.framework_registry import BASELINE, OPTIONAL, read_registry, set_framework_enabled, is_enabled


def test_defaults(tmp_path):
    rows = {row['id']: row for row in read_registry(tmp_path / 'registry.json')}
    assert all(rows[k]['enabled'] and rows[k]['assessment_ready'] for k in BASELINE)
    assert all(not rows[k]['enabled'] and not rows[k]['assessment_ready'] for k in OPTIONAL)


@pytest.mark.parametrize('framework', ['pci_dss', 'soc2', 'nist_800_53', 'iso_27001', 'iso_27002', 'hipaa', 'gdpr', 'nist_csf', 'ccpa_cpra'])
def test_every_framework_can_toggle(tmp_path, framework):
    path = tmp_path / 'registry.json'
    set_framework_enabled(framework, False, path)
    assert not is_enabled(framework, path)
    set_framework_enabled(framework, True, path)
    assert is_enabled(framework, path)
    assert path.stat().st_mode & 0o777 == 0o600


def test_invalid_input_rejected(tmp_path):
    path = tmp_path / 'registry.json'
    with pytest.raises(ValueError):
        set_framework_enabled('unknown', True, path)
    with pytest.raises(ValueError):
        set_framework_enabled('hipaa', 'true', path)
    assert not path.exists()


def test_invalid_registry_fails_closed(tmp_path):
    path = tmp_path / 'registry.json'
    path.write_text(json.dumps({'schema_version': 1, 'enabled': {'hipaa': 'true'}}))
    with pytest.raises(ValueError):
        read_registry(path)


def test_audit_record_and_noop(tmp_path):
    path = tmp_path / 'registry.json'
    set_framework_enabled('pci_dss', False, path, actor='test-admin')
    audit = path.with_name(path.name + '.audit.jsonl')
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    assert len(entries) == 2
    assert [entry['outcome'] for entry in entries] == [
        'requested',
        'committed',
    ]
    for entry in entries:
        assert entry['actor'] == 'test-admin'
        assert entry['framework'] == 'pci_dss'
        assert entry['previous_enabled'] is True
        assert entry['enabled'] is False

    assert not is_enabled('pci_dss', path)

    set_framework_enabled('pci_dss', False, path, actor='test-admin')

    # Repeating the same setting must not create additional audit events.
    assert len(audit.read_text().splitlines()) == 2
    assert audit.stat().st_mode & 0o777 == 0o600
