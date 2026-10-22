import json
import pytest
from app.services import requirements_registry as registry
from app.services import requirements_lifecycle as lifecycle


def stage(root, version):
    return registry.stage_version('pci_dss', version, [{'id': '1.1', 'title': version}],
                                  {'publisher': 'Test'}, 'admin', root=root)


def test_full_lifecycle_and_rollback(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    stage(root, 'v2')
    assert lifecycle.lifecycle_status('pci_dss', root)['published_version'] is None
    lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', 'reviewed', root)
    lifecycle.transition('pci_dss', 'v1', 'publish', 'admin', 'publish', root)
    lifecycle.transition('pci_dss', 'v2', 'approve', 'admin', 'reviewed', root)
    lifecycle.transition('pci_dss', 'v2', 'publish', 'admin', 'supersedes', root)
    lifecycle.transition('pci_dss', 'v1', 'rollback', 'admin', 'restore', root)
    status = lifecycle.lifecycle_status('pci_dss', root)
    assert status['published_version'] == 'v1'
    assert {v['version']: v['status'] for v in status['versions']} == {'v1': 'published', 'v2': 'approved'}
    assert len(registry.list_versions('pci_dss', root)) == 2


def test_reject_unapproved_and_invalid_transitions(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    with pytest.raises(ValueError):
        lifecycle.transition('pci_dss', 'v1', 'publish', 'admin', 'premature', root)
    with pytest.raises(ValueError):
        lifecycle.transition('pci_dss', 'v1', 'rollback', 'admin', 'premature', root)
    with pytest.raises(ValueError):
        lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', '', root)
    lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', 'reviewed', root)
    with pytest.raises(ValueError):
        lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', 'duplicate', root)


def test_detect_lifecycle_tampering(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', 'reviewed', root)
    path = root / 'lifecycle.jsonl'
    events = [json.loads(line) for line in path.read_text().splitlines()]
    events[0]['actor'] = 'intruder'
    path.write_text('\n'.join(json.dumps(e) for e in events) + '\n')
    with pytest.raises(ValueError, match='integrity'):
        lifecycle.lifecycle_status('pci_dss', root)


def test_detect_and_reconcile_missing_stage_audit(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    (root / 'audit.jsonl').unlink()
    assert lifecycle.audit_gaps('pci_dss', root) == ['v1']
    with pytest.raises(ValueError, match='audit gap'):
        lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', 'reviewed', root)
    event = lifecycle.reconcile_staging_audit('pci_dss', 'v1', 'admin', 'verified interrupted write', root)
    assert event['reconciled'] is True
    assert lifecycle.audit_gaps('pci_dss', root) == []
    lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', 'reviewed', root)


def test_reject_rollback_to_never_published(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    stage(root, 'v2')
    lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', 'ok', root)
    lifecycle.transition('pci_dss', 'v1', 'publish', 'admin', 'ok', root)
    lifecycle.transition('pci_dss', 'v2', 'approve', 'admin', 'ok', root)
    with pytest.raises(ValueError, match='never been published'):
        lifecycle.transition('pci_dss', 'v2', 'rollback', 'admin', 'no', root)


def test_no_registry_is_empty(tmp_path):
    assert lifecycle.lifecycle_status('soc2', tmp_path / 'missing')['versions'] == []


def _replace_staging_event(root, transform):
    path = root / 'audit.jsonl'
    events = [json.loads(line) for line in path.read_text().splitlines()]
    transform(events)
    path.write_text(''.join(json.dumps(e) + '\n' for e in events))


def _append_valid_lifecycle_event(root, action, framework, version):
    events = lifecycle._read_lifecycle(root)
    lifecycle._append(root, events, action, framework, version, 'admin', 'test sequence')


def test_reject_conflicting_stage_audit(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    _replace_staging_event(root, lambda events: events[0].update(sha256='0' * 64))
    with pytest.raises(ValueError, match='digest mismatch'):
        lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', 'reviewed', root)


def test_reject_duplicate_stage_audit(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    _replace_staging_event(root, lambda events: events.append(dict(events[0])))
    with pytest.raises(ValueError, match='Duplicate or conflicting'):
        lifecycle.lifecycle_status('pci_dss', root)


def test_reject_malformed_stage_audit(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    _replace_staging_event(root, lambda events: events[0].pop('actor'))
    with pytest.raises(ValueError, match='actor'):
        lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', 'reviewed', root)


def test_reject_invalid_other_framework_sequence(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    _append_valid_lifecycle_event(root, 'published', 'soc2', 'v9')
    with pytest.raises(ValueError, match='publication sequence'):
        lifecycle.lifecycle_status('pci_dss', root)
    with pytest.raises(ValueError, match='publication sequence'):
        lifecycle.transition('pci_dss', 'v1', 'approve', 'admin', 'reviewed', root)


def test_reject_duplicate_approval_in_other_framework(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    _append_valid_lifecycle_event(root, 'approved', 'soc2', 'v9')
    _append_valid_lifecycle_event(root, 'approved', 'soc2', 'v9')
    with pytest.raises(ValueError, match='Duplicate approval'):
        lifecycle.lifecycle_status('pci_dss', root)


def test_reject_other_framework_missing_version(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    _append_valid_lifecycle_event(root, 'approved', 'soc2', 'v9')
    with pytest.raises(ValueError, match='missing version'):
        lifecycle.lifecycle_status('pci_dss', root)


def test_reject_malformed_reconciliation(tmp_path):
    root = tmp_path / 'registry'
    stage(root, 'v1')
    _replace_staging_event(root, lambda events: events[0].update(reconciled=True))
    with pytest.raises(ValueError, match='reconciliation'):
        lifecycle.lifecycle_status('pci_dss', root)
