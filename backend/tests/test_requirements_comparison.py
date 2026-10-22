"""Offline regression tests for Phase 4D-1 comparison service."""
import json
import pytest
from app.services import requirements_registry as registry
from app.services.requirements_comparison import compare_versions


def _stage(root, version, requirements):
    registry.stage_version('pci_dss', version, requirements, {'publisher': 'Test publisher'}, 'admin', root=root)


def test_classification_and_determinism(tmp_path):
    root = tmp_path / 'registry'
    _stage(root, 'v1', [{'id': 'A', 'title': 'Old'}, {'id': 'B', 'title': 'Removed'}, {'id': 'D', 'title': 'Same'}])
    _stage(root, 'v2', [{'id': 'D', 'title': 'Same'}, {'id': 'C', 'title': 'Added'}, {'id': 'A', 'title': 'New'}])
    first = compare_versions('pci_dss', 'v1', 'v2', root)
    assert first['added'] == ['C']
    assert first['removed'] == ['B']
    assert first['modified'] == ['A']
    assert first['unchanged'] == ['D']
    assert first['counts'] == {'added': 1, 'removed': 1, 'modified': 1, 'unchanged': 1}
    assert first == compare_versions('pci_dss', 'v1', 'v2', root)
    assert first['read_only'] is True
    assert first['publisher_version_verified'] is False


def test_reordered_keys_are_not_modifications(tmp_path):
    root = tmp_path / 'registry'
    _stage(root, 'v1', [{'id': 'A', 'title': 'Same', 'detail': {'a': 1, 'b': 2}}])
    _stage(root, 'v2', [{'detail': {'b': 2, 'a': 1}, 'title': 'Same', 'id': 'A'}])
    assert compare_versions('pci_dss', 'v1', 'v2', root)['unchanged'] == ['A']


def test_invalid_and_missing_versions_fail_closed(tmp_path):
    root = tmp_path / 'registry'
    _stage(root, 'v1', [{'id': 'A'}])
    for version in ('../escape', 'missing'):
        with pytest.raises(ValueError):
            compare_versions('pci_dss', 'v1', version, root)
    with pytest.raises(ValueError):
        compare_versions('unknown', 'v1', 'v1', root)


def test_tampering_is_rejected(tmp_path):
    root = tmp_path / 'registry'
    _stage(root, 'v1', [{'id': 'A'}])
    record_path = root / 'pci_dss' / 'v1.json'
    record = json.loads(record_path.read_text())
    record['requirements'][0]['id'] = 'TAMPERED'
    record_path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match='integrity'):
        compare_versions('pci_dss', 'v1', 'v1', root)


def test_symlink_is_rejected(tmp_path):
    root = tmp_path / 'registry'
    _stage(root, 'v1', [{'id': 'A'}])
    path = root / 'pci_dss' / 'v1.json'
    path.rename(path.with_suffix('.saved'))
    path.symlink_to(path.with_suffix('.saved'))
    with pytest.raises(ValueError, match='Unsafe'):
        compare_versions('pci_dss', 'v1', 'v1', root)


def test_no_writes_to_registry(tmp_path):
    root = tmp_path / 'registry'
    _stage(root, 'v1', [{'id': 'A'}])
    _stage(root, 'v2', [{'id': 'A', 'title': 'New'}])
    before = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    compare_versions('pci_dss', 'v1', 'v2', root)
    after = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert before == after
