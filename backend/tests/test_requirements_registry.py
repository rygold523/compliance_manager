import json
import os
import stat
import pytest
from app.services.requirements_registry import list_versions, stage_version


def test_offline_staging_is_immutable_and_private(tmp_path):
    root = tmp_path / 'registry'
    result = stage_version('pci_dss', '4.0.1', [{'id': '1.1', 'title': 'Test'}],
                           {'publisher': 'Test publisher'}, 'admin', root=root)
    assert result['status'] == 'staged'
    assert list_versions('pci_dss', root=root) == [result]
    assert stat.S_IMODE((root / 'pci_dss' / '4.0.1.json').stat().st_mode) == 0o600
    assert stat.S_IMODE((root / 'audit.jsonl').stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        stage_version('pci_dss', '4.0.1', [{'id': '1.1'}], {'publisher': 'X'}, 'admin', root=root)
    assert len((root / 'audit.jsonl').read_text().splitlines()) == 1


def test_invalid_payload_does_not_write(tmp_path):
    with pytest.raises(ValueError):
        stage_version('unknown', 'v1', [{'id': 'A'}], {'publisher': 'X'}, 'admin', root=tmp_path / 'registry')
    with pytest.raises(ValueError):
        stage_version('pci_dss', '../escape', [{'id': 'A'}], {'publisher': 'X'}, 'admin', root=tmp_path / 'registry')
    with pytest.raises(ValueError):
        stage_version('pci_dss', 'v1', [{'id': 'A'}, {'id': 'A'}], {'publisher': 'X'}, 'admin', root=tmp_path / 'registry')
    assert not (tmp_path / 'registry').exists()


def test_detect_tampering(tmp_path):
    root = tmp_path / 'registry'
    stage_version('soc2', 'v1', [{'id': 'CC1'}], {'publisher': 'X'}, 'admin', root=root)
    path = root / 'soc2' / 'v1.json'
    data = json.loads(path.read_text())
    data['requirements'][0]['id'] = 'ALTERED'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='integrity'):
        list_versions('soc2', root=root)


def test_all_frameworks_empty(tmp_path):
    assert list_versions('hipaa', root=tmp_path / 'absent') == []


def test_version_metadata_mismatch_is_rejected(tmp_path):
    root = tmp_path / 'registry'
    stage_version('pci_dss', 'v1', [{'id': '1'}], {'publisher': 'X'}, 'admin', root=root)
    path = root / 'pci_dss' / 'v1.json'
    record = json.loads(path.read_text())
    record['version'] = 'v2'
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match='metadata'):
        list_versions('pci_dss', root=root)


def test_unsafe_version_permissions_rejected(tmp_path):
    root = tmp_path / 'registry'
    stage_version('pci_dss', 'v1', [{'id': '1'}], {'publisher': 'X'}, 'admin', root=root)
    path = root / 'pci_dss' / 'v1.json'
    path.chmod(0o666)
    with pytest.raises(ValueError, match='writable'):
        list_versions('pci_dss', root=root)


def test_symlinked_version_rejected(tmp_path):
    root = tmp_path / 'registry'
    stage_version('pci_dss', 'v1', [{'id': '1'}], {'publisher': 'X'}, 'admin', root=root)
    path = root / 'pci_dss' / 'v1.json'
    path.rename(root / 'pci_dss' / 'original')
    path.symlink_to(root / 'pci_dss' / 'original')
    with pytest.raises(ValueError, match='Unsafe registry file'):
        list_versions('pci_dss', root=root)


def test_unsafe_audit_permissions_rejected(tmp_path):
    root = tmp_path / 'registry'
    stage_version('pci_dss', 'v1', [{'id': '1'}], {'publisher': 'X'}, 'admin', root=root)
    (root / 'audit.jsonl').chmod(0o666)
    with pytest.raises(ValueError, match='writable'):
        stage_version('pci_dss', 'v2', [{'id': '2'}], {'publisher': 'X'}, 'admin', root=root)
