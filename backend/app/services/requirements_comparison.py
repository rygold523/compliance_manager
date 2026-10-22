"""Offline, read-only comparison of immutable framework requirement versions.

No network, persistence, lifecycle transitions, or assessment mapping changes.
"""
import hashlib
import json
import os
from pathlib import Path

from app.services import requirements_registry as registry
from app.services.framework_registry import ALL


def _load(framework, version, root):
    if framework not in ALL:
        raise ValueError('Unknown framework')
    if not isinstance(version, str) or not registry._VERSION.fullmatch(version) or version in ('.', '..'):
        raise ValueError('Invalid version identifier')
    folder = root / framework
    if not folder.exists():
        raise ValueError('Requirements version does not exist')
    registry._validate_dir(root)
    registry._validate_dir(folder)
    path = folder / (version + '.json')
    try:
        info = registry._validate_regular_file(path)
    except FileNotFoundError as exc:
        raise ValueError('Requirements version does not exist') from exc
    if info.st_size > registry._MAX_BYTES + 8192:
        raise ValueError('Oversized version record')
    # Open without following symlinks, then validate the opened descriptor.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        import stat
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_mode & 0o022:
            raise ValueError('Unsafe registry file type or link count')
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('Requirements version changed during read')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(registry._MAX_BYTES + 8193)
        if len(raw) > registry._MAX_BYTES + 8192:
            raise ValueError('Oversized version record')
    finally:
        os.close(fd)
    record = json.loads(raw)
    if not isinstance(record, dict) or record.get('schema_version') != 1 or record.get('framework') != framework or record.get('version') != version or record.get('status') != 'staged':
        raise ValueError('Invalid version record')
    registry._validate(framework, version, record['requirements'], record['source'])
    if not isinstance(record.get('actor'), str) or not record['actor'].strip() or not isinstance(record.get('created_at'), str):
        raise ValueError('Invalid version metadata')
    payload = {'requirements': record['requirements'], 'source': record['source']}
    digest = hashlib.sha256(registry._canonical(payload)).hexdigest()
    if digest != record.get('sha256'):
        raise ValueError('Version integrity check failed')
    return record


def compare_versions(framework, from_version, to_version, root=None):
    """Compare two stored versions without changing registry or lifecycle state."""
    root = Path(root) if root is not None else registry.ROOT
    before = _load(framework, from_version, root)
    after = _load(framework, to_version, root)
    old = {item['id']: item for item in before['requirements']}
    new = {item['id']: item for item in after['requirements']}
    old_ids, new_ids = set(old), set(new)
    shared = old_ids & new_ids
    added = sorted(new_ids - old_ids)
    removed = sorted(old_ids - new_ids)
    modified = sorted(key for key in shared if registry._canonical(old[key]) != registry._canonical(new[key]))
    unchanged = sorted(shared - set(modified))
    return {
        'framework': framework,
        'from_version': from_version,
        'to_version': to_version,
        'from_sha256': before['sha256'],
        'to_sha256': after['sha256'],
        'added': added,
        'removed': removed,
        'modified': modified,
        'unchanged': unchanged,
        'counts': {'added': len(added), 'removed': len(removed), 'modified': len(modified), 'unchanged': len(unchanged)},
        'read_only': True,
        'publisher_version_verified': False,
    }
