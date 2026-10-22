"""Offline, append-only framework requirements version storage (Phase 4A).

No network operations, API routes, scoring or framework mapping modifications.
"""
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from app.services.framework_registry import ALL

ROOT = Path(os.environ.get('REQUIREMENTS_REGISTRY_DIR', '/var/lib/ai-vulnerability-management/requirements-versions'))
_VERSION = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')
_MAX_BYTES = 2 * 1024 * 1024


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _validate(framework, version, requirements, source):
    if framework not in ALL:
        raise ValueError('Unknown framework')
    if not isinstance(version, str) or not _VERSION.fullmatch(version) or version in ('.', '..'):
        raise ValueError('Invalid version identifier')
    if not isinstance(requirements, list) or not requirements or len(requirements) > 10000:
        raise ValueError('Requirements must be a nonempty list (maximum 10000)')
    ids = set()
    for item in requirements:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'].strip():
            raise ValueError('Every requirement must have a nonempty string id')
        if len(item['id']) > 200 or item['id'] in ids:
            raise ValueError('Duplicate or oversized requirement id')
        ids.add(item['id'])
        if any(not isinstance(k, str) for k in item):
            raise ValueError('Requirement keys must be strings')
    if not isinstance(source, dict) or not isinstance(source.get('publisher'), str) or not source['publisher'].strip():
        raise ValueError('Source must identify its publisher')
    if len(source['publisher']) > 255:
        raise ValueError('Publisher name too long')
    if len(_canonical({'requirements': requirements, 'source': source})) > _MAX_BYTES:
        raise ValueError('Requirements payload too large')


def _validate_regular_file(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Unsafe registry file type or link count')
    if info.st_mode & 0o022:
        raise ValueError('Registry file must not be group/world writable')
    return info


def _validate_dir(path):
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise ValueError('Unsafe registry directory')
    if info.st_uid != os.geteuid():
        raise ValueError('Registry directory ownership mismatch')


def _write_once(path, payload):
    """Create immutable-by-API file; never overwrite an existing version."""
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        raise


def _append_audit(path, event):
    if os.path.lexists(path):
        _validate_regular_file(path)
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError('Unsafe audit file')
        os.write(fd, _canonical(event) + b'\n')
        os.fsync(fd)
    finally:
        os.close(fd)


def _lock(root):
    path = root / '.registry.lock'
    if os.path.lexists(path):
        _validate_regular_file(path)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022:
        os.close(fd)
        raise ValueError('Unsafe registry lock')
    return fd


def _secure_dir(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_dir(path)


def list_versions(framework, root=None):
    if framework not in ALL:
        raise ValueError('Unknown framework')
    root = Path(root) if root is not None else ROOT
    folder = root / framework
    if not folder.exists():
        return []
    _validate_dir(root)
    _validate_dir(folder)
    versions = []
    for path in sorted(folder.glob('*.json')):
        _validate_regular_file(path)
        if path.stat().st_size > _MAX_BYTES + 8192:
            raise ValueError('Oversized version record')
        record = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(record, dict) or record.get('schema_version') != 1 or record.get('framework') != framework:
            raise ValueError('Invalid version record')
        if record.get('version') != path.stem or record.get('status') != 'staged':
            raise ValueError('Invalid version metadata')
        _validate(framework, record['version'], record['requirements'], record['source'])
        if not isinstance(record.get('actor'), str) or not record['actor'].strip():
            raise ValueError('Invalid actor metadata')
        if not isinstance(record.get('created_at'), str):
            raise ValueError('Invalid timestamp metadata')
        payload = {'requirements': record['requirements'], 'source': record['source']}
        if hashlib.sha256(_canonical(payload)).hexdigest() != record.get('sha256'):
            raise ValueError('Version integrity check failed')
        versions.append({k: record[k] for k in ('framework', 'version', 'sha256', 'created_at', 'actor', 'status')})
    return versions


def stage_version(framework, version, requirements, source, actor, root=None):
    """Store an unapproved version. Never changes active assessment mappings."""
    _validate(framework, version, requirements, source)
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError('Actor is required')
    root = Path(root) if root is not None else ROOT
    _secure_dir(root)
    fd = _lock(root)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        folder = root / framework
        _secure_dir(folder)
        payload = {'requirements': requirements, 'source': source}
        digest = hashlib.sha256(_canonical(payload)).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        record = {'schema_version': 1, 'framework': framework, 'version': version,
                  'requirements': requirements, 'source': source, 'sha256': digest,
                  'created_at': now, 'actor': actor[:255], 'status': 'staged'}
        target = folder / (version + '.json')
        if target.exists() or target.is_symlink():
            raise FileExistsError('Requirements version already exists')
        _write_once(target, _canonical(record) + b'\n')
        dir_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        # If audit fails, retain the immutable staged version for reconciliation.
        _append_audit(root / 'audit.jsonl', {'timestamp': now, 'actor': actor[:255],
                      'action': 'version_staged', 'framework': framework,
                      'version': version, 'sha256': digest})
        return {k: record[k] for k in ('framework', 'version', 'sha256', 'created_at', 'actor', 'status')}
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
