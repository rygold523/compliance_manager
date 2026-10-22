"""Offline, append-only requirements publication lifecycle.

No API, networking, compliance scoring, or assessment mapping mutations.
An untrusted local filesystem administrator can rewrite files and hashes; this is
not a cryptographic non-repudiation mechanism.
"""
import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from app.services.framework_registry import ALL
from app.services import requirements_registry as registry

_MAX_LINE = 8192


def _digest(value):
    return hashlib.sha256(registry._canonical(value)).hexdigest()


def _actor(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 255:
        raise ValueError('A valid administrator actor is required')
    return value


def _read_jsonl(path):
    if not os.path.lexists(path):
        return []
    registry._validate_regular_file(path)
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('Audit ledger exceeds supported size')
    with open(path, 'rb') as handle:
        raw = handle.read()
    if raw and not raw.endswith(b'\n'):
        raise ValueError('Incomplete audit ledger line')
    entries = []
    for line in raw.splitlines():
        if not line or len(line) > _MAX_LINE:
            raise ValueError('Invalid audit ledger line')
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise ValueError('Invalid audit ledger event')
        entries.append(obj)
    return entries


def _read_lifecycle(root):
    events = _read_jsonl(root / 'lifecycle.jsonl')
    previous = '0' * 64
    states = {framework: (set(), None, set()) for framework in ALL}
    for index, event in enumerate(events, 1):
        if event.get('seq') != index or event.get('previous_hash') != previous:
            raise ValueError('Lifecycle ledger sequence/hash chain mismatch')
        content = {key: val for key, val in event.items() if key != 'event_hash'}
        if _digest(content) != event.get('event_hash'):
            raise ValueError('Lifecycle ledger integrity failure')
        action = event.get('action')
        framework = event.get('framework')
        version = event.get('version')
        if action not in ('approved', 'published', 'rolled_back'):
            raise ValueError('Unsupported lifecycle event')
        if framework not in ALL or not isinstance(version, str) or not registry._VERSION.fullmatch(version):
            raise ValueError('Invalid lifecycle event framework/version')
        if not isinstance(event.get('actor'), str) or not event['actor'].strip():
            raise ValueError('Invalid lifecycle actor')
        if not isinstance(event.get('reason'), str) or not event['reason'].strip():
            raise ValueError('Invalid lifecycle reason')
        if not isinstance(event.get('timestamp'), str) or not event['timestamp'].strip():
            raise ValueError('Invalid lifecycle timestamp')
        approved, published, previously_published = states[framework]
        if action == 'approved':
            if version in approved:
                raise ValueError('Duplicate approval event')
            approved.add(version)
        elif action == 'published':
            if version not in approved or version == published:
                raise ValueError('Invalid publication sequence')
            published = version
            previously_published.add(version)
        else:
            if published is None or version not in approved or version == published or version not in previously_published:
                raise ValueError('Invalid rollback sequence')
            published = version
        states[framework] = (approved, published, previously_published)
        previous = event['event_hash']
    return events


def _state(events, framework):
    approved = set()
    published = None
    for event in events:
        if event['framework'] != framework:
            continue
        version = event['version']
        if event['action'] == 'approved':
            approved.add(version)
        else:
            published = version
    return approved, published


def _verified_versions(framework, root):
    return {item['version']: item for item in registry.list_versions(framework, root=root)}


def _audit_missing(root, framework, versions):
    # Validate the full staging audit ledger, including unrelated frameworks.
    # Missing events may be reconciled explicitly; conflicting events fail closed.
    events = _read_jsonl(root / 'audit.jsonl')
    staged = {}
    for event in events:
        if event.get('action') != 'version_staged':
            raise ValueError('Unsupported staging audit event')
        fw, ver, digest = event.get('framework'), event.get('version'), event.get('sha256')
        if fw not in ALL or not isinstance(ver, str) or not registry._VERSION.fullmatch(ver):
            raise ValueError('Invalid staging audit framework/version')
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('Invalid staging audit digest')
        if not isinstance(event.get('actor'), str) or not event['actor'].strip():
            raise ValueError('Invalid staging audit actor')
        if not isinstance(event.get('timestamp'), str) or not event['timestamp'].strip():
            raise ValueError('Invalid staging audit timestamp')
        if 'reconciled' in event:
            if event['reconciled'] is not True or not isinstance(event.get('reason'), str) or not event['reason'].strip():
                raise ValueError('Invalid staging audit reconciliation')
        key = (fw, ver)
        if key in staged:
            raise ValueError('Duplicate or conflicting staging audit event')
        staged[key] = digest
    for version, record in versions.items():
        existing = staged.get((framework, version))
        if existing is not None and existing != record['sha256']:
            raise ValueError('Staging audit digest mismatch')
    return sorted(v for v in versions if (framework, v) not in staged)


def _append(root, events, action, framework, version, actor, reason):
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2048:
        raise ValueError('A reason (maximum 2048 characters) is required')
    entry = {'seq': len(events) + 1, 'previous_hash': events[-1]['event_hash'] if events else '0' * 64,
             'timestamp': datetime.now(timezone.utc).isoformat(), 'actor': _actor(actor),
             'action': action, 'framework': framework, 'version': version, 'reason': reason}
    entry['event_hash'] = _digest(entry)
    registry._append_audit(root / 'lifecycle.jsonl', entry)
    return entry


def _with_lock(root, operation):
    # Caller must already have validated root. All writes use the same lock as staging.
    registry._validate_dir(root)
    fd = registry._lock(root)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return operation()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def lifecycle_status(framework, root=None):
    if framework not in ALL:
        raise ValueError('Unknown framework')
    root = Path(root) if root is not None else registry.ROOT
    if not root.exists():
        return {'framework': framework, 'published_version': None, 'versions': [], 'audit_gaps': []}
    def read():
        versions = _verified_versions(framework, root)
        events = _read_lifecycle(root)
        approved, published = _state(events, framework)
        for event in events:
            if event['version'] not in _verified_versions(event['framework'], root):
                raise ValueError('Lifecycle event references a missing version')
        return {'framework': framework, 'published_version': published,
                'audit_gaps': _audit_missing(root, framework, versions),
                'versions': [{**item, 'status': ('published' if item['version'] == published else
                             'approved' if item['version'] in approved else 'staged')}
                             for item in versions.values()]}
    return _with_lock(root, read)


def transition(framework, version, action, actor, reason, root=None):
    """Explicit offline transition: approve, publish, or rollback to an approved version."""
    if framework not in ALL or not isinstance(version, str) or not registry._VERSION.fullmatch(version):
        raise ValueError('Invalid framework/version')
    if action not in ('approve', 'publish', 'rollback'):
        raise ValueError('Invalid transition')
    _actor(actor)
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2048:
        raise ValueError('A reason (maximum 2048 characters) is required')
    root = Path(root) if root is not None else registry.ROOT
    def apply():
        versions = _verified_versions(framework, root)
        if version not in versions:
            raise ValueError('Requirements version does not exist')
        if _audit_missing(root, framework, versions):
            raise ValueError('Unreconciled staging audit gap; transition blocked')
        events = _read_lifecycle(root)
        approved, published = _state(events, framework)
        for event in events:
            if event['version'] not in _verified_versions(event['framework'], root):
                raise ValueError('Lifecycle event references a missing version')
        if action == 'approve':
            if version in approved:
                raise ValueError('Version already approved')
            event_action = 'approved'
        elif action == 'publish':
            if version not in approved or version == published:
                raise ValueError('Publication requires a different approved version')
            event_action = 'published'
        else:
            if published is None or version not in approved or version == published:
                raise ValueError('Rollback requires a previously approved, different version')
            if not any(e['framework'] == framework and e['version'] == version and
                       e['action'] in ('published', 'rolled_back') for e in events):
                raise ValueError('Rollback target has never been published')
            event_action = 'rolled_back'
        return _append(root, events, event_action, framework, version, actor, reason)
    return _with_lock(root, apply)


def audit_gaps(framework, root=None):
    """Read-only identification of version files lacking matching stage audit entries."""
    return lifecycle_status(framework, root=root)['audit_gaps']


def reconcile_staging_audit(framework, version, actor, reason, root=None):
    """Explicit operator-authorized reconciliation; never changes publication state."""
    if framework not in ALL or not isinstance(version, str) or not registry._VERSION.fullmatch(version):
        raise ValueError('Invalid framework/version')
    _actor(actor)
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2048:
        raise ValueError('A reason is required')
    root = Path(root) if root is not None else registry.ROOT
    def apply():
        versions = _verified_versions(framework, root)
        if version not in versions or version not in _audit_missing(root, framework, versions):
            raise ValueError('No missing staging audit event for version')
        record = versions[version]
        event = {'timestamp': datetime.now(timezone.utc).isoformat(), 'actor': actor,
                 'action': 'version_staged', 'framework': framework, 'version': version,
                 'sha256': record['sha256'], 'reconciled': True, 'reason': reason}
        registry._append_audit(root / 'audit.jsonl', event)
        return event
    return _with_lock(root, apply)
