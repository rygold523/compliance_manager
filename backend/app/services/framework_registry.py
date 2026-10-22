"""Persistent administrator framework selection; no network activity."""
import json
import os
import tempfile
import fcntl
from datetime import datetime, timezone
from pathlib import Path

REGISTRY_PATH = Path(os.environ.get('FRAMEWORK_REGISTRY_PATH', '/var/lib/ai-vulnerability-management/framework-registry.json'))
BASELINE = ('pci_dss', 'soc2', 'nist_800_53', 'iso_27001', 'iso_27002')
OPTIONAL = ('hipaa', 'gdpr', 'nist_csf', 'ccpa_cpra')
ALL = (*BASELINE, *OPTIONAL)
LABELS = {
    'pci_dss': 'PCI DSS', 'soc2': 'SOC 2', 'nist_800_53': 'NIST SP 800-53',
    'iso_27001': 'ISO 27001', 'iso_27002': 'ISO 27002',
    'hipaa': 'HIPAA', 'gdpr': 'GDPR', 'nist_csf': 'NIST CSF',
    'ccpa_cpra': 'CCPA / CPRA',
}


def _settings(path):
    if not path.exists():
        return {}
    content = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(content, dict) or content.get('schema_version') != 1:
        raise ValueError('Unsupported framework registry schema')
    settings = content.get('enabled', {})
    if not isinstance(settings, dict) or any(k not in ALL or type(v) is not bool for k, v in settings.items()):
        raise ValueError('Invalid framework registry settings')
    return settings


def read_registry(path=None):
    path = Path(path) if path is not None else REGISTRY_PATH
    settings = _settings(path)
    return [
        {'id': key, 'label': LABELS[key], 'enabled': settings.get(key, key in BASELINE),
         'baseline': key in BASELINE, 'assessment_ready': key in BASELINE}
        for key in ALL
    ]


def is_enabled(framework, path=None):
    if framework not in ALL:
        return False
    return next(item['enabled'] for item in read_registry(path) if item['id'] == framework)


def is_assessment_ready(framework):
    return framework in BASELINE


def set_framework_enabled(framework, enabled, path=None, actor="system"):
    if framework not in ALL:
        raise ValueError('Unknown framework')
    if type(enabled) is not bool:
        raise ValueError('enabled must be boolean')
    path = Path(path) if path is not None else REGISTRY_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + '.lock')
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        settings = _settings(path)
        old_value = settings.get(framework, framework in BASELINE)
        if old_value == enabled:
            return read_registry(path)
        settings[framework] = enabled
        payload = {'schema_version': 1, 'enabled': settings}
        # Audit first: if audit cannot be recorded, no state transition occurs.
        audit_path = path.with_name(path.name + '.audit.jsonl')
        event = {'timestamp': datetime.now(timezone.utc).isoformat(),
                 'actor': str(actor)[:255], 'framework': framework,
                 'previous_enabled': old_value, 'enabled': enabled,
                 'outcome': 'requested'}
        audit_fd = os.open(audit_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.write(audit_fd, (json.dumps(event, sort_keys=True) + '\n').encode('utf-8'))
            os.fsync(audit_fd)
        finally:
            os.close(audit_fd)
        fd, temp = tempfile.mkstemp(prefix='.framework-registry-', dir=str(path.parent))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump(payload, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        # A successful replacement is reflected in a separate audit event. The
        # requested event remains distinguishable if persistence fails.
        committed = dict(event, outcome='committed', timestamp=datetime.now(timezone.utc).isoformat())
        audit_fd = os.open(audit_path, os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW)
        try:
            os.write(audit_fd, (json.dumps(committed, sort_keys=True) + '\n').encode('utf-8'))
            os.fsync(audit_fd)
        finally:
            os.close(audit_fd)
        return read_registry(path)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


# Compatibility alias for existing callers.
def set_optional_enabled(framework, enabled, path=None):
    return set_framework_enabled(framework, enabled, path)
