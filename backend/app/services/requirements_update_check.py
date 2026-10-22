"""Explicit, read-only publisher discovery. Never stages or publishes requirements.

A publisher landing page is not a machine-readable requirements catalog.
"""
from datetime import datetime, timezone

import os
import requests  # compatibility for existing Phase 4C-1 offline tests; never used for transport

from app.services.publisher_https import fetch_publisher, PublisherTransportError

from app.services.framework_registry import ALL, read_registry

# Exact HTTPS hosts and paths. No administrator-supplied destinations.
SOURCES = {
    'pci_dss': ('www.pcisecuritystandards.org', '/document_library/'),
    'nist_800_53': ('csrc.nist.gov', '/projects/risk-management/sp800-53-controls'),
    'nist_csf': ('www.nist.gov', '/cyberframework'),
    'iso_27001': ('www.iso.org', '/standard/27001'),
    'iso_27002': ('www.iso.org', '/standard/75652.html'),
    'hipaa': ('www.hhs.gov', '/hipaa/for-professionals/security/'),
    'gdpr': ('eur-lex.europa.eu', '/eli/reg/2016/679/oj'),
    'ccpa_cpra': ('cppa.ca.gov', '/regulations/'),
    # SOC 2 criteria are licensed AICPA material; no automated catalog available.
}
# Default is off until approved outbound access is explicitly enabled.
ENABLE_LIVE_PUBLISHER_CHECKS = 'COMPLIANCE_PUBLISHER_CHECKS_ENABLED'


def _approved_sources():
    return frozenset(SOURCES.values())


def _live_fetch(url):
    return fetch_publisher(url, approved_sources=_approved_sources())


def check_framework(framework, *, enabled=None, fetcher=None):
    """Return source reachability only. No requirements-version claims.

    Production retrieval requires an explicit opt-in environment flag.
    A publisher landing page cannot establish a requirements version.
    """
    if framework not in ALL:
        raise ValueError('Unknown framework')
    if enabled is None:
        enabled = next(item['enabled'] for item in read_registry() if item['id'] == framework)
    result = {
        'framework': framework,
        'enabled': bool(enabled),
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'requirements_current': None,
        'requirements_version_verified': False,
        'requirements_changed': None,
        'automatic_publication': False,
    }
    if not enabled:
        return {**result, 'status': 'disabled', 'message': 'Framework is disabled; no check performed.'}
    if framework not in SOURCES:
        return {**result, 'status': 'manual_verification_required', 'message': 'No approved public discovery source; authorized manual import required.'}
    host, path = SOURCES[framework]
    url = f'https://{host}{path}'
    result['publisher_url'] = url
    if fetcher is None:
        if os.environ.get(ENABLE_LIVE_PUBLISHER_CHECKS, '').lower() != 'true':
            return {**result, 'status': 'manual_verification_required', 'message': 'Publisher retrieval disabled by configuration.'}
        fetcher = _live_fetch
    # Caller-supplied fetcher is reserved for offline test doubles, not API input.
    try:
        response = fetcher(url)
        if not isinstance(response, dict) or response.get('status') != 'reachable':
            raise ValueError('Invalid publisher check response')
        return {**result, 'status': 'publisher_reachable', 'message': 'Publisher landing page reachable; requirements version not verified.'}
    except (PublisherTransportError, ValueError, OSError):
        return {**result, 'status': 'check_failed', 'message': 'Publisher discovery failed; no requirements version verified.'}


def check_all(*, settings=None, fetcher=None):
    settings = read_registry() if settings is None else settings
    enabled = {item['id']: item['enabled'] for item in settings}
    return {'results': [check_framework(fw, enabled=enabled.get(fw, False), fetcher=fetcher) for fw in ALL if enabled.get(fw, False)]}
