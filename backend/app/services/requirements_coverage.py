"""Read-only, exact-ID coverage of a published framework requirements catalog.

Coverage is not a compliance determination. Never infer child mappings from parents.
"""
from collections import defaultdict

from app.services import requirements_lifecycle as lifecycle
from app.services import requirements_comparison as comparison
from app.services import requirements_registry as registry
from app.services.control_catalog import list_controls


def coverage(framework='pci_dss'):
    if framework != 'pci_dss':
        raise ValueError('Coverage currently supports pci_dss only')

    state = lifecycle.lifecycle_status(framework)
    if state.get('audit_gaps'):
        raise ValueError('Unreconciled requirements staging audit gaps')

    published = state.get('published_version')
    if published is not None:
        known = {item['version'] for item in state['versions']}
        if published not in known:
            raise ValueError('Published requirements version missing')
        record = comparison._load(framework, published, registry.ROOT)

        if not isinstance(record, dict):
            raise ValueError('Invalid published requirements record')

        if record.get('framework') != framework:
            raise ValueError('Published requirements framework mismatch')

        if record.get('version') != published:
            raise ValueError('Published requirements version mismatch')

        requirements = record['requirements']
        catalog_ids = {item['id'] for item in requirements}
    else:
        requirements = []
        catalog_ids = set()

    mappings = defaultdict(set)
    for control in list_controls():
        control_id = control.get('control_id')
        if not isinstance(control_id, str) or not control_id.strip():
            continue
        framework_mappings = control.get('framework_mappings') or {}
        if not isinstance(framework_mappings, dict):
            raise ValueError(f'Invalid mappings for control {control_id}')
        refs = framework_mappings.get(framework) or []
        if not isinstance(refs, list):
            refs = [refs]
        for ref in refs:
            if isinstance(ref, bool) or not isinstance(ref, (str, int, float)):
                raise ValueError(f'Invalid requirement reference for control {control_id}')
            key = str(ref).strip()
            if not key:
                raise ValueError(f'Empty requirement reference for control {control_id}')
            mappings[key].add(control_id)

    if published is None:
        return {
            'framework': framework, 'catalog_status': 'catalog_unavailable',
            'published_version': None, 'total_requirements': None,
            'mapped_requirements': None, 'unmapped_requirements': None,
            'unmatched_mappings': None, 'coverage_percentage': None,
            'read_only': True, 'compliance_determination': False,
        }

    mapped = sorted(catalog_ids & mappings.keys())
    unmapped = sorted(catalog_ids - mappings.keys())
    unmatched = sorted(mappings.keys() - catalog_ids)
    total = len(catalog_ids)
    return {
        'framework': framework, 'catalog_status': 'published',
        'published_version': published, 'total_requirements': total,
        'mapped_requirements': len(mapped), 'unmapped_requirements': len(unmapped),
        'unmatched_mappings': [{'id': key, 'controls': sorted(mappings[key])} for key in unmatched],
        'coverage_percentage': round(len(mapped) * 100 / total, 2) if total else None,
        'requirements': [
            {'id': item['id'], 'mapped_controls': sorted(mappings.get(item['id'], set())),
             'mapping_status': 'mapped' if item['id'] in mappings else 'unmapped'}
            for item in requirements
        ],
        'read_only': True, 'compliance_determination': False,
    }
