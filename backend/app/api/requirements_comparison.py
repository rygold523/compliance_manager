"""Administrator-only, offline requirements version comparison API."""

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.dependencies import require_roles
from app.services.framework_registry import ALL
from app.services import requirements_comparison as comparison
from app.services import requirements_lifecycle as lifecycle
from app.services import requirements_registry as registry

router = APIRouter(
    prefix='/api/admin/frameworks',
    tags=['Requirements Administration'],
)


@router.get('/{framework_id}/requirements/compare')
def compare_requirements(
    framework_id: str,
    from_version: str = Query(..., min_length=1, max_length=80),
    to_version: str = Query(..., min_length=1, max_length=80),
    _admin=Depends(require_roles('admin')),
):
    if framework_id not in ALL:
        raise HTTPException(status_code=404, detail='Unknown framework')
    for version in (from_version, to_version):
        if not registry._VERSION.fullmatch(version) or version in ('.', '..'):
            raise HTTPException(status_code=422, detail='Invalid version identifier')
    try:
        status = lifecycle.lifecycle_status(framework_id)
        if status['audit_gaps']:
            raise ValueError('Unreconciled staging audit gap; comparison blocked')
        available = {item['version'] for item in status['versions']}
        if from_version not in available or to_version not in available:
            raise ValueError('Requirements version does not exist')
        return comparison.compare_versions(framework_id, from_version, to_version)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=409, detail='Requirements comparison validation failed') from exc
