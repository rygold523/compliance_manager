"""Administrator-only, offline requirements version lifecycle API.

Publication changes requirements metadata only, never assessment mappings/scores.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, ConfigDict

from app.auth.dependencies import require_roles
from app.services.framework_registry import ALL
from app.services import requirements_registry as registry
from app.services import requirements_lifecycle as lifecycle

router = APIRouter(prefix='/api/admin/frameworks', tags=['Requirements Administration'])


class StageRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    version: str = Field(min_length=1, max_length=80)
    requirements: list[dict] = Field(min_length=1, max_length=10000)
    source: dict


class ReasonRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    reason: str = Field(min_length=1, max_length=2048)


def _framework(framework_id: str):
    if framework_id not in ALL:
        raise HTTPException(status_code=404, detail='Unknown framework')


def _conflict(exc: ValueError):
    raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get('/{framework_id}/requirements')
def get_requirements_status(framework_id: str, _admin=Depends(require_roles('admin'))):
    _framework(framework_id)
    try:
        return lifecycle.lifecycle_status(framework_id)
    except ValueError as exc:
        _conflict(exc)


@router.get('/{framework_id}/requirements/versions')
def get_requirements_versions(framework_id: str, _admin=Depends(require_roles('admin'))):
    _framework(framework_id)
    try:
        return {'framework': framework_id, 'versions': lifecycle.lifecycle_status(framework_id)['versions']}
    except ValueError as exc:
        _conflict(exc)


@router.get('/{framework_id}/requirements/audit-gaps')
def get_requirements_audit_gaps(framework_id: str, _admin=Depends(require_roles('admin'))):
    _framework(framework_id)
    try:
        return {'framework': framework_id, 'audit_gaps': lifecycle.audit_gaps(framework_id)}
    except ValueError as exc:
        _conflict(exc)


@router.post('/{framework_id}/requirements/stage', status_code=status.HTTP_201_CREATED)
def stage_requirements(framework_id: str, payload: StageRequest, admin=Depends(require_roles('admin'))):
    _framework(framework_id)
    try:
        return registry.stage_version(framework_id, payload.version, payload.requirements, payload.source, admin.username)
    except FileExistsError as exc:
        _conflict(ValueError(str(exc)))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post('/{framework_id}/requirements/{version}/approve')
def approve_requirements(framework_id: str, version: str, payload: ReasonRequest, admin=Depends(require_roles('admin'))):
    return _transition(framework_id, version, 'approve', payload.reason, admin.username)


@router.post('/{framework_id}/requirements/{version}/publish')
def publish_requirements(framework_id: str, version: str, payload: ReasonRequest, admin=Depends(require_roles('admin'))):
    return _transition(framework_id, version, 'publish', payload.reason, admin.username)


@router.post('/{framework_id}/requirements/{version}/rollback')
def rollback_requirements(framework_id: str, version: str, payload: ReasonRequest, admin=Depends(require_roles('admin'))):
    return _transition(framework_id, version, 'rollback', payload.reason, admin.username)


def _transition(framework_id, version, action, reason, actor):
    _framework(framework_id)
    try:
        return lifecycle.transition(framework_id, version, action, actor, reason)
    except ValueError as exc:
        _conflict(exc)


@router.post('/{framework_id}/requirements/{version}/reconcile-audit')
def reconcile_requirements_audit(framework_id: str, version: str, payload: ReasonRequest, admin=Depends(require_roles('admin'))):
    _framework(framework_id)
    try:
        return lifecycle.reconcile_staging_audit(framework_id, version, admin.username, payload.reason)
    except ValueError as exc:
        _conflict(exc)
