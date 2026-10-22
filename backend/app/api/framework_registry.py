"""Administrator-only registry discovery; no external network access."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.auth.dependencies import require_roles
from app.services.framework_registry import read_registry, set_framework_enabled

router = APIRouter(prefix='/api/admin/frameworks', tags=['Framework Administration'])


class FrameworkSetting(BaseModel):
    enabled: bool


@router.get('')
def list_frameworks(_admin=Depends(require_roles('admin'))):
    return {'frameworks': read_registry()}


@router.put('/{framework_id}')
def update_framework(framework_id: str, setting: FrameworkSetting, _admin=Depends(require_roles('admin'))):
    try:
        return {'frameworks': set_framework_enabled(framework_id, setting.enabled, actor=_admin.username)}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
