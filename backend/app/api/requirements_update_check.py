"""Administrator-triggered requirements source discovery; no persistent mutations."""
from fastapi import APIRouter, Depends, HTTPException
from app.auth.dependencies import require_roles
from app.services.framework_registry import ALL
from app.services import requirements_update_check as checks

router = APIRouter(prefix='/api/admin/frameworks', tags=['Requirements Update Checking'])

@router.post('/requirements/check-all-updates')
def check_all_updates(_admin=Depends(require_roles('admin'))):
    return checks.check_all()


@router.post('/{framework_id}/requirements/check-updates')
def check_updates(framework_id: str, _admin=Depends(require_roles('admin'))):
    if framework_id not in ALL:
        raise HTTPException(status_code=404, detail='Unknown framework')
    return checks.check_framework(framework_id)
