"""Administrator-only, read-only PCI DSS requirement mapping coverage."""
from fastapi import APIRouter, Depends, HTTPException

from app.auth.dependencies import require_roles
from app.services.requirements_coverage import coverage

router = APIRouter(prefix='/api/admin/frameworks', tags=['Requirements Administration'])


@router.get('/pci_dss/requirements/coverage')
def pci_dss_requirements_coverage(_admin=Depends(require_roles('admin'))):
    try:
        return coverage('pci_dss')
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=409, detail='Requirements coverage validation failed') from exc
