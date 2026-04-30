from fastapi import APIRouter
from app.services.control_catalog import list_controls, suggest_controls

router = APIRouter(prefix="/api/controls", tags=["controls"])


@router.get("/")
def get_controls():
    return list_controls()


@router.post("/suggest")
def suggest(payload: dict):
    return {
        "suggested_controls": suggest_controls(
            scope=payload.get("scope", ""),
            filename=payload.get("filename", ""),
        )
    }
