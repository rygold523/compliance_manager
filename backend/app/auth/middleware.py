from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from types import SimpleNamespace

from app.auth.service import resolve_session
from app.core.config import settings
from app.core.database import SessionLocal


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _csv_values(value: str) -> tuple[str, ...]:
    return tuple(item.strip().rstrip("/") for item in value.split(",") if item.strip())


def _path_is_public(path: str) -> bool:
    normalized = path.rstrip("/") or "/"
    if normalized in {"/api/auth/login", "/api/health", "/api/live", "/api/ready"}:
        return True
    return normalized in _csv_values(settings.auth_service_paths)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if (
            request.method == "OPTIONS"
            or not request.url.path.startswith("/api/")
            or _path_is_public(request.url.path)
        ):
            return await call_next(request)

        db = SessionLocal()
        try:
            resolved = resolve_session(
                db,
                request.cookies.get(settings.auth_cookie_name),
            )
            if resolved is None:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication required."},
                )

            user, session = resolved
            auth_user = SimpleNamespace(
                id=user.id,
                username=user.username,
                display_name=user.display_name,
                role=user.role,
                enabled=user.enabled,
                must_change_password=user.must_change_password,
            )
            auth_session = SimpleNamespace(id=session.id)
        finally:
            db.close()

        request.state.auth_user = auth_user
        request.state.auth_session = auth_session

        auth_account_path = request.url.path.rstrip("/") in {
            "/api/auth/logout",
            "/api/auth/password",
        }
        if auth_user.must_change_password and not auth_account_path:
            return JSONResponse(
                status_code=403,
                content={"detail": "Password change required.", "code": "password_change_required"},
            )

        if request.method not in SAFE_METHODS:
            origin = request.headers.get("origin", "").rstrip("/")
            allowed_origins = _csv_values(settings.auth_cors_origins)
            if origin not in allowed_origins:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Request origin is not allowed."},
                )

            if not auth_account_path and auth_user.role != "admin":
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Administrator role required."},
                )

        return await call_next(request)
