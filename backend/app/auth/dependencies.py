from fastapi import HTTPException, Request


def require_roles(*roles: str):
    def dependency(request: Request):
        user = getattr(request.state, "auth_user", None)
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication required.")
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions.")
        return user

    return dependency
