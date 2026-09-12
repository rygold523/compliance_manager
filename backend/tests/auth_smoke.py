from types import SimpleNamespace

from app.auth.middleware import _path_is_public
from app.auth.service import (
    hash_password,
    normalize_username,
    public_user,
    token_hash,
    verify_password,
)


password_hash = hash_password("correct horse battery staple")
assert password_hash.startswith("$argon2id$")
assert verify_password(password_hash, "correct horse battery staple")
assert not verify_password(password_hash, "incorrect password")

try:
    hash_password("too-short")
except ValueError:
    pass
else:
    raise AssertionError("Short password was accepted")

assert normalize_username("  Dashboard.Admin ") == "dashboard.admin"
assert token_hash("session-token") == token_hash("session-token")
assert token_hash("session-token") != token_hash("another-token")

user = SimpleNamespace(
    id=7,
    username="auditor",
    display_name="Compliance Auditor",
    role="auditor",
    must_change_password=False,
    password_hash="must-not-leak",
)
assert "password_hash" not in public_user(user)

assert _path_is_public("/api/auth/login")
assert not _path_is_public("/api/auth/me")
assert not _path_is_public("/api/auth/logout")
assert not _path_is_public("/api/auth/password")

print("All local-authentication smoke tests passed.")
