# Local User Management and Eastern Time Display

This package adds administrative management of local Compliance Manager users and standardizes browser-rendered timestamps on US Eastern Time.

## Security behavior

- Only users with the `admin` role can list or modify dashboard accounts.
- New accounts receive a temporary password and must change it at first login.
- Disabling an account or changing its role revokes its active sessions.
- Password resets revoke active sessions, clear lockout state, and require a password change.
- An administrator cannot disable or demote their own account.
- The final enabled administrator cannot be disabled or demoted.
- Every administrative action records the acting administrator in `auth_audit_events`.
- Password hashes and session tokens are never returned by the API.
- The implementation intentionally does not provide public registration or account deletion.

## Timestamp behavior

Timestamps remain stored and transported in UTC. The frontend converts ISO timestamps to `America/New_York`, including the correct EST or EDT abbreviation for the historical date. This avoids corrupting evidence chronology while giving dashboard users a consistent Eastern Time display.

The shared formatter is applied to finding and evidence modal fields, nested current-state fields, changelog events, agent lifecycle timestamps, database IAM last-seen timestamps, and user-management timestamps.

## Files changed

- `backend/app/api/admin_users.py` — new administrator-only API.
- `backend/app/main.py` — registers the new router.
- `backend/tests/test_auth.py` — adds validation regressions.
- `frontend/src/dateTime.js` — shared Eastern Time formatter.
- `frontend/src/pages/UserManagement.jsx` — new Users page.
- `frontend/src/pages/IAM.jsx` — uses the shared formatter.
- `frontend/src/main.jsx` — adds the Users tab and centralized timestamp rendering.
- `frontend/src/style.css` — user-management layout and status styling.

## API routes

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/admin/users` | List local accounts and active-session counts |
| `POST` | `/api/admin/users` | Create an enabled account with a forced password change |
| `PATCH` | `/api/admin/users/{id}` | Change display name, role, or enabled state |
| `POST` | `/api/admin/users/{id}/reset-password` | Set a temporary password and revoke sessions |
| `POST` | `/api/admin/users/{id}/unlock` | Clear failed attempts and temporary lockout |
| `POST` | `/api/admin/users/{id}/revoke-sessions` | Revoke all active sessions for an account |

No database migration is required because the existing local authentication tables already contain every required field.

## Deployment

Extract the package, enter its directory, and run:

```bash
chmod +x deploy-update.sh rollback-update.sh
./deploy-update.sh /opt/ai-vulnerability-management
```

The deployment script backs up every replaced file, compiles the Python entry points, rebuilds only the backend and frontend images, recreates only those two services, validates `/api/health`, and confirms that the user-management API rejects unauthenticated access.

If application-level validation fails after deployment, roll back with:

```bash
./rollback-update.sh /opt/ai-vulnerability-management
```
