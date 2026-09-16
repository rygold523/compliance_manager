# Security Fix Phase 9: Required Database Configuration

This phase removes the credential-like PostgreSQL connection string embedded
as the application configuration default.

- `DATABASE_URL` is now required at process startup.
- Backend and worker continue to receive it from the protected Compose `.env`
  file.
- Missing configuration fails closed instead of silently attempting a known
  username, password, host, and database combination.
- Validation and deployment checks report only presence and parsed endpoint
  metadata; they do not print the password or complete connection URL.

The existing database credential is not rotated or modified by this phase.
