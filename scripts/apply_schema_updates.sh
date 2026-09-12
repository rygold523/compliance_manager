#!/usr/bin/env bash
set -euo pipefail
DB_CONTAINER="${DB_CONTAINER:-aivuln-postgres}"; POSTGRES_DB="${POSTGRES_DB:-aivuln}"; POSTGRES_USER="${POSTGRES_USER:-aivuln}"
sleep 5
docker exec -i "$DB_CONTAINER" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
ALTER TABLE assets ADD COLUMN IF NOT EXISTS ssh_port INTEGER DEFAULT 22;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS compliance_scope JSON DEFAULT '[]'::json;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS agent_status VARCHAR(64) DEFAULT 'not_deployed';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS affected_frameworks JSON DEFAULT '[]'::json;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS collector VARCHAR(128);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS evidence_type VARCHAR(128);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS frameworks JSON DEFAULT '{}'::json;
CREATE TABLE IF NOT EXISTS agent_deployments (id SERIAL PRIMARY KEY, deployment_id VARCHAR(128) UNIQUE NOT NULL, asset_id VARCHAR(128) NOT NULL, hostname VARCHAR(255) NOT NULL, address VARCHAR(255) NOT NULL, username VARCHAR(128) NOT NULL, port INTEGER DEFAULT 22, status VARCHAR(64) DEFAULT 'pending', output TEXT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS collector_runs (id SERIAL PRIMARY KEY, run_id VARCHAR(128) UNIQUE NOT NULL, asset_id VARCHAR(128) NOT NULL, collector VARCHAR(128) NOT NULL, status VARCHAR(64) DEFAULT 'queued', output JSON DEFAULT '{}'::json, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS scanner_results (id SERIAL PRIMARY KEY, scanner_result_id VARCHAR(128) UNIQUE NOT NULL, scanner VARCHAR(128) NOT NULL, asset_id VARCHAR(128), raw JSON DEFAULT '{}'::json, imported_findings INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS local_users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(128) UNIQUE NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'viewer',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  password_changed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_local_users_username ON local_users (username);
CREATE TABLE IF NOT EXISTS auth_sessions (
  id SERIAL PRIMARY KEY,
  session_token_hash VARCHAR(64) UNIQUE NOT NULL,
  user_id INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_token_hash ON auth_sessions (session_token_hash);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_id ON auth_sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_expires_at ON auth_sessions (expires_at);
CREATE TABLE IF NOT EXISTS auth_audit_events (
  id SERIAL PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  username VARCHAR(128),
  user_id INTEGER,
  source_address VARCHAR(128),
  detail JSON DEFAULT '{}'::json,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_auth_audit_events_event_type ON auth_audit_events (event_type);
CREATE INDEX IF NOT EXISTS ix_auth_audit_events_username ON auth_audit_events (username);
SQL
