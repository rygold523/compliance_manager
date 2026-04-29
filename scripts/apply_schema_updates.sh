#!/usr/bin/env bash
set -euo pipefail

DB_CONTAINER="${DB_CONTAINER:-aivuln-postgres}"
POSTGRES_DB="${POSTGRES_DB:-aivuln}"
POSTGRES_USER="${POSTGRES_USER:-aivuln}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run as root or with sudo."
  exit 1
fi

sleep 5

docker exec -i "${DB_CONTAINER}" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" <<'SQL'
ALTER TABLE assets ADD COLUMN IF NOT EXISTS ssh_port INTEGER DEFAULT 22;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS compliance_scope JSON DEFAULT '[]'::json;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS agent_status VARCHAR(64) DEFAULT 'not_deployed';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS affected_frameworks JSON DEFAULT '[]'::json;

ALTER TABLE evidence ADD COLUMN IF NOT EXISTS collector VARCHAR(128);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS evidence_type VARCHAR(128);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS frameworks JSON DEFAULT '{}'::json;

CREATE TABLE IF NOT EXISTS agent_deployments (
  id SERIAL PRIMARY KEY,
  deployment_id VARCHAR(128) UNIQUE NOT NULL,
  asset_id VARCHAR(128) NOT NULL,
  hostname VARCHAR(255) NOT NULL,
  address VARCHAR(255) NOT NULL,
  username VARCHAR(128) NOT NULL,
  port INTEGER DEFAULT 22,
  status VARCHAR(64) DEFAULT 'pending',
  output TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS collector_runs (
  id SERIAL PRIMARY KEY,
  run_id VARCHAR(128) UNIQUE NOT NULL,
  asset_id VARCHAR(128) NOT NULL,
  collector VARCHAR(128) NOT NULL,
  status VARCHAR(64) DEFAULT 'queued',
  output JSON DEFAULT '{}'::json,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scanner_results (
  id SERIAL PRIMARY KEY,
  scanner_result_id VARCHAR(128) UNIQUE NOT NULL,
  scanner VARCHAR(128) NOT NULL,
  asset_id VARCHAR(128),
  raw JSON DEFAULT '{}'::json,
  imported_findings INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now()
);
SQL

echo "[+] Schema updates applied."
