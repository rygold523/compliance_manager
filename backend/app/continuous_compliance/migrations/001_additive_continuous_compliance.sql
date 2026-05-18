-- Additive-only continuous compliance schema update.
-- Do not rename, remove, or modify existing tables destructively.

ALTER TABLE evidence ADD COLUMN IF NOT EXISTS evidence_scope VARCHAR(64);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS source_type VARCHAR(64);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS source_id VARCHAR(255);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS environment VARCHAR(64);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS service_name VARCHAR(255);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS coverage_basis VARCHAR(64);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS authoritative_source BOOLEAN DEFAULT FALSE;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS freshness_requirement_seconds BIGINT;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS baseline_hash VARCHAR(128);

CREATE TABLE IF NOT EXISTS evidence_policies (
    id UUID PRIMARY KEY,
    control_id VARCHAR(128) NOT NULL,
    policy_version VARCHAR(32) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_policy_requirements (
    id UUID PRIMARY KEY,
    policy_id UUID NOT NULL,
    evidence_name VARCHAR(255) NOT NULL,
    scope_requirement VARCHAR(64),
    freshness_seconds BIGINT,
    authoritative_source VARCHAR(255),
    minimum_coverage_percent INTEGER,
    required BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS regulatory_documents (
    id UUID PRIMARY KEY,
    source_name VARCHAR(255) NOT NULL,
    document_type VARCHAR(255) NOT NULL,
    version_hash VARCHAR(128),
    content_hash VARCHAR(128),
    retrieved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    normalized_content JSONB,
    raw_content TEXT
);

CREATE TABLE IF NOT EXISTS compliance_tasks (
    id UUID PRIMARY KEY,
    task_type VARCHAR(128) NOT NULL,
    severity VARCHAR(32),
    status VARCHAR(32) DEFAULT 'open',
    linked_finding_id UUID,
    assigned_to VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    due_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS drift_findings (
    id UUID PRIMARY KEY,
    drift_type VARCHAR(128) NOT NULL,
    severity VARCHAR(32),
    source_id VARCHAR(255),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT FALSE,
    details JSONB
);

CREATE TABLE IF NOT EXISTS continuous_compliance_events (
    id UUID PRIMARY KEY,
    event_source VARCHAR(128) NOT NULL,
    event_type VARCHAR(128),
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    normalized_event JSONB,
    raw_event JSONB
);

CREATE INDEX IF NOT EXISTS idx_evidence_scope ON evidence(evidence_scope);
CREATE INDEX IF NOT EXISTS idx_evidence_source_id ON evidence(source_id);
CREATE INDEX IF NOT EXISTS idx_evidence_environment ON evidence(environment);
CREATE INDEX IF NOT EXISTS idx_regulatory_documents_hash ON regulatory_documents(content_hash);
CREATE INDEX IF NOT EXISTS idx_drift_findings_source ON drift_findings(source_id);
CREATE INDEX IF NOT EXISTS idx_compliance_tasks_status ON compliance_tasks(status);
