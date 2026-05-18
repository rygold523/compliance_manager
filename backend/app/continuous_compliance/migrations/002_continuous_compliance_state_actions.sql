CREATE TABLE IF NOT EXISTS continuous_compliance_domain_status (
    id UUID PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(64) NOT NULL DEFAULT 'unknown',
    status_reason TEXT,
    required_actions INTEGER DEFAULT 0,
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_marked_current_at TIMESTAMP WITH TIME ZONE,
    marked_current_by VARCHAR(255),
    next_review_due_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS continuous_compliance_action_items (
    id UUID PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    control_id VARCHAR(128),
    title VARCHAR(512) NOT NULL,
    description TEXT,
    severity VARCHAR(64) DEFAULT 'medium',
    status VARCHAR(64) DEFAULT 'open',
    source VARCHAR(128),
    due_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE,
    closed_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_cc_domain_status_domain
ON continuous_compliance_domain_status(domain);

CREATE INDEX IF NOT EXISTS idx_cc_action_items_domain
ON continuous_compliance_action_items(domain);

CREATE INDEX IF NOT EXISTS idx_cc_action_items_status
ON continuous_compliance_action_items(status);
