CREATE TABLE IF NOT EXISTS iam_db_sources (
    source_key TEXT PRIMARY KEY,
    source_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    database_name TEXT,
    collector_username TEXT,

    status TEXT NOT NULL DEFAULT 'unknown',

    last_collected_at TIMESTAMPTZ,
    last_received_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    updated_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS iam_db_accounts (
    id BIGSERIAL PRIMARY KEY,

    source_key TEXT NOT NULL
        REFERENCES iam_db_sources(
            source_key
        )
        ON DELETE CASCADE,

    username TEXT NOT NULL,

    login_enabled BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    privileged BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    superuser BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    create_role BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    create_database BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    replication BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    bypass_rls BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    inherit BOOLEAN
        NOT NULL
        DEFAULT TRUE,

    connection_limit INTEGER,

    valid_until TIMESTAMPTZ,

    first_seen_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    last_seen_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    active BOOLEAN
        NOT NULL
        DEFAULT TRUE,

    UNIQUE (
        source_key,
        username
    )
);


CREATE TABLE IF NOT EXISTS iam_db_memberships (
    id BIGSERIAL PRIMARY KEY,

    source_key TEXT NOT NULL
        REFERENCES iam_db_sources(
            source_key
        )
        ON DELETE CASCADE,

    username TEXT NOT NULL,

    role_name TEXT NOT NULL,

    membership_type TEXT
        NOT NULL
        DEFAULT 'direct',

    admin_option BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    first_seen_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    last_seen_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    active BOOLEAN
        NOT NULL
        DEFAULT TRUE,

    UNIQUE (
        source_key,
        username,
        role_name,
        membership_type
    )
);


CREATE TABLE IF NOT EXISTS iam_db_privileges (
    id BIGSERIAL PRIMARY KEY,

    source_key TEXT NOT NULL
        REFERENCES iam_db_sources(
            source_key
        )
        ON DELETE CASCADE,

    username TEXT NOT NULL,

    database_name TEXT NOT NULL,

    can_connect BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    can_create BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    can_temp BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    first_seen_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    last_seen_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    active BOOLEAN
        NOT NULL
        DEFAULT TRUE,

    UNIQUE (
        source_key,
        username,
        database_name
    )
);


CREATE TABLE IF NOT EXISTS iam_db_sync_runs (
    id BIGSERIAL PRIMARY KEY,

    source_key TEXT,

    source_name TEXT,

    status TEXT NOT NULL,

    accounts_seen INTEGER
        NOT NULL
        DEFAULT 0,

    memberships_seen INTEGER
        NOT NULL
        DEFAULT 0,

    privileges_seen INTEGER
        NOT NULL
        DEFAULT 0,

    collected_at TIMESTAMPTZ,

    received_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    error TEXT
);


CREATE INDEX IF NOT EXISTS
    idx_iam_db_accounts_username
ON iam_db_accounts(
    username
);


CREATE INDEX IF NOT EXISTS
    idx_iam_db_memberships_username
ON iam_db_memberships(
    username
);


CREATE INDEX IF NOT EXISTS
    idx_iam_db_memberships_role
ON iam_db_memberships(
    role_name
);


CREATE INDEX IF NOT EXISTS
    idx_iam_db_privileges_username
ON iam_db_privileges(
    username
);
