from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import psycopg2
import psycopg2.extras


DATABASE_URL = os.getenv(
    "DATABASE_URL",
)

SCHEMA_FILE = Path(
    "/app/app/iam_db_schema.sql"
)


def get_connection():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not configured."
        )

    psycopg2_database_url = DATABASE_URL.replace(
        "postgresql+psycopg2://",
        "postgresql://",
        1,
    )

    return psycopg2.connect(
        psycopg2_database_url,
    )


def ensure_schema():
    candidates = [
        SCHEMA_FILE,
        Path(
            "/opt/ai-vulnerability-management/"
            "scripts/iam_db_schema.sql"
        ),
        Path(
            "scripts/iam_db_schema.sql"
        ),
    ]

    schema_path = next(
        (
            path
            for path in candidates
            if path.exists()
        ),
        None,
    )

    if not schema_path:
        raise RuntimeError(
            "Unable to locate "
            "iam_db_schema.sql."
        )

    schema = schema_path.read_text(
        encoding="utf-8",
    )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                schema,
            )


def ingest(
    payload: dict[str, Any],
) -> dict[str, Any]:

    ensure_schema()

    source = payload.get(
        "source",
        {},
    )

    source_key = str(
        source.get("id")
        or ""
    ).strip()

    if not source_key:
        raise ValueError(
            "source.id is required."
        )

    source_name = str(
        source.get("name")
        or source_key
    )

    collected_at = payload.get(
        "collected_at"
    )

    accounts = payload.get(
        "accounts"
    ) or []

    memberships = payload.get(
        "memberships"
    ) or []

    privileges = payload.get(
        "database_privileges"
    ) or []

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO iam_db_sources (
                    source_key,
                    source_name,
                    source_type,
                    host,
                    port,
                    database_name,
                    collector_username,
                    status,
                    last_collected_at,
                    last_received_at,
                    updated_at
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    'success',
                    %s,
                    NOW(),
                    NOW()
                )
                ON CONFLICT (
                    source_key
                )
                DO UPDATE SET
                    source_name =
                        EXCLUDED.source_name,
                    source_type =
                        EXCLUDED.source_type,
                    host =
                        EXCLUDED.host,
                    port =
                        EXCLUDED.port,
                    database_name =
                        EXCLUDED.database_name,
                    collector_username =
                        EXCLUDED.collector_username,
                    status =
                        'success',
                    last_collected_at =
                        EXCLUDED.last_collected_at,
                    last_received_at =
                        NOW(),
                    updated_at =
                        NOW();
                """,
                (
                    source_key,
                    source_name,
                    source.get(
                        "type",
                        "postgres",
                    ),
                    source.get(
                        "host"
                    ),
                    source.get(
                        "port"
                    ),
                    source.get(
                        "database"
                    ),
                    source.get(
                        "username"
                    ),
                    collected_at,
                ),
            )

            #
            # Mark the previous snapshot inactive.
            #
            # Rows seen during this collection are
            # reactivated below.
            #

            cursor.execute(
                """
                UPDATE iam_db_accounts
                SET active = FALSE
                WHERE source_key = %s;
                """,
                (
                    source_key,
                ),
            )

            cursor.execute(
                """
                UPDATE iam_db_memberships
                SET active = FALSE
                WHERE source_key = %s;
                """,
                (
                    source_key,
                ),
            )

            cursor.execute(
                """
                UPDATE iam_db_privileges
                SET active = FALSE
                WHERE source_key = %s;
                """,
                (
                    source_key,
                ),
            )

            for account in accounts:

                cursor.execute(
                    """
                    INSERT INTO iam_db_accounts (
                        source_key,
                        username,
                        login_enabled,
                        privileged,
                        superuser,
                        create_role,
                        create_database,
                        replication,
                        bypass_rls,
                        inherit,
                        connection_limit,
                        valid_until,
                        first_seen_at,
                        last_seen_at,
                        active
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        NOW(),
                        NOW(),
                        TRUE
                    )
                    ON CONFLICT (
                        source_key,
                        username
                    )
                    DO UPDATE SET
                        login_enabled =
                            EXCLUDED.login_enabled,
                        privileged =
                            EXCLUDED.privileged,
                        superuser =
                            EXCLUDED.superuser,
                        create_role =
                            EXCLUDED.create_role,
                        create_database =
                            EXCLUDED.create_database,
                        replication =
                            EXCLUDED.replication,
                        bypass_rls =
                            EXCLUDED.bypass_rls,
                        inherit =
                            EXCLUDED.inherit,
                        connection_limit =
                            EXCLUDED.connection_limit,
                        valid_until =
                            EXCLUDED.valid_until,
                        last_seen_at =
                            NOW(),
                        active =
                            TRUE;
                    """,
                    (
                        source_key,
                        account.get(
                            "username"
                        ),
                        account.get(
                            "login_enabled",
                            False,
                        ),
                        account.get(
                            "privileged",
                            False,
                        ),
                        account.get(
                            "superuser",
                            False,
                        ),
                        account.get(
                            "create_role",
                            False,
                        ),
                        account.get(
                            "create_database",
                            False,
                        ),
                        account.get(
                            "replication",
                            False,
                        ),
                        account.get(
                            "bypass_rls",
                            False,
                        ),
                        account.get(
                            "inherit",
                            True,
                        ),
                        account.get(
                            "connection_limit"
                        ),
                        account.get(
                            "valid_until"
                        ),
                    ),
                )

            for membership in memberships:

                cursor.execute(
                    """
                    INSERT INTO iam_db_memberships (
                        source_key,
                        username,
                        role_name,
                        membership_type,
                        admin_option,
                        first_seen_at,
                        last_seen_at,
                        active
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        NOW(),
                        NOW(),
                        TRUE
                    )
                    ON CONFLICT (
                        source_key,
                        username,
                        role_name,
                        membership_type
                    )
                    DO UPDATE SET
                        admin_option =
                            EXCLUDED.admin_option,
                        last_seen_at =
                            NOW(),
                        active =
                            TRUE;
                    """,
                    (
                        source_key,
                        membership.get(
                            "username"
                        ),
                        membership.get(
                            "role_name"
                        ),
                        membership.get(
                            "membership_type",
                            "direct",
                        ),
                        membership.get(
                            "admin_option",
                            False,
                        ),
                    ),
                )

            for privilege in privileges:

                cursor.execute(
                    """
                    INSERT INTO iam_db_privileges (
                        source_key,
                        username,
                        database_name,
                        can_connect,
                        can_create,
                        can_temp,
                        first_seen_at,
                        last_seen_at,
                        active
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        NOW(),
                        NOW(),
                        TRUE
                    )
                    ON CONFLICT (
                        source_key,
                        username,
                        database_name
                    )
                    DO UPDATE SET
                        can_connect =
                            EXCLUDED.can_connect,
                        can_create =
                            EXCLUDED.can_create,
                        can_temp =
                            EXCLUDED.can_temp,
                        last_seen_at =
                            NOW(),
                        active =
                            TRUE;
                    """,
                    (
                        source_key,
                        privilege.get(
                            "username"
                        ),
                        privilege.get(
                            "database_name"
                        ),
                        privilege.get(
                            "can_connect",
                            False,
                        ),
                        privilege.get(
                            "can_create",
                            False,
                        ),
                        privilege.get(
                            "can_temp",
                            False,
                        ),
                    ),
                )

            cursor.execute(
                """
                INSERT INTO iam_db_sync_runs (
                    source_key,
                    source_name,
                    status,
                    accounts_seen,
                    memberships_seen,
                    privileges_seen,
                    collected_at
                )
                VALUES (
                    %s,
                    %s,
                    'success',
                    %s,
                    %s,
                    %s,
                    %s
                );
                """,
                (
                    source_key,
                    source_name,
                    len(accounts),
                    len(memberships),
                    len(privileges),
                    collected_at,
                ),
            )

    return {
        "status": "success",
        "source_key": source_key,
        "accounts_received": len(
            accounts
        ),
        "memberships_received": len(
            memberships
        ),
        "privileges_received": len(
            privileges
        ),
    }


def get_sources():
    ensure_schema()

    with get_connection() as connection:
        with connection.cursor(
            cursor_factory=(
                psycopg2.extras.RealDictCursor
            )
        ) as cursor:

            cursor.execute(
                """
                SELECT
                    source_key,
                    source_name,
                    source_type,
                    host,
                    port,
                    database_name,
                    collector_username,
                    status,
                    last_collected_at,
                    last_received_at
                FROM iam_db_sources
                ORDER BY source_name;
                """
            )

            return [
                dict(row)
                for row
                in cursor.fetchall()
            ]


def get_access_matrix():
    ensure_schema()

    with get_connection() as connection:
        with connection.cursor(
            cursor_factory=(
                psycopg2.extras.RealDictCursor
            )
        ) as cursor:

            cursor.execute(
                """
                SELECT
                    account.source_key,
                    source.source_name,
                    source.source_type,
                    source.host,
                    source.database_name,

                    account.username,
                    account.login_enabled,
                    account.privileged,
                    account.superuser,
                    account.create_role,
                    account.create_database,
                    account.replication,
                    account.bypass_rls,
                    account.connection_limit,
                    account.valid_until,
                    account.last_seen_at,

                    COALESCE(
                        ARRAY_AGG(
                            DISTINCT membership.role_name
                        )
                        FILTER (
                            WHERE
                                membership.role_name
                                IS NOT NULL
                                AND membership.active
                        ),
                        ARRAY[]::TEXT[]
                    ) AS roles

                FROM iam_db_accounts AS account

                JOIN iam_db_sources AS source
                    ON source.source_key =
                       account.source_key

                LEFT JOIN iam_db_memberships
                    AS membership
                    ON membership.source_key =
                       account.source_key
                    AND membership.username =
                        account.username

                WHERE
                    account.active = TRUE
                    AND account.login_enabled = TRUE

                GROUP BY
                    account.source_key,
                    source.source_name,
                    source.source_type,
                    source.host,
                    source.database_name,
                    account.username,
                    account.login_enabled,
                    account.privileged,
                    account.superuser,
                    account.create_role,
                    account.create_database,
                    account.replication,
                    account.bypass_rls,
                    account.connection_limit,
                    account.valid_until,
                    account.last_seen_at

                ORDER BY
                    source.source_name,
                    account.username;
                """
            )

            rows = [
                dict(row)
                for row
                in cursor.fetchall()
            ]

            cursor.execute(
                """
                SELECT
                    source_key,
                    username,
                    database_name,
                    can_connect,
                    can_create,
                    can_temp
                FROM iam_db_privileges
                WHERE active = TRUE
                ORDER BY
                    username,
                    database_name;
                """
            )

            privilege_rows = [
                dict(row)
                for row
                in cursor.fetchall()
            ]

    privilege_map: dict[
        tuple[str, str],
        list[dict[str, Any]]
    ] = {}

    for privilege in privilege_rows:
        key = (
            privilege["source_key"],
            privilege["username"],
        )

        privilege_map.setdefault(
            key,
            [],
        ).append(
            {
                "database": (
                    privilege[
                        "database_name"
                    ]
                ),
                "connect": (
                    privilege[
                        "can_connect"
                    ]
                ),
                "create": (
                    privilege[
                        "can_create"
                    ]
                ),
                "temp": (
                    privilege[
                        "can_temp"
                    ]
                ),
            }
        )

    for row in rows:
        key = (
            row["source_key"],
            row["username"],
        )

        row["database_privileges"] = (
            privilege_map.get(
                key,
                [],
            )
        )

        row["access_source"] = (
            "PostgreSQL"
        )

        row["access_type"] = (
            "Database"
        )

    return rows
