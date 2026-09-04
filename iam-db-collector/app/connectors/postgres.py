from __future__ import annotations

from typing import Any

import psycopg2
import psycopg2.extras


LOGIN_ACCOUNTS_QUERY = """
SELECT
    rolname::text AS username,
    rolcanlogin AS login_enabled,
    rolsuper AS superuser,
    rolinherit AS inherit,
    rolcreaterole AS create_role,
    rolcreatedb AS create_database,
    rolreplication AS replication,
    rolbypassrls AS bypass_rls,
    rolconnlimit AS connection_limit,
    rolvaliduntil
FROM pg_catalog.pg_roles
ORDER BY rolname;
"""


ROLE_MEMBERSHIP_QUERY = """
SELECT
    member_role.rolname::text AS username,
    granted_role.rolname::text AS role_name,
    membership.admin_option
FROM pg_catalog.pg_auth_members AS membership
JOIN pg_catalog.pg_roles AS granted_role
    ON granted_role.oid = membership.roleid
JOIN pg_catalog.pg_roles AS member_role
    ON member_role.oid = membership.member
ORDER BY
    member_role.rolname,
    granted_role.rolname;
"""


DATABASE_PRIVILEGE_QUERY = """
SELECT
    role.rolname::text AS username,
    db.datname::text AS database_name,
    has_database_privilege(
        role.rolname,
        db.datname,
        'CONNECT'
    ) AS can_connect,
    has_database_privilege(
        role.rolname,
        db.datname,
        'CREATE'
    ) AS can_create,
    has_database_privilege(
        role.rolname,
        db.datname,
        'TEMP'
    ) AS can_temp
FROM pg_catalog.pg_roles AS role
CROSS JOIN pg_catalog.pg_database AS db
WHERE
    role.rolcanlogin = TRUE
    AND db.datallowconn = TRUE
    AND NOT db.datistemplate
ORDER BY
    role.rolname,
    db.datname;
"""


class PostgreSQLIAMConnector:
    def __init__(
        self,
        source: dict[str, Any],
        password: str,
    ):
        self.source = source
        self.password = password

    def _connect(
        self,
    ):
        connection = psycopg2.connect(
            host=self.source["host"],
            port=int(
                self.source.get(
                    "port",
                    5432,
                )
            ),
            dbname=self.source["database"],
            user=self.source["username"],
            password=self.password,
            sslmode=self.source.get(
                "sslmode",
                "prefer",
            ),
            connect_timeout=int(
                self.source.get(
                    "connect_timeout",
                    10,
                )
            ),
            application_name=(
                "compliance-iam-db-collector"
            ),
        )

        #
        # Defense-in-depth:
        #
        # Even if the configured credential has write privileges,
        # every collector transaction is forced read-only.
        #
        connection.set_session(
            readonly=True,
            autocommit=False,
        )

        return connection

    @staticmethod
    def _query(
        cursor,
        statement: str,
    ) -> list[dict[str, Any]]:
        cursor.execute(
            statement,
        )

        return [
            dict(row)
            for row in cursor.fetchall()
        ]

    def test_connection(
        self,
    ) -> dict[str, Any]:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT "
                    "current_database(), "
                    "current_user, "
                    "pg_is_in_recovery();"
                )

                row = cursor.fetchone()

                return {
                    "database": row[0],
                    "current_user": row[1],
                    "in_recovery": row[2],
                }

    def collect(
        self,
    ) -> dict[str, Any]:
        with self._connect() as connection:
            with connection.cursor(
                cursor_factory=(
                    psycopg2.extras.RealDictCursor
                )
            ) as cursor:

                accounts = self._query(
                    cursor,
                    LOGIN_ACCOUNTS_QUERY,
                )

                memberships = self._query(
                    cursor,
                    ROLE_MEMBERSHIP_QUERY,
                )

                database_privileges = self._query(
                    cursor,
                    DATABASE_PRIVILEGE_QUERY,
                )

                connection.rollback()

        normalized_accounts = []

        for account in accounts:
            normalized_accounts.append(
                {
                    "username": account[
                        "username"
                    ],
                    "login_enabled": bool(
                        account[
                            "login_enabled"
                        ]
                    ),
                    "privileged": bool(
                        account["superuser"]
                        or account[
                            "create_role"
                        ]
                        or account[
                            "create_database"
                        ]
                        or account[
                            "replication"
                        ]
                        or account[
                            "bypass_rls"
                        ]
                    ),
                    "superuser": bool(
                        account["superuser"]
                    ),
                    "create_role": bool(
                        account["create_role"]
                    ),
                    "create_database": bool(
                        account[
                            "create_database"
                        ]
                    ),
                    "replication": bool(
                        account["replication"]
                    ),
                    "bypass_rls": bool(
                        account["bypass_rls"]
                    ),
                    "inherit": bool(
                        account["inherit"]
                    ),
                    "connection_limit": (
                        account[
                            "connection_limit"
                        ]
                    ),
                    "valid_until": (
                        account[
                            "rolvaliduntil"
                        ].isoformat()
                        if account[
                            "rolvaliduntil"
                        ]
                        else None
                    ),
                }
            )

        normalized_memberships = []

        for membership in memberships:
            normalized_memberships.append(
                {
                    "username": membership[
                        "username"
                    ],
                    "role_name": membership[
                        "role_name"
                    ],
                    "membership_type": (
                        "direct"
                    ),
                    "admin_option": bool(
                        membership[
                            "admin_option"
                        ]
                    ),
                }
            )

        normalized_privileges = []

        for privilege in database_privileges:
            normalized_privileges.append(
                {
                    "username": privilege[
                        "username"
                    ],
                    "database_name": (
                        privilege[
                            "database_name"
                        ]
                    ),
                    "can_connect": bool(
                        privilege[
                            "can_connect"
                        ]
                    ),
                    "can_create": bool(
                        privilege[
                            "can_create"
                        ]
                    ),
                    "can_temp": bool(
                        privilege[
                            "can_temp"
                        ]
                    ),
                }
            )

        return {
            "accounts": normalized_accounts,
            "memberships": (
                normalized_memberships
            ),
            "database_privileges": (
                normalized_privileges
            ),
        }
