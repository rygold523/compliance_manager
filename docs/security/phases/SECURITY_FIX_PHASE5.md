# Phase 5: IAM authorization

Raw IAM identities, service accounts, groups, access matrices, database
privileges, database source configuration, and collector health are restricted
to the `admin` and `auditor` roles.

Only `admin` may trigger an on-demand database IAM collection. The
`/api/iam/db-ingest` service endpoint remains authenticated by its separate
collector token and is not converted to session authentication.

The frontend exposes the IAM page only to roles with the `view_iam`
capability. Administrators and auditors receive this capability; viewers do
not. This prevents a viewer from receiving an unusable IAM page filled with
authorization errors while the backend remains authoritative against direct
API requests.
