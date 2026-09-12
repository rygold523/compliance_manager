from sqlalchemy import text

from app.core.database import engine


def main() -> None:
    statements = (
        "ALTER TABLE local_users ADD COLUMN IF NOT EXISTS inactivity_exempt BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE local_users ADD COLUMN IF NOT EXISTS inactivity_exemption_reason VARCHAR(500)",
    )
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
    print("Dormant-account schema migration completed.")


if __name__ == "__main__":
    main()
