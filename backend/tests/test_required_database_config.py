import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_database_url_has_no_application_default():
    field = Settings.model_fields["database_url"]
    assert field.is_required()
    assert field.default is not None


def test_missing_database_url_is_rejected(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    error_text = str(exc_info.value)
    assert "database_url" in error_text
    assert "change_me" not in error_text
    assert "postgresql+psycopg2://" not in error_text


def test_explicit_database_url_is_preserved_without_rewriting():
    configured = (
        "postgresql+psycopg2://application-user:"
        "opaque-test-secret@database.internal:5432/application-db"
    )
    loaded = Settings(
        _env_file=None,
        database_url=configured,
    )
    assert loaded.database_url == configured
