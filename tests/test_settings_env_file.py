"""The settings error names the .env path it checked (#143).

On a regular install the project-root walk in utils/config.py lands outside
any checkout, no .env is read, and the first symptom is a validation error
that names a field the user has already set. The error must say which file
was not read, because nothing else does.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from fortianalyzer_mcp.utils import config


class _SettingsWithoutEnvFile(config.Settings):
    """What Settings becomes when the project-root walk misses: no dotenv at all."""

    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def no_env_file_read(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make get_settings build a Settings that reads no .env, with the cache cleared around it."""
    monkeypatch.setattr(config, "Settings", _SettingsWithoutEnvFile)
    monkeypatch.delenv("FORTIANALYZER_HOST", raising=False)
    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()


def test_missing_setting_error_names_the_env_path_that_was_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_env_file_read: None
) -> None:
    missing = tmp_path / ".env"
    monkeypatch.setattr(config, "_ENV_FILE", missing)

    with pytest.raises(ValidationError) as excinfo:
        config.get_settings()

    assert "FORTIANALYZER_HOST" in str(excinfo.value)
    notes = "\n".join(getattr(excinfo.value, "__notes__", []))
    assert str(missing) in notes
    assert "working directory" in notes


def test_error_carries_no_env_note_when_the_file_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_env_file_read: None
) -> None:
    present = tmp_path / ".env"
    present.write_text("")
    monkeypatch.setattr(config, "_ENV_FILE", present)

    with pytest.raises(ValidationError) as excinfo:
        config.get_settings()

    assert "FORTIANALYZER_HOST" in str(excinfo.value)
    assert not getattr(excinfo.value, "__notes__", None)
