"""Startup security tests (S1): credential refusal and explicit demo bypass.

S1: production startup refuses to run without valid credentials, and any
unauthenticated demo mode must be an explicit opt-in. The loopback-only
binding enforcement for the demo bypass and the shared entry-point
validation coverage live in tests/test_startup_binding.py (S2).
"""
import json
from pathlib import Path

import pytest

from api import auth as auth_module
from api.auth import CredentialConfigurationError, MIN_KEY_LENGTH
from api.server import create_app
from api.startup import StartupError

VALID_KEY = "unit-test-key-0123456789abcdefghij"  # >= MIN_KEY_LENGTH


@pytest.fixture
def clean_credentials(monkeypatch, tmp_path):
    """Remove ambient credentials so startup tests are deterministic."""
    for var in (
        "LOTL_API_KEY",
        "LOTL_API_KEY_FILE",
        "LOTL_API_KEYS_FILE",
        "LOTL_ALLOW_UNAUTHENTICATED",
    ):
        monkeypatch.delenv(var, raising=False)
    # Never read the user's real default key file during tests.
    monkeypatch.setattr(
        auth_module, "DEFAULT_KEY_FILE", tmp_path / "no-such-key-file", raising=False
    )
    return tmp_path


def _config(tmp_path, **extra):
    config = {
        "DATABASE_PATH": str(tmp_path / "test.db"),
        "RULES_DIR": "rules",
        "LOG_LEVEL": "ERROR",
    }
    config.update(extra)
    return config


class TestCredentialRefusal:
    """Production startup must fail closed without valid credentials."""

    def test_create_app_refuses_without_credentials(self, clean_credentials):
        with pytest.raises(StartupError) as excinfo:
            create_app(_config(clean_credentials))
        assert "LOTL_API_KEY" in str(excinfo.value)

    def test_broken_keys_file_is_fatal(self, clean_credentials, monkeypatch):
        bad = clean_credentials / "keys.json"
        bad.write_text("{not valid json")
        monkeypatch.setenv("LOTL_API_KEYS_FILE", str(bad))
        with pytest.raises(CredentialConfigurationError):
            create_app(_config(clean_credentials))

    def test_keys_file_without_valid_keys_is_fatal(self, clean_credentials, monkeypatch):
        keys = clean_credentials / "keys.json"
        keys.write_text(json.dumps([{"key": "short", "label": "bad"}]))
        monkeypatch.setenv("LOTL_API_KEYS_FILE", str(keys))
        with pytest.raises(CredentialConfigurationError):
            create_app(_config(clean_credentials))

    def test_unreadable_key_file_path_is_fatal(self, clean_credentials, monkeypatch):
        monkeypatch.setenv(
            "LOTL_API_KEY_FILE", str(clean_credentials / "missing.key")
        )
        with pytest.raises(CredentialConfigurationError):
            create_app(_config(clean_credentials))

    def test_short_env_key_is_fatal(self, clean_credentials, monkeypatch):
        monkeypatch.setenv("LOTL_API_KEY", "short")
        with pytest.raises(CredentialConfigurationError):
            create_app(_config(clean_credentials))

    def test_short_config_api_key_is_fatal(self, clean_credentials):
        with pytest.raises(CredentialConfigurationError):
            create_app(_config(clean_credentials, API_KEY="short"))

    def test_config_api_keys_without_valid_records_is_fatal(self, clean_credentials):
        with pytest.raises(CredentialConfigurationError):
            create_app(
                _config(
                    clean_credentials,
                    API_KEYS=[{"key": "short", "label": "bad", "scopes": ["read"]}],
                )
            )

    def test_valid_env_key_starts_with_auth_enabled(self, clean_credentials, monkeypatch):
        monkeypatch.setenv("LOTL_API_KEY", VALID_KEY)
        app = create_app(_config(clean_credentials))
        client = app.test_client()
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/alerts").status_code == 401
        authed = client.get(
            "/api/alerts", headers={"Authorization": f"Bearer {VALID_KEY}"}
        )
        assert authed.status_code == 200

    def test_testing_mode_still_starts_without_credentials(self, clean_credentials):
        app = create_app(_config(clean_credentials, TESTING=True))
        assert app.test_client().get("/api/alerts").status_code == 200


class TestExplicitDemoBypass:
    """The unauthenticated mode is an explicit, opt-in switch."""

    def test_config_flag_enables_explicit_bypass(self, clean_credentials):
        app = create_app(_config(clean_credentials, ALLOW_UNAUTHENTICATED_DEMO=True))
        assert app.config["ALLOW_UNAUTHENTICATED_DEMO"] is True
        assert app.test_client().get("/api/alerts").status_code == 200

    def test_env_flag_enables_explicit_bypass(self, clean_credentials, monkeypatch):
        monkeypatch.setenv("LOTL_ALLOW_UNAUTHENTICATED", "1")
        app = create_app(_config(clean_credentials))
        assert app.config["ALLOW_UNAUTHENTICATED_DEMO"] is True

    def test_disabled_flag_value_stays_refused(self, clean_credentials, monkeypatch):
        monkeypatch.setenv("LOTL_ALLOW_UNAUTHENTICATED", "0")
        with pytest.raises(StartupError):
            create_app(_config(clean_credentials))

    def test_flag_is_false_when_credentials_exist(self, clean_credentials, monkeypatch):
        monkeypatch.setenv("LOTL_API_KEY", VALID_KEY)
        app = create_app(_config(clean_credentials, ALLOW_UNAUTHENTICATED_DEMO=True))
        assert app.config["ALLOW_UNAUTHENTICATED_DEMO"] is False
