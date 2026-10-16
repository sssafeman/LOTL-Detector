"""
Configuration hardening tests (finding E16).

Validation must reject values consumers cannot use (non-mapping
sections, boolean ports, non-string paths), normalize logging levels
once, keep defaults unshared, and scope the cache by resolved path.
"""
import logging

import pytest
import yaml

from api.server import create_app
from api.startup import StartupError
from core.config import (
    DEFAULT_CONFIG,
    ConfigurationError,
    get_config,
    load_config,
    reset_config_cache,
)


@pytest.fixture(autouse=True)
def clean_cache():
    reset_config_cache()
    yield
    reset_config_cache()


@pytest.fixture
def temp_config(tmp_path):
    return str(tmp_path / "config.yml")


def _write(path, data):
    with open(path, "w") as handle:
        yaml.dump(data, handle)


def test_lowercase_logging_level_is_normalized(temp_config):
    _write(temp_config, {"logging": {"level": "debug"}})
    config = load_config(temp_config)

    assert config["logging"]["level"] == "DEBUG"
    assert isinstance(getattr(logging, config["logging"]["level"]), int)


@pytest.mark.parametrize("bad_level", ["NOISY", 5, ["INFO"]])
def test_invalid_logging_level_is_rejected(temp_config, bad_level):
    _write(temp_config, {"logging": {"level": bad_level}})
    with pytest.raises(ConfigurationError):
        load_config(temp_config)


@pytest.mark.parametrize("section,value", [
    ("api", "yes"),
    ("logging", 5),
    ("database", ["a"]),
    ("rules", "rules"),
    ("scan", 1),
])
def test_non_mapping_sections_are_rejected(temp_config, section, value):
    _write(temp_config, {section: value})
    with pytest.raises(ConfigurationError):
        load_config(temp_config)


def test_boolean_port_is_rejected(temp_config):
    _write(temp_config, {"api": {"port": True}})
    with pytest.raises(ConfigurationError):
        load_config(temp_config)


@pytest.mark.parametrize("section,data", [
    ("database", {"path": 5}),
    ("logging", {"file": 5}),
    ("api", {"host": 8080}),
    ("scan", {"allowed_roots": "x"}),
    ("scan", {"allowed_roots": [1, 2]}),
    ("scan", {"max_file_size_mb": 0}),
    ("scan", {"max_file_size_mb": "big"}),
])
def test_invalid_values_inside_sections_are_rejected(temp_config, section, data):
    _write(temp_config, {section: data})
    with pytest.raises(ConfigurationError):
        load_config(temp_config)


def test_defaults_are_not_shared_between_loads():
    first = load_config("nonexistent.yml")
    first["api"]["port"] = 9
    first["scan"]["allowed_roots"].append("/tmp/evil")

    second = load_config("nonexistent.yml")
    assert second["api"]["port"] == 5000
    assert second["scan"]["allowed_roots"] == []
    assert DEFAULT_CONFIG["api"]["port"] == 5000
    assert DEFAULT_CONFIG["scan"]["allowed_roots"] == []


def test_cache_is_scoped_by_config_path(tmp_path):
    path_a = str(tmp_path / "a.yml")
    path_b = str(tmp_path / "b.yml")
    _write(path_a, {"api": {"port": 1111}})
    _write(path_b, {"api": {"port": 2222}})

    first_a = get_config(path_a)
    first_b = get_config(path_b)
    assert first_a["api"]["port"] == 1111
    assert first_b["api"]["port"] == 2222

    # Same path keeps returning the same cached object.
    assert get_config(path_a) is first_a


def test_reload_picks_up_changed_content(temp_config):
    _write(temp_config, {"api": {"port": 1111}})
    assert get_config(temp_config)["api"]["port"] == 1111

    _write(temp_config, {"api": {"port": 2222}})
    assert get_config(temp_config)["api"]["port"] == 1111

    reset_config_cache()
    assert get_config(temp_config)["api"]["port"] == 2222


def test_server_rejects_invalid_logging_level(tmp_path):
    with pytest.raises(StartupError):
        create_app({
            "DATABASE_PATH": str(tmp_path / "api.db"),
            "RULES_DIR": "rules",
            "TESTING": True,
            "LOG_LEVEL": "NOISY",
        })


def test_server_accepts_normalized_lowercase_level(tmp_path):
    app = create_app({
        "DATABASE_PATH": str(tmp_path / "api.db"),
        "RULES_DIR": "rules",
        "TESTING": True,
        "LOG_LEVEL": "error",
    })
    assert app.test_client().get("/api/health").status_code == 200


def test_server_aborts_on_invalid_config_file(tmp_path, monkeypatch):
    _write(str(tmp_path / "config.yml"), {"api": {"port": 70000}})
    monkeypatch.chdir(tmp_path)

    with pytest.raises(StartupError):
        create_app({
            "DATABASE_PATH": str(tmp_path / "api.db"),
            "RULES_DIR": "rules",
            "TESTING": True,
        })


def test_server_aborts_when_a_section_is_null(tmp_path, monkeypatch):
    """A null section must not silently discard the rest of the config.

    S2 review finding 1: `logging: null` made the whole config fall back
    to defaults, dropping scan.allowed_roots and the configured port.
    """
    _write(str(tmp_path / "config.yml"), {
        "logging": None,
        "api": {"port": 6789},
        "scan": {"allowed_roots": [str(tmp_path)]},
    })
    monkeypatch.chdir(tmp_path)

    with pytest.raises(StartupError):
        create_app({
            "DATABASE_PATH": str(tmp_path / "api.db"),
            "RULES_DIR": "rules",
            "TESTING": True,
        })
