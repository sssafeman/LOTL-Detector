"""
Tests for configuration management
"""
import pytest
import os
import tempfile
from pathlib import Path
import yaml
from core.config import (
    load_config,
    get_config,
    reset_config_cache,
    get_database_path,
    get_rules_directory,
    get_logging_config,
    get_api_config,
    ConfigurationError,
    DEFAULT_CONFIG
)


@pytest.fixture(autouse=True)
def reset_cache():
    """Reset config cache before and after each test"""
    reset_config_cache()
    yield
    reset_config_cache()


@pytest.fixture
def temp_config_file():
    """Create a temporary config file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yield f.name
    # Cleanup
    if os.path.exists(f.name):
        os.unlink(f.name)


def test_load_config_with_defaults():
    """Test loading config when no file exists"""
    config = load_config('nonexistent.yml')

    # Should return default configuration
    assert config == DEFAULT_CONFIG
    assert config['database']['path'] == 'alerts.db'
    assert config['rules']['directory'] == 'rules/'
    assert config['logging']['level'] == 'INFO'
    assert config['api']['host'] == '0.0.0.0'
    assert config['api']['port'] == 5000
    assert config['api']['debug'] is False


def test_load_config_from_file(temp_config_file):
    """Test loading config from YAML file"""
    custom_config = {
        'database': {
            'path': 'custom_alerts.db'
        },
        'api': {
            'port': 8080
        }
    }

    # Write custom config
    with open(temp_config_file, 'w') as f:
        yaml.dump(custom_config, f)

    # Load config
    config = load_config(temp_config_file)

    # Should merge with defaults
    assert config['database']['path'] == 'custom_alerts.db'
    assert config['api']['port'] == 8080
    assert config['api']['host'] == '0.0.0.0'  # Default value
    assert config['rules']['directory'] == 'rules/'  # Default value


def test_invalid_port_value(temp_config_file):
    """Test validation of invalid port values"""
    invalid_configs = [
        {'api': {'port': 0}},
        {'api': {'port': 70000}},
        {'api': {'port': -1}},
        {'api': {'port': 'invalid'}},
    ]

    for invalid_config in invalid_configs:
        with open(temp_config_file, 'w') as f:
            yaml.dump(invalid_config, f)

        with pytest.raises(ConfigurationError):
            load_config(temp_config_file)


def test_invalid_logging_level(temp_config_file):
    """Test validation of invalid logging level"""
    invalid_config = {
        'logging': {
            'level': 'INVALID_LEVEL'
        }
    }

    with open(temp_config_file, 'w') as f:
        yaml.dump(invalid_config, f)

    with pytest.raises(ConfigurationError):
        load_config(temp_config_file)


def test_invalid_debug_flag(temp_config_file):
    """Test validation of invalid debug flag"""
    invalid_config = {
        'api': {
            'debug': 'yes'  # Should be boolean
        }
    }

    with open(temp_config_file, 'w') as f:
        yaml.dump(invalid_config, f)

    with pytest.raises(ConfigurationError):
        load_config(temp_config_file)


def test_invalid_yaml_syntax(temp_config_file):
    """Test handling of invalid YAML syntax"""
    with open(temp_config_file, 'w') as f:
        f.write("invalid: yaml: syntax: [unclosed")

    with pytest.raises(ConfigurationError):
        load_config(temp_config_file)


def test_config_caching():
    """Test that config is cached after first load"""
    # Load config twice
    config1 = get_config('nonexistent.yml')
    config2 = get_config('nonexistent.yml')

    # Should return the same object (cached)
    assert config1 is config2


def test_config_reload():
    """Test forcing config reload"""
    # Load config
    config1 = get_config('nonexistent.yml')

    # Force reload
    config2 = get_config('nonexistent.yml', reload=True)

    # Should be different objects but same content
    assert config1 is not config2
    assert config1 == config2


def test_get_database_path():
    """Test getting database path from config"""
    reset_config_cache()
    db_path = get_database_path()
    assert db_path == 'alerts.db'  # Default


def test_get_rules_directory():
    """Test getting rules directory from config"""
    reset_config_cache()
    rules_dir = get_rules_directory()
    assert rules_dir == 'rules/'  # Default


def test_get_logging_config():
    """Test getting logging configuration"""
    reset_config_cache()
    logging_config = get_logging_config()
    assert logging_config['level'] == 'INFO'
    assert logging_config['file'] == 'detector.log'


def test_get_api_config():
    """Test getting API configuration"""
    reset_config_cache()
    api_config = get_api_config()
    assert api_config['host'] == '0.0.0.0'
    assert api_config['port'] == 5000
    assert api_config['debug'] is False


def test_custom_config_values(temp_config_file):
    """Test that custom config values are properly loaded"""
    custom_config = {
        'database': {
            'path': 'production.db'
        },
        'rules': {
            'directory': 'rules/'  # Use existing rules directory
        },
        'logging': {
            'level': 'WARNING',
            'file': '/var/log/lotl.log'
        },
        'api': {
            'host': '127.0.0.1',
            'port': 3000,
            'debug': False
        }
    }

    with open(temp_config_file, 'w') as f:
        yaml.dump(custom_config, f)

    reset_config_cache()
    config = get_config(temp_config_file)

    assert config['database']['path'] == 'production.db'
    assert config['rules']['directory'] == 'rules/'
    assert config['logging']['level'] == 'WARNING'
    assert config['logging']['file'] == '/var/log/lotl.log'
    assert config['api']['host'] == '127.0.0.1'
    assert config['api']['port'] == 3000


def test_partial_config_override(temp_config_file):
    """Test that partial config properly merges with defaults"""
    # Only override one value
    partial_config = {
        'api': {
            'port': 9000
        }
    }

    with open(temp_config_file, 'w') as f:
        yaml.dump(partial_config, f)

    config = load_config(temp_config_file)

    # Custom value
    assert config['api']['port'] == 9000

    # Default values should still be present
    assert config['api']['host'] == '0.0.0.0'
    assert config['api']['debug'] is False
    assert config['database']['path'] == 'alerts.db'
    assert config['rules']['directory'] == 'rules/'


def test_valid_logging_levels(temp_config_file):
    """Test all valid logging levels"""
    valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']

    for level in valid_levels:
        config_data = {
            'logging': {
                'level': level
            }
        }

        with open(temp_config_file, 'w') as f:
            yaml.dump(config_data, f)

        # Should not raise any exception
        config = load_config(temp_config_file)
        assert config['logging']['level'] == level


def test_edge_case_port_values(temp_config_file):
    """Test edge case port values (1 and 65535)"""
    # Minimum valid port
    config_data = {'api': {'port': 1}}
    with open(temp_config_file, 'w') as f:
        yaml.dump(config_data, f)
    config = load_config(temp_config_file)
    assert config['api']['port'] == 1

    # Maximum valid port
    config_data = {'api': {'port': 65535}}
    with open(temp_config_file, 'w') as f:
        yaml.dump(config_data, f)
    reset_config_cache()
    config = load_config(temp_config_file)
    assert config['api']['port'] == 65535


def test_empty_config_file(temp_config_file):
    """Test loading an empty config file"""
    with open(temp_config_file, 'w') as f:
        f.write("")  # Empty file

    config = load_config(temp_config_file)

    # Should return defaults
    assert config == DEFAULT_CONFIG


def test_config_with_none_values(temp_config_file):
    """Test config file with null/None values"""
    config_data = {
        'database': None
    }

    with open(temp_config_file, 'w') as f:
        yaml.dump(config_data, f)

    config = load_config(temp_config_file)

    # None should override the default
    assert config['database'] is None


def test_reset_config_cache_effect():
    """Test that resetting cache forces config reload"""
    # Load config and cache it
    config1 = get_config('nonexistent.yml')
    assert config1 == DEFAULT_CONFIG

    # Reset cache
    reset_config_cache()

    # Load again - should reload, not use cache
    config2 = get_config('nonexistent.yml')

    # Should be different objects
    assert config1 is not config2
    # But same content
    assert config1 == config2
