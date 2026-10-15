"""
Configuration management for LOTL Detector

This module provides centralized configuration loading with validation,
caching, and sensible defaults.
"""
import copy
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


# Per-path cache for configuration
_config_cache: Dict[str, Dict[str, Any]] = {}

VALID_LOG_LEVELS = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')


# Default configuration values
DEFAULT_CONFIG = {
    'database': {
        'path': 'alerts.db'
    },
    'rules': {
        'directory': 'rules/'
    },
    'logging': {
        'level': 'INFO',
        'file': 'detector.log'
    },
    'api': {
        'host': '127.0.0.1',
        'port': 5000,
        'debug': False
    },
    'scan': {
        'allowed_roots': [],
        'max_file_size_mb': 100
    }
}


class ConfigurationError(Exception):
    """Raised when configuration is invalid"""
    pass


def _validate_config(config: Dict[str, Any]) -> None:
    """
    Validate configuration values and structure

    A section set to None is an explicit opt-out and passes validation.
    A section set to anything else than a mapping, or values consumers
    cannot use (boolean ports, non-string paths), raise
    ConfigurationError (finding E16).

    Args:
        config: Configuration dictionary to validate

    Raises:
        ConfigurationError: If configuration is invalid
    """
    for section in ('database', 'rules', 'logging', 'api', 'scan'):
        value = config.get(section)
        if value is not None and not isinstance(value, dict):
            raise ConfigurationError(
                f"Configuration section '{section}' must be a mapping, "
                f"got: {type(value).__name__}"
            )

    database = config.get('database') or {}
    if 'path' in database and not isinstance(database['path'], str):
        raise ConfigurationError(
            f"Database path must be a string, got: {database['path']!r}"
        )

    api = config.get('api') or {}
    if 'port' in api:
        port = api['port']
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ConfigurationError(
                f"API port must be an integer between 1 and 65535, got: {port!r}"
            )
    if 'debug' in api and not isinstance(api['debug'], bool):
        raise ConfigurationError(
            f"API debug must be boolean, got: {type(api['debug']).__name__}"
        )
    if 'host' in api and not isinstance(api['host'], str):
        raise ConfigurationError(
            f"API host must be a string, got: {api['host']!r}"
        )

    logging_section = config.get('logging') or {}
    if 'level' in logging_section:
        level = logging_section['level']
        if not isinstance(level, str) or level.strip().upper() not in VALID_LOG_LEVELS:
            raise ConfigurationError(
                f"Logging level must be one of {list(VALID_LOG_LEVELS)}, "
                f"got: {level!r}"
            )
    if 'file' in logging_section and not isinstance(logging_section['file'], str):
        raise ConfigurationError(
            f"Logging file must be a string, got: {logging_section['file']!r}"
        )

    rules = config.get('rules') or {}
    rules_dir = rules.get('directory')
    if rules_dir is not None:
        if not isinstance(rules_dir, str):
            raise ConfigurationError(
                f"Rules directory must be a string, got: {rules_dir!r}"
            )
        if (
            rules_dir != DEFAULT_CONFIG['rules']['directory']
            and not os.path.isdir(rules_dir)
        ):
            raise ConfigurationError(
                f"Rules directory does not exist: {rules_dir}"
            )

    scan = config.get('scan') or {}
    allowed_roots = scan.get('allowed_roots')
    if allowed_roots is not None:
        if not isinstance(allowed_roots, list) or not all(
            isinstance(root, str) for root in allowed_roots
        ):
            raise ConfigurationError(
                f"scan.allowed_roots must be a list of strings, "
                f"got: {allowed_roots!r}"
            )
    max_file_size = scan.get('max_file_size_mb')
    if max_file_size is not None:
        if (
            isinstance(max_file_size, bool)
            or not isinstance(max_file_size, int)
            or max_file_size <= 0
        ):
            raise ConfigurationError(
                f"scan.max_file_size_mb must be a positive integer, "
                f"got: {max_file_size!r}"
            )


def _normalize_config(config: Dict[str, Any]) -> None:
    """Normalize values once so every consumer sees the same form.

    Logging levels are stored uppercase; the server resolves them with
    getattr(logging, level), so a lowercase level that passed the old
    validation crashed startup (finding E16).
    """
    logging_section = config.get('logging')
    if isinstance(logging_section, dict):
        level = logging_section.get('level')
        if isinstance(level, str):
            logging_section['level'] = level.strip().upper()


def _merge_configs(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two configuration dictionaries

    Args:
        base: Base configuration (defaults)
        override: Override configuration (from file)

    Returns:
        Merged configuration dictionary
    """
    result = copy.deepcopy(base)

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_configs(result[key], value)
        else:
            result[key] = copy.deepcopy(value)

    return result


def load_config(config_path: str = 'config.yml') -> Dict[str, Any]:
    """
    Load configuration from YAML file with validation

    Args:
        config_path: Path to configuration file (default: config.yml)

    Returns:
        Configuration dictionary

    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Start with an independent copy of the default configuration
    config = copy.deepcopy(DEFAULT_CONFIG)

    # Try to load config file if it exists
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f)

            # Merge file config with defaults
            if file_config:
                config = _merge_configs(DEFAULT_CONFIG, file_config)

        except yaml.YAMLError as e:
            raise ConfigurationError(f"Failed to parse config file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load config file: {e}")

    # Normalize values once, then validate the final configuration
    _normalize_config(config)
    _validate_config(config)

    return config


def get_config(config_path: str = 'config.yml', reload: bool = False) -> Dict[str, Any]:
    """
    Get configuration with caching (singleton pattern)

    The configuration is loaded once and cached. Subsequent calls return
    the cached configuration unless reload=True is specified.

    Args:
        config_path: Path to configuration file (default: config.yml)
        reload: Force reload of configuration (default: False)

    Returns:
        Configuration dictionary

    Raises:
        ConfigurationError: If configuration is invalid

    Example:
        >>> config = get_config()
        >>> db_path = config['database']['path']
        >>> api_port = config['api']['port']
    """
    cache_key = str(Path(config_path).resolve())

    # Return cached config if available and reload not requested
    if cache_key in _config_cache and not reload:
        return _config_cache[cache_key]

    # Load and cache configuration
    _config_cache[cache_key] = load_config(config_path)

    return _config_cache[cache_key]


def reset_config_cache() -> None:
    """
    Reset the configuration cache

    This is primarily useful for testing to ensure a fresh config load.
    """
    _config_cache.clear()


def get_database_path() -> str:
    """
    Get database path from configuration

    Returns:
        Database file path
    """
    config = get_config()
    return config['database']['path']


def get_rules_directory() -> str:
    """
    Get rules directory from configuration

    Returns:
        Rules directory path
    """
    config = get_config()
    return config['rules']['directory']


def get_logging_config() -> Dict[str, Any]:
    """
    Get logging configuration

    Returns:
        Logging configuration dictionary with 'level' and 'file' keys
    """
    config = get_config()
    return config['logging']


def get_api_config() -> Dict[str, Any]:
    """
    Get API configuration

    Returns:
        API configuration dictionary with 'host', 'port', and 'debug' keys
    """
    config = get_config()
    return config['api']
