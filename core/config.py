"""
Configuration management for LOTL Detector

This module provides centralized configuration loading with validation,
caching, and sensible defaults.
"""
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


# Singleton cache for configuration
_config_cache: Optional[Dict[str, Any]] = None


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
        'host': '0.0.0.0',
        'port': 5000,
        'debug': False
    }
}


class ConfigurationError(Exception):
    """Raised when configuration is invalid"""
    pass


def _validate_config(config: Dict[str, Any]) -> None:
    """
    Validate configuration values

    Args:
        config: Configuration dictionary to validate

    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Validate API port
    if 'api' in config and 'port' in config['api']:
        port = config['api']['port']
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ConfigurationError(
                f"API port must be between 1 and 65535, got: {port}"
            )

    # Validate logging level
    if 'logging' in config and 'level' in config['logging']:
        level = config['logging']['level']
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if level.upper() not in valid_levels:
            raise ConfigurationError(
                f"Logging level must be one of {valid_levels}, got: {level}"
            )

    # Validate API debug flag
    if 'api' in config and 'debug' in config['api']:
        debug = config['api']['debug']
        if not isinstance(debug, bool):
            raise ConfigurationError(
                f"API debug must be boolean, got: {type(debug).__name__}"
            )

    # Validate rules directory exists (if not default)
    if 'rules' in config and 'directory' in config['rules']:
        rules_dir = config['rules']['directory']
        if rules_dir != DEFAULT_CONFIG['rules']['directory']:
            if not os.path.isdir(rules_dir):
                raise ConfigurationError(
                    f"Rules directory does not exist: {rules_dir}"
                )


def _merge_configs(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two configuration dictionaries

    Args:
        base: Base configuration (defaults)
        override: Override configuration (from file)

    Returns:
        Merged configuration dictionary
    """
    result = base.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_configs(result[key], value)
        else:
            result[key] = value

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
    # Start with default configuration
    config = DEFAULT_CONFIG.copy()

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

    # Validate the final configuration
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
    global _config_cache

    # Return cached config if available and reload not requested
    if _config_cache is not None and not reload:
        return _config_cache

    # Load and cache configuration
    _config_cache = load_config(config_path)

    return _config_cache


def reset_config_cache() -> None:
    """
    Reset the configuration cache

    This is primarily useful for testing to ensure a fresh config load.
    """
    global _config_cache
    _config_cache = None


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
