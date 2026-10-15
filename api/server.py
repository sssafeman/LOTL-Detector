"""
REST API server for LOTL Detection Framework

Security: Bearer API key auth, restricted CORS, loopback binding.
All endpoints except /api/health require authentication. Startup is
refused when no valid credentials are configured unless the explicit,
loopback-only demo bypass (LOTL_ALLOW_UNAUTHENTICATED) is set.
"""
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

from api.auth import CredentialConfigurationError, KeyStore, MIN_KEY_LENGTH
from api.routes import register_routes as register_api_routes
from api.startup import StartupError, validate_startup_binding
from api.workflows import (
    ApiComponents,
    ApiWorkflows,
    RequestValidationError as RequestValidationError,
    SUPPORTED_PLATFORMS as SUPPORTED_PLATFORMS,
)
from collectors.linux.collector import LinuxCollector
from collectors.macos.collector import MacOSCollector
from collectors.windows.collector import WindowsCollector
from core.config import (
    get_config,
    get_database_path,
    get_logging_config,
    get_rules_directory,
)
from core.correlator import ChainRuleLoader, Correlator
from core.database import AlertDatabase
from core.engine import DetectionEngine
from core.rule_loader import RuleLoader

logger = logging.getLogger(__name__)

# Global instances
db = None
rule_loader = None
engine = None
correlator = None
collectors = {}

DEFAULT_CONFIG = {
    'DATABASE_PATH': 'alerts.db',
    'RULES_DIR': 'rules',
    'LOG_LEVEL': 'INFO',
    'API_HOST': '127.0.0.1',
    'API_PORT': 5000,
    'API_DEBUG': False,
}


def _load_application_config(app: Flask) -> None:
    """Populate Flask configuration from the project config system."""
    try:
        app_config = get_config()
        logging_config = get_logging_config()
        scan_config = app_config.get('scan', {})
        app.config.update({
            'DATABASE_PATH': get_database_path(),
            'RULES_DIR': get_rules_directory(),
            'LOG_LEVEL': logging_config['level'],
            'API_HOST': app_config.get('api', {}).get('host', '127.0.0.1'),
            'API_PORT': app_config.get('api', {}).get('port', 5000),
            'API_DEBUG': app_config.get('api', {}).get('debug', False),
            'ALLOWED_LOG_ROOTS': scan_config.get('allowed_roots', []),
            'MAX_FILE_SIZE_MB': scan_config.get('max_file_size_mb', 100),
        })
    except Exception as error:
        logger.warning(f"Failed to load config, using defaults: {error}")
        app.config.update(DEFAULT_CONFIG)


def _build_key_store(app: Flask) -> Optional[KeyStore]:
    """Resolve the configured API key source using documented precedence.

    Raises CredentialConfigurationError when an explicitly configured
    source exists but yields no usable keys.
    """
    key_store = app.config.get('API_KEY_STORE')
    if key_store is not None:
        return key_store

    api_keys = app.config.get('API_KEYS')
    api_key = app.config.get('API_KEY')
    if api_keys:
        store = KeyStore.from_records(api_keys)
        if not len(store):
            raise CredentialConfigurationError(
                "API_KEYS contains no usable keys; each key needs at least "
                f"{MIN_KEY_LENGTH} characters."
            )
        return store
    if api_key:
        if len(str(api_key).strip()) < MIN_KEY_LENGTH:
            raise CredentialConfigurationError(
                f"API_KEY is shorter than {MIN_KEY_LENGTH} characters."
            )
        return KeyStore.from_single(str(api_key).strip())
    if not app.config.get('TESTING'):
        return KeyStore.load()
    return None


def _unauthenticated_demo_allowed(app: Flask) -> bool:
    """Resolve the explicit unauthenticated-demo switch.

    The switch must be set deliberately: either via the app config key
    ALLOW_UNAUTHENTICATED_DEMO or the LOTL_ALLOW_UNAUTHENTICATED env var.
    TESTING mode (unit-test app fixtures) always counts as explicit.
    """
    if app.config.get('TESTING'):
        return True
    explicit = app.config.get('ALLOW_UNAUTHENTICATED_DEMO')
    if explicit is None:
        raw = os.environ.get('LOTL_ALLOW_UNAUTHENTICATED', '')
        explicit = raw.strip().lower() in ('1', 'true', 'yes', 'on')
    return bool(explicit)


def _configure_authentication(app: Flask) -> Optional[KeyStore]:
    """Configure authentication and return the active key store.

    Refuses startup (StartupError) when no valid credentials are available
    and the unauthenticated demo mode was not explicitly enabled.
    """
    key_store = _build_key_store(app)
    if key_store is not None:
        app.config['ALLOW_UNAUTHENTICATED_DEMO'] = False
        app.config['API_KEY_STORE'] = key_store
        logger.info(
            f"Authentication enabled with {len(key_store)} key(s): "
            f"{key_store.labels}"
        )
        return key_store

    if not _unauthenticated_demo_allowed(app):
        raise StartupError(
            "No API credentials configured; refusing to start an "
            "unprotected server. Generate a key with "
            "'python -m api.auth generate', or set LOTL_API_KEY / "
            "LOTL_API_KEYS_FILE. For a loopback-only demo, set "
            "LOTL_ALLOW_UNAUTHENTICATED=1 explicitly."
        )

    app.config['ALLOW_UNAUTHENTICATED_DEMO'] = True
    app.config['API_KEY_STORE'] = None
    logger.warning(
        "API authentication disabled by the explicit unauthenticated demo "
        "switch. Every entry point must bind to a loopback address."
    )
    return None


def _configure_cors(app: Flask) -> None:
    """Enable CORS only when the allowed origin list is non-empty."""
    cors_origins = app.config.get('CORS_ORIGINS', [])
    if not cors_origins:
        logger.info("CORS disabled. No origins allowed.")
        return

    CORS(
        app,
        resources={r"/api/*": {
            "origins": cors_origins,
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Authorization", "Content-Type"],
            "expose_headers": ["Retry-After", "X-Request-ID"],
            "supports_credentials": False,
            "max_age": 3600,
        }},
    )
    logger.info(f"CORS configured for origins: {cors_origins}")


def _register_request_hooks(app: Flask) -> None:
    """Register request logging and shared HTTP error responses."""
    @app.before_request
    def log_request() -> None:
        logger.info(f"{request.method} {request.path} - {request.remote_addr}")

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad request', 'message': str(error)}), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found', 'message': str(error)}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal error: {error}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(error),
        }), 500


def create_app(config: Optional[Dict[str, Any]] = None) -> Flask:
    """
    Create and configure the Flask application

    Args:
        config: Optional configuration dictionary.
                Set API_KEY to inject a test key.
                Set CORS_ORIGINS to configure allowed origins.

    Returns:
        Flask app instance
    """
    app = Flask(__name__)
    _load_application_config(app)
    app.config.setdefault('CORS_ORIGINS', [])
    if config:
        app.config.update(config)

    logging.basicConfig(
        level=getattr(logging, app.config['LOG_LEVEL']),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    key_store = _configure_authentication(app)
    _configure_cors(app)
    initialize_components(app)
    register_routes(app, key_store)
    _register_request_hooks(app)
    return app


def _initialize_database(app: Flask) -> AlertDatabase:
    """Create the database and apply connection tuning for API workloads."""
    database = AlertDatabase(app.config['DATABASE_PATH'])
    try:
        database.connection.execute("PRAGMA journal_mode=WAL")
        database.connection.execute("PRAGMA busy_timeout=5000")
        logger.info("Database WAL mode enabled with 5s busy timeout")
    except Exception as error:
        logger.warning(f"Could not enable WAL mode: {error}")
    logger.info(f"Database initialized: {app.config['DATABASE_PATH']}")
    return database


def _initialize_correlator(rules_dir: str) -> Correlator:
    """Load chain rules, falling back to an empty correlator on failure."""
    chains_dir = str(Path(rules_dir) / 'correlation')
    try:
        chains = ChainRuleLoader().load_chains_directory(chains_dir)
    except Exception as error:
        logger.warning(
            f"Chain rules unavailable, correlation disabled: {error}"
        )
        chains = []
    logger.info(f"Loaded {len(chains)} chain rules")
    return Correlator(chains)


def initialize_components(app: Flask) -> None:
    """Initialize database, rules, correlation, and collectors."""
    global db, rule_loader, engine, correlator, collectors

    db = _initialize_database(app)
    rule_loader = RuleLoader()
    rules = rule_loader.load_rules_directory(app.config['RULES_DIR'])
    logger.info(f"Loaded {len(rules)} detection rules")
    engine = DetectionEngine(rules)
    correlator = _initialize_correlator(app.config['RULES_DIR'])
    collectors.clear()
    collectors.update({
        'windows': WindowsCollector(),
        'linux': LinuxCollector(),
        'macos': MacOSCollector(),
    })
    logger.info("Collectors initialized")


def register_routes(
    app: Flask, key_store: Optional[KeyStore] = None
) -> Flask:
    """Register API routes using the initialized application components."""
    workflows = ApiWorkflows(
        app,
        lambda: ApiComponents(db, engine, correlator, collectors),
        logger,
    )
    return register_api_routes(app, workflows, logger, key_store)


# For development/testing
if __name__ == '__main__':
    try:
        app = create_app()
    except (StartupError, CredentialConfigurationError) as error:
        raise SystemExit(f"Error: {error}")

    host = app.config.get('API_HOST', '127.0.0.1')
    port = app.config.get('API_PORT', 5000)
    debug = app.config.get('API_DEBUG', False)

    # Refuse unsafe bindings before any socket is opened (shared with
    # run.py so every entry point enforces the same rules).
    try:
        validate_startup_binding(
            host,
            debug=debug,
            allow_unauthenticated=bool(
                app.config.get('ALLOW_UNAUTHENTICATED_DEMO')
            ),
        )
    except StartupError as error:
        raise SystemExit(f"Error: {error}")

    app.run(debug=debug, host=host, port=port)
