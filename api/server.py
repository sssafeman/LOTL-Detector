"""
REST API server for LOTL Detection Framework

Security: Bearer API key auth, restricted CORS, loopback binding.
All endpoints except /api/health require authentication.
"""
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

from api.auth import KeyStore
from api.routes import register_routes as register_api_routes
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
    """Resolve the configured API key source using documented precedence."""
    key_store = app.config.get('API_KEY_STORE')
    if key_store is not None:
        return key_store

    api_keys = app.config.get('API_KEYS')
    api_key = app.config.get('API_KEY')
    if api_keys:
        return KeyStore.from_records(api_keys)
    if api_key:
        return KeyStore.from_single(api_key)
    if not app.config.get('TESTING'):
        return KeyStore.load()
    return None


def _configure_authentication(app: Flask) -> Optional[KeyStore]:
    """Configure authentication and return the active key store."""
    key_store = _build_key_store(app)
    if key_store is None and not app.config.get('TESTING'):
        logger.error(
            "No API key configured. Set LOTL_API_KEY env var or run: "
            "python -m api.auth generate"
        )
        logger.error(
            "Server starting without authentication. All endpoints are unprotected."
        )
    if key_store is not None:
        logger.info(
            f"Authentication enabled with {len(key_store)} key(s): "
            f"{key_store.labels}"
        )
    app.config['API_KEY_STORE'] = key_store
    return key_store


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
    app = create_app()
    host = app.config.get('API_HOST', '127.0.0.1')
    port = app.config.get('API_PORT', 5000)
    debug = app.config.get('API_DEBUG', False)

    # Safety check: never expose debug mode on a non-loopback interface
    if debug and host not in ('127.0.0.1', '::1', 'localhost'):
        raise RuntimeError(
            f"Refusing to start: debug mode cannot be enabled on {host}. "
            f"Use 127.0.0.1 for debug mode, or disable debug for remote access."
        )

    app.run(debug=debug, host=host, port=port)
