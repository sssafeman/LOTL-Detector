"""
REST API server for LOTL Detection Framework

Security: Bearer API key auth, restricted CORS, loopback binding.
All endpoints except /api/health require authentication.
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from flask import Flask, jsonify, request
from flask_cors import CORS

from api.auth import KeyStore, require_scope
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
from core.export import format_records
from core.ingest import (
    IngestionService,
    linux_auditd_parser,
    macos_eslogger_parser,
    windows_sysmon_parser,
)
from core.rule_loader import RuleLoader
from core.source_validator import SourceValidationError, validate_log_source

logger = logging.getLogger(__name__)

# Global instances
db = None
rule_loader = None
engine = None
correlator = None
collectors = {}

SUPPORTED_PLATFORMS = ('windows', 'linux', 'macos')
DEFAULT_CONFIG = {
    'DATABASE_PATH': 'alerts.db',
    'RULES_DIR': 'rules',
    'LOG_LEVEL': 'INFO',
    'API_HOST': '127.0.0.1',
    'API_PORT': 5000,
    'API_DEBUG': False,
}


class RequestValidationError(ValueError):
    """Represent a client input error with an API-safe message."""


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


def _query_alerts(args) -> list[Dict[str, Any]]:
    """Apply alert query parameters using the API's filter precedence."""
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    if start_time:
        start_time = datetime.fromisoformat(start_time)
    if end_time:
        end_time = datetime.fromisoformat(end_time)

    severity = args.get('severity')
    platform = args.get('platform')
    min_score = args.get('min_score', type=int)
    limit = args.get('limit', type=int, default=100)
    if severity:
        return db.get_alerts_by_severity(severity)
    if platform:
        return db.get_alerts_by_platform(platform)
    if min_score is not None:
        return db.get_high_score_alerts(min_score)
    return db.get_alerts(
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )


def _query_export_records(args) -> Tuple[list[Dict[str, Any]], str]:
    """Load and filter records for the export endpoint."""
    kind = args.get('kind', 'alerts')
    output_format = args.get('format', 'json')
    if output_format.lower() not in ('cef', 'json'):
        raise RequestValidationError("format must be 'cef' or 'json'")

    severity = args.get('severity')
    platform = args.get('platform')
    min_score = args.get('min_score', type=int)
    limit = args.get('limit', type=int, default=1000)
    if kind == 'incidents':
        records = db.get_incidents(
            severity=severity,
            platform=platform,
            min_score=min_score,
            limit=limit,
        )
        return records, output_format

    records = db.get_alerts(limit=limit)
    if severity:
        records = [
            record for record in records
            if record.get('severity') == severity
        ]
    if platform:
        records = [
            record for record in records
            if record.get('platform') == platform
        ]
    if min_score is not None:
        records = [
            record for record in records
            if record.get('score', 0) >= min_score
        ]
    return records, output_format


def _rules_payload() -> Dict[str, Any]:
    """Serialize loaded rules and calculate their summary counts."""
    rules_data = [rule.to_dict() for rule in engine.rules]
    stats = {
        'total': len(rules_data),
        'by_platform': {},
        'by_severity': {},
    }
    for rule in engine.rules:
        platform_counts = stats['by_platform']
        severity_counts = stats['by_severity']
        platform_counts[rule.platform] = platform_counts.get(rule.platform, 0) + 1
        severity_counts[rule.severity] = severity_counts.get(rule.severity, 0) + 1
    return {
        'count': len(rules_data),
        'rules': rules_data,
        'stats': stats,
    }


def _parse_source_request(
    data: Optional[Dict[str, Any]], platform_error: str
) -> Tuple[str, str]:
    """Validate the fields shared by scan and ingestion requests."""
    if not data:
        raise RequestValidationError('Request body is required')

    platform = data.get('platform')
    log_path = data.get('log_path')
    if not platform or not log_path:
        raise RequestValidationError('platform and log_path are required')
    if platform not in SUPPORTED_PLATFORMS:
        raise RequestValidationError(platform_error)
    return platform, log_path


def _validate_source_path(
    app: Flask, log_path: str, platform: str
) -> str:
    """Validate a client supplied source path against configured limits."""
    allowed_roots = app.config.get('ALLOWED_LOG_ROOTS', [])
    max_size_mb = app.config.get('MAX_FILE_SIZE_MB', 100)
    max_size_bytes = (
        max_size_mb * 1024 * 1024
        if max_size_mb
        else 100 * 1024 * 1024
    )
    try:
        return validate_log_source(
            log_path,
            platform,
            allowed_roots=allowed_roots,
            max_file_size=max_size_bytes,
        )
    except SourceValidationError as error:
        raise RequestValidationError(
            f'Invalid log source: {error}'
        ) from error


def _save_alert_results(alerts) -> Tuple[list[Dict[str, Any]], int, int, int]:
    """Persist alerts and return results with new, duplicate, and suppressed counts."""
    results = [db.save_alert_dedup(alert) for alert in alerts]
    new_count = sum(
        1 for result in results
        if not result['is_duplicate'] and not result.get('is_suppressed')
    )
    duplicate_count = sum(
        1 for result in results if result['is_duplicate']
    )
    suppressed_count = sum(
        1 for result in results if result.get('is_suppressed')
    )
    return results, new_count, duplicate_count, suppressed_count


def _save_incident_results(events) -> Tuple[list[Dict[str, Any]], int]:
    """Correlate a batch, persist incidents, and count new records."""
    incidents = correlator.correlate(events) if correlator else []
    results = []
    for incident in incidents:
        results.append({
            **db.save_incident(incident),
            'chain_id': incident.chain_id,
            'score': incident.score,
            'risk_band': incident.risk_band,
        })
    new_count = sum(1 for result in results if not result['is_duplicate'])
    logger.info(f"Correlated {new_count} new incidents")
    return results, new_count


def _scan_source(app: Flask, data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Collect, detect, correlate, and persist one scan request."""
    platform, log_path = _parse_source_request(
        data,
        'platform must be "windows", "linux", or "macos"',
    )
    validated_path = _validate_source_path(app, log_path, platform)
    collector = collectors.get(platform)
    if not collector:
        raise RequestValidationError(
            f'No collector available for platform: {platform}'
        )

    logger.info(f"Scanning {platform} logs at {validated_path}")
    events = collector.collect_events(validated_path)
    logger.info(f"Collected {len(events)} events")
    alerts = engine.match_events(events)
    logger.info(f"Generated {len(alerts)} alerts")

    alert_results, new_alerts, duplicates, suppressed = _save_alert_results(
        alerts
    )
    incident_results, new_incidents = _save_incident_results(events)
    return {
        'events_processed': len(events),
        'alerts_generated': new_alerts,
        'duplicates_updated': duplicates,
        'suppressed': suppressed,
        'incidents_generated': new_incidents,
        'incident_results': incident_results,
        'results': alert_results,
    }


def _parser_for_platform(platform: str):
    """Build the incremental parser for a supported platform."""
    parser_factories = {
        'linux': linux_auditd_parser,
        'windows': windows_sysmon_parser,
        'macos': macos_eslogger_parser,
    }
    return parser_factories[platform](collectors[platform])


def _ingest_source(
    app: Flask, data: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Validate and execute an incremental ingestion request."""
    platform, log_path = _parse_source_request(
        data,
        'incremental ingestion supports "linux", "windows", or "macos"',
    )
    validated_path = _validate_source_path(app, log_path, platform)
    service = IngestionService(
        db,
        engine,
        _parser_for_platform(platform),
        correlator=correlator,
        batch_size=data.get('batch_size', 500),
    )
    return service.ingest_file(validated_path)


def register_routes(
    app: Flask, key_store: Optional[KeyStore] = None
) -> Flask:
    """Register all API routes with scope-aware authentication"""

    # Health check is the only unauthenticated endpoint
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Public health check endpoint. Returns minimal info."""
        return jsonify({'status': 'ok'})

    # When no key store is configured (tests, or explicitly unprotected),
    # endpoints run without auth. Otherwise each endpoint requires a key
    # holding the endpoint's scope: read for queries, scan for
    # scan/ingest, admin for state changes and suppressions.
    use_auth = key_store is not None

    def scoped(scope):
        """Return a scope-enforcing decorator, or passthrough if no auth."""
        if use_auth:
            return require_scope(key_store, scope)

        def passthrough(f):
            return f
        return passthrough

    def auth_decorator():
        """Backward-compatible read-scope decorator."""
        return scoped('read')

    @app.route('/api/alerts', methods=['GET'])
    @auth_decorator()
    def get_alerts():
        """
        Get alerts with optional filtering

        Query parameters:
        - start_time: ISO format datetime
        - end_time: ISO format datetime
        - severity: critical, high, medium, low
        - platform: windows, linux, macos
        - min_score: minimum alert score
        - limit: maximum number of results (default 100)
        """
        try:
            alerts = _query_alerts(request.args)
            return jsonify({
                'count': len(alerts),
                'alerts': alerts
            })

        except ValueError as e:
            return jsonify({'error': 'Invalid parameter', 'message': str(e)}), 400
        except Exception as e:
            logger.error(f"Error fetching alerts: {e}")
            return jsonify({'error': 'Failed to fetch alerts', 'message': str(e)}), 500

    @app.route('/api/alerts/<int:alert_id>', methods=['GET'])
    @auth_decorator()
    def get_alert(alert_id):
        """Get a single alert by ID"""
        try:
            alerts = db.get_alerts(limit=10000)  # Get all alerts
            alert = next((a for a in alerts if a['id'] == alert_id), None)

            if alert:
                return jsonify(alert)
            else:
                return jsonify({'error': 'Alert not found'}), 404

        except Exception as e:
            logger.error(f"Error fetching alert {alert_id}: {e}")
            return jsonify({'error': 'Failed to fetch alert', 'message': str(e)}), 500

    @app.route('/api/export', methods=['GET'])
    @auth_decorator()
    def export_records():
        """
        Export alerts or incidents in a SIEM format.

        Query parameters:
        - kind: 'alerts' (default) or 'incidents'
        - format: 'cef' or 'json' (default 'json', ECS-aligned)
        - severity, platform, min_score, limit: passed through to the query

        Returns newline-delimited records (text/plain) so the response
        streams directly into syslog or a file collector.
        """
        try:
            records, output_format = _query_export_records(request.args)
            lines = format_records(records, output_format)
            body = "\n".join(lines) + ("\n" if lines else "")
            return app.response_class(body, mimetype='text/plain')

        except RequestValidationError as e:
            return jsonify({'error': str(e)}), 400
        except ValueError as e:
            return jsonify({'error': 'Invalid parameter', 'message': str(e)}), 400
        except Exception as e:
            logger.error(f"Error exporting records: {e}")
            return jsonify({'error': 'Export failed', 'message': str(e)}), 500

    @app.route('/api/stats', methods=['GET'])
    @auth_decorator()
    def get_stats():
        """Get database statistics"""
        try:
            stats = db.get_stats()
            engine_stats = engine.get_stats()

            return jsonify({
                'alerts': stats,
                'rules': engine_stats
            })

        except Exception as e:
            logger.error(f"Error fetching stats: {e}")
            return jsonify({'error': 'Failed to fetch statistics', 'message': str(e)}), 500

    @app.route('/api/rules', methods=['GET'])
    @auth_decorator()
    def get_rules():
        """Get all loaded detection rules"""
        try:
            return jsonify(_rules_payload())

        except Exception as e:
            logger.error(f"Error fetching rules: {e}")
            return jsonify({'error': 'Failed to fetch rules', 'message': str(e)}), 500

    @app.route('/api/scan', methods=['POST'])
    @scoped('scan')
    def scan_logs():
        """
        Scan log files for threats

        Request body:
        {
            "platform": "windows" or "linux",
            "log_path": "/path/to/logs"
        }

        Returns:
        {
            "events_processed": N,
            "alerts_generated": N,
            "alert_ids": [...]
        }
        """
        try:
            return jsonify(_scan_source(app, request.get_json()))

        except RequestValidationError as e:
            return jsonify({'error': str(e)}), 400
        except ValueError as e:
            return jsonify({'error': 'Invalid request', 'message': str(e)}), 400
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return jsonify({'error': 'Scan failed', 'message': str(e)}), 500

    @app.route('/api/incidents', methods=['GET'])
    @auth_decorator()
    def get_incidents():
        """
        Get correlated incidents with optional filtering

        Query parameters:
        - chain_id: filter by chain rule ID
        - severity: critical, high, medium, low
        - platform: windows, linux, macos
        - min_score: minimum incident score
        - limit: maximum number of results (default 100)
        """
        try:
            incidents = db.get_incidents(
                chain_id=request.args.get('chain_id'),
                severity=request.args.get('severity'),
                platform=request.args.get('platform'),
                min_score=request.args.get('min_score', type=int),
                limit=request.args.get('limit', type=int, default=100),
            )
            return jsonify({
                'count': len(incidents),
                'incidents': incidents,
            })
        except Exception as e:
            logger.error(f"Error fetching incidents: {e}")
            return jsonify({'error': 'Failed to fetch incidents', 'message': str(e)}), 500

    @app.route('/api/ingest', methods=['POST'])
    @scoped('scan')
    def ingest_source():
        """
        Incrementally ingest new content from a line-oriented log source.

        Body: {"platform": "linux", "log_path": "/var/log/audit/audit.log",
               "batch_size": 500 (optional)}

        Only content appended since the last ingest of this source is
        processed, tracked by a durable byte-offset checkpoint. Writes are
        idempotent via alert and incident fingerprint dedup. Currently
        supports linux auditd sources (file tailing).
        """
        try:
            return jsonify(_ingest_source(app, request.get_json()))

        except RequestValidationError as e:
            return jsonify({'error': str(e)}), 400
        except ValueError as e:
            return jsonify({'error': 'Invalid request', 'message': str(e)}), 400
        except Exception as e:
            logger.error(f"Error during ingest: {e}")
            return jsonify({'error': 'Ingest failed', 'message': str(e)}), 500

    @app.route('/api/alerts/<int:alert_id>/state', methods=['POST'])
    @scoped('admin')
    def update_alert_state(alert_id):
        """Update an alert's lifecycle state."""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body is required'}), 400

            new_state = data.get('state')
            author = data.get('author', 'api')
            reason = data.get('reason', '')

            if not new_state:
                return jsonify({'error': 'state is required'}), 400

            updated = db.update_alert_state(alert_id, new_state, author, reason)
            if updated:
                return jsonify({'status': 'updated', 'alert_id': alert_id, 'state': new_state})
            else:
                return jsonify({'error': 'Alert not found'}), 404

        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Error updating alert state: {e}")
            return jsonify({'error': 'Failed to update state', 'message': str(e)}), 500

    @app.route('/api/suppressions', methods=['POST'])
    @scoped('admin')
    def create_suppression():
        """Create a new alert suppression."""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body is required'}), 400

            fingerprint = data.get('fingerprint')
            scope = data.get('scope', 'global')
            scope_value = data.get('scope_value')
            author = data.get('author', 'api')
            reason = data.get('reason', '')
            duration_hours = data.get('duration_hours', 24)

            if not fingerprint:
                return jsonify({'error': 'fingerprint is required'}), 400
            if scope not in ('global', 'host'):
                return jsonify({'error': 'scope must be global or host'}), 400
            if scope == 'host' and not scope_value:
                return jsonify({'error': 'scope_value is required for host scope'}), 400
            if not reason:
                return jsonify({'error': 'reason is required'}), 400

            sid = db.add_suppression(
                fingerprint, scope, scope_value, author, reason, duration_hours
            )
            return jsonify({'status': 'created', 'suppression_id': sid})

        except Exception as e:
            logger.error(f"Error creating suppression: {e}")
            return jsonify({'error': 'Failed to create suppression', 'message': str(e)}), 500

    return app


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
