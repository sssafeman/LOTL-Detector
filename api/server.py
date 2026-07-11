"""
REST API server for LOTL Detection Framework

Security: Bearer API key auth, restricted CORS, loopback binding.
All endpoints except /api/health require authentication.
"""
import os
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from core.database import AlertDatabase
from core.rule_loader import RuleLoader
from core.engine import DetectionEngine
from core.config import get_config, get_database_path, get_rules_directory, get_logging_config
from collectors.windows.collector import WindowsCollector
from collectors.linux.collector import LinuxCollector
from collectors.macos.collector import MacOSCollector
from api.auth import load_api_key, require_scope, KeyStore
import logging

logger = logging.getLogger(__name__)

# Global instances
db = None
rule_loader = None
engine = None
correlator = None
collectors = {}


def create_app(config=None):
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

    # Load configuration from config system
    try:
        app_config = get_config()
        logging_config = get_logging_config()

        # Set configuration from config system
        app.config['DATABASE_PATH'] = get_database_path()
        app.config['RULES_DIR'] = get_rules_directory()
        app.config['LOG_LEVEL'] = logging_config['level']
        app.config['API_HOST'] = app_config.get('api', {}).get('host', '127.0.0.1')
        app.config['API_PORT'] = app_config.get('api', {}).get('port', 5000)
        app.config['API_DEBUG'] = app_config.get('api', {}).get('debug', False)
        # Load scan source restrictions from config
        scan_config = app_config.get('scan', {})
        app.config['ALLOWED_LOG_ROOTS'] = scan_config.get('allowed_roots', [])
        app.config['MAX_FILE_SIZE_MB'] = scan_config.get('max_file_size_mb', 100)
    except Exception as e:
        logger.warning(f"Failed to load config, using defaults: {e}")
        # Fallback to secure defaults
        app.config['DATABASE_PATH'] = 'alerts.db'
        app.config['RULES_DIR'] = 'rules'
        app.config['LOG_LEVEL'] = 'INFO'
        app.config['API_HOST'] = '127.0.0.1'
        app.config['API_PORT'] = 5000
        app.config['API_DEBUG'] = False

    # Default CORS origins: none allowed unless explicitly configured
    app.config.setdefault('CORS_ORIGINS', [])

    # Override with provided config (for testing)
    if config:
        app.config.update(config)

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, app.config['LOG_LEVEL']),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Build the API key store for authentication and scope enforcement.
    # Precedence: an injected KeyStore (API_KEY_STORE), then a list of key
    # records (API_KEYS), then a single key (API_KEY, all scopes), then
    # environment loading. Tests may run without any key (unprotected).
    key_store = app.config.get('API_KEY_STORE')
    if key_store is None:
        api_keys = app.config.get('API_KEYS')
        api_key = app.config.get('API_KEY')
        if api_keys:
            key_store = KeyStore.from_records(api_keys)
        elif api_key:
            key_store = KeyStore.from_single(api_key)
        elif not app.config.get('TESTING'):
            key_store = KeyStore.load()

    if key_store is None and not app.config.get('TESTING'):
        logger.error("No API key configured. Set LOTL_API_KEY env var or run: python -m api.auth generate")
        logger.error("Server starting without authentication. All endpoints are unprotected.")
    if key_store is not None:
        logger.info(f"Authentication enabled with {len(key_store)} key(s): {key_store.labels}")
    app.config['API_KEY_STORE'] = key_store

    # Configure CORS with restricted origins
    cors_origins = app.config.get('CORS_ORIGINS', [])
    if cors_origins:
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
    else:
        logger.info("CORS disabled. No origins allowed.")

    # Initialize components
    initialize_components(app)

    # Register routes
    register_routes(app, key_store)

    # Request logging (do not log command lines or request bodies)
    @app.before_request
    def log_request():
        logger.info(f"{request.method} {request.path} - {request.remote_addr}")

    # Error handlers
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({'error': 'Bad request', 'message': str(e)}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Not found', 'message': str(e)}), 404

    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f"Internal error: {e}")
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

    return app


def initialize_components(app):
    """Initialize database, rules, and collectors"""
    global db, rule_loader, engine, correlator, collectors

    # Initialize database with WAL mode for concurrent access
    db = AlertDatabase(app.config['DATABASE_PATH'])
    # Enable WAL mode for better concurrent read/write support
    try:
        db.connection.execute("PRAGMA journal_mode=WAL")
        db.connection.execute("PRAGMA busy_timeout=5000")
        logger.info("Database WAL mode enabled with 5s busy timeout")
    except Exception as e:
        logger.warning(f"Could not enable WAL mode: {e}")
    logger.info(f"Database initialized: {app.config['DATABASE_PATH']}")

    # Load detection rules
    rule_loader = RuleLoader()
    rules = rule_loader.load_rules_directory(app.config['RULES_DIR'])
    logger.info(f"Loaded {len(rules)} detection rules")

    # Initialize detection engine
    engine = DetectionEngine(rules)

    # Load chain rules and initialize the correlation layer
    from core.correlator import ChainRuleLoader, Correlator
    from pathlib import Path as _Path
    chains_dir = str(_Path(app.config['RULES_DIR']) / 'correlation')
    try:
        chain_loader = ChainRuleLoader()
        chains = chain_loader.load_chains_directory(chains_dir)
    except Exception as e:
        logger.warning(f"Chain rules unavailable, correlation disabled: {e}")
        chains = []
    correlator = Correlator(chains)
    logger.info(f"Loaded {len(chains)} chain rules")

    # Initialize collectors
    collectors['windows'] = WindowsCollector()
    collectors['linux'] = LinuxCollector()
    collectors['macos'] = MacOSCollector()
    logger.info("Collectors initialized")


def register_routes(app, key_store=None):
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
            # Parse query parameters
            start_time = request.args.get('start_time')
            end_time = request.args.get('end_time')
            severity = request.args.get('severity')
            platform = request.args.get('platform')
            min_score = request.args.get('min_score', type=int)
            limit = request.args.get('limit', type=int, default=100)

            # Convert datetime strings
            if start_time:
                start_time = datetime.fromisoformat(start_time)
            if end_time:
                end_time = datetime.fromisoformat(end_time)

            # Query database based on filters
            if severity:
                alerts = db.get_alerts_by_severity(severity)
            elif platform:
                alerts = db.get_alerts_by_platform(platform)
            elif min_score is not None:
                alerts = db.get_high_score_alerts(min_score)
            else:
                alerts = db.get_alerts(start_time=start_time, end_time=end_time, limit=limit)

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
            from core.export import format_records

            kind = request.args.get('kind', 'alerts')
            fmt = request.args.get('format', 'json')
            if fmt.lower() not in ('cef', 'json'):
                return jsonify({'error': "format must be 'cef' or 'json'"}), 400
            severity = request.args.get('severity')
            platform = request.args.get('platform')
            min_score = request.args.get('min_score', type=int)
            limit = request.args.get('limit', type=int, default=1000)

            if kind == 'incidents':
                records = db.get_incidents(
                    severity=severity, platform=platform,
                    min_score=min_score, limit=limit,
                )
            else:
                records = db.get_alerts(limit=limit)
                if severity:
                    records = [r for r in records if r.get('severity') == severity]
                if platform:
                    records = [r for r in records if r.get('platform') == platform]
                if min_score is not None:
                    records = [r for r in records if r.get('score', 0) >= min_score]

            lines = format_records(records, fmt)
            body = "\n".join(lines) + ("\n" if lines else "")
            return app.response_class(body, mimetype='text/plain')

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
            rules_data = []
            for rule in engine.rules:
                rules_data.append(rule.to_dict())

            # Calculate statistics
            stats = {
                'total': len(rules_data),
                'by_platform': {},
                'by_severity': {}
            }

            for rule in engine.rules:
                # Count by platform
                stats['by_platform'][rule.platform] = stats['by_platform'].get(rule.platform, 0) + 1
                # Count by severity
                stats['by_severity'][rule.severity] = stats['by_severity'].get(rule.severity, 0) + 1

            return jsonify({
                'count': len(rules_data),
                'rules': rules_data,
                'stats': stats
            })

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
            data = request.get_json()

            # Validate input
            if not data:
                return jsonify({'error': 'Request body is required'}), 400

            platform = data.get('platform')
            log_path = data.get('log_path')

            if not platform or not log_path:
                return jsonify({'error': 'platform and log_path are required'}), 400

            if platform not in ['windows', 'linux', 'macos']:
                return jsonify({'error': 'platform must be "windows", "linux", or "macos"'}), 400

            # Validate log source for path traversal and safety
            from core.source_validator import validate_log_source, SourceValidationError
            allowed_roots = app.config.get('ALLOWED_LOG_ROOTS', [])
            max_size_mb = app.config.get('MAX_FILE_SIZE_MB', 100)
            max_size_bytes = max_size_mb * 1024 * 1024 if max_size_mb else 100 * 1024 * 1024
            try:
                validated_path = validate_log_source(
                    log_path, platform,
                    allowed_roots=allowed_roots,
                    max_file_size=max_size_bytes,
                )
            except SourceValidationError as e:
                return jsonify({'error': f'Invalid log source: {e}'}), 400

            # Get appropriate collector
            collector = collectors.get(platform)
            if not collector:
                return jsonify({'error': f'No collector available for platform: {platform}'}), 400

            # Collect events from validated path
            logger.info(f"Scanning {platform} logs at {validated_path}")
            events = collector.collect_events(validated_path)
            logger.info(f"Collected {len(events)} events")

            # Run detection
            alerts = engine.match_events(events)
            logger.info(f"Generated {len(alerts)} alerts")

            # Save alerts to database with deduplication
            results = []
            for alert in alerts:
                result = db.save_alert_dedup(alert)
                results.append(result)

            new_count = sum(1 for r in results if not r["is_duplicate"] and not r.get("is_suppressed"))
            dup_count = sum(1 for r in results if r["is_duplicate"])
            supp_count = sum(1 for r in results if r.get("is_suppressed"))

            # Run lineage correlation across the full event batch
            incidents = correlator.correlate(events) if correlator else []
            incident_results = []
            for incident in incidents:
                saved = db.save_incident(incident)
                incident_results.append({
                    **saved,
                    'chain_id': incident.chain_id,
                    'score': incident.score,
                    'risk_band': incident.risk_band,
                })
            new_incidents = sum(
                1 for r in incident_results if not r["is_duplicate"]
            )
            logger.info(f"Correlated {new_incidents} new incidents")

            return jsonify({
                'events_processed': len(events),
                'alerts_generated': new_count,
                'duplicates_updated': dup_count,
                'suppressed': supp_count,
                'incidents_generated': new_incidents,
                'incident_results': incident_results,
                'results': results
            })

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
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body is required'}), 400

            platform = data.get('platform')
            log_path = data.get('log_path')
            batch_size = data.get('batch_size', 500)

            if not platform or not log_path:
                return jsonify({'error': 'platform and log_path are required'}), 400
            if platform not in ('linux', 'windows', 'macos'):
                return jsonify({
                    'error': 'incremental ingestion supports "linux", "windows", or "macos"'
                }), 400

            from core.source_validator import validate_log_source, SourceValidationError
            allowed_roots = app.config.get('ALLOWED_LOG_ROOTS', [])
            max_size_mb = app.config.get('MAX_FILE_SIZE_MB', 100)
            max_size_bytes = max_size_mb * 1024 * 1024 if max_size_mb else 100 * 1024 * 1024
            try:
                validated_path = validate_log_source(
                    log_path, platform,
                    allowed_roots=allowed_roots,
                    max_file_size=max_size_bytes,
                )
            except SourceValidationError as e:
                return jsonify({'error': f'Invalid log source: {e}'}), 400

            from core.ingest import (
                IngestionService, linux_auditd_parser, windows_sysmon_parser,
                macos_eslogger_parser,
            )
            if platform == 'linux':
                parser = linux_auditd_parser(collectors['linux'])
            elif platform == 'windows':
                parser = windows_sysmon_parser(collectors['windows'])
            else:
                parser = macos_eslogger_parser(collectors['macos'])
            service = IngestionService(
                db, engine, parser, correlator=correlator, batch_size=batch_size
            )
            summary = service.ingest_file(validated_path)
            return jsonify(summary)

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
