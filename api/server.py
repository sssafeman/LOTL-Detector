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
from api.auth import load_api_key, require_auth
import logging

logger = logging.getLogger(__name__)

# Global instances
db = None
rule_loader = None
engine = None
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

    # Load API key for authentication
    # Test config can inject API_KEY directly. Otherwise load from env/file.
    api_key = app.config.get('API_KEY')
    if not api_key and not app.config.get('TESTING'):
        api_key = load_api_key()

    if not api_key and not app.config.get('TESTING'):
        logger.error("No API key configured. Set LOTL_API_KEY env var or run: python -m api.auth generate")
        logger.error("Server starting without authentication. All endpoints are unprotected.")
        app.config['API_KEY'] = None
    else:
        app.config['API_KEY'] = api_key

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
    register_routes(app, api_key)

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
    global db, rule_loader, engine, collectors

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

    # Initialize collectors
    collectors['windows'] = WindowsCollector()
    collectors['linux'] = LinuxCollector()
    logger.info("Collectors initialized")


def register_routes(app, api_key=None):
    """Register all API routes with authentication"""

    # Health check is the only unauthenticated endpoint
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Public health check endpoint. Returns minimal info."""
        return jsonify({'status': 'ok'})

    # If no API key is configured (non-test), skip auth on all endpoints
    # for backward compatibility during transition. In production, always set a key.
    use_auth = api_key is not None

    def auth_decorator():
        """Return auth decorator if key is set, else passthrough."""
        if use_auth:
            return require_auth(api_key)
        # No-op decorator when auth is disabled
        def passthrough(f):
            return f
        return passthrough

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
    @auth_decorator()
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

            if platform not in ['windows', 'linux']:
                return jsonify({'error': 'platform must be "windows" or "linux"'}), 400

            # Check if path exists
            if not Path(log_path).exists():
                return jsonify({'error': f'Log path does not exist: {log_path}'}), 400

            # Get appropriate collector
            collector = collectors.get(platform)
            if not collector:
                return jsonify({'error': f'No collector available for platform: {platform}'}), 400

            # Collect events
            logger.info(f"Scanning {platform} logs at {log_path}")
            events = collector.collect_events(log_path)
            logger.info(f"Collected {len(events)} events")

            # Run detection
            alerts = engine.match_events(events)
            logger.info(f"Generated {len(alerts)} alerts")

            # Save alerts to database
            alert_ids = []
            for alert in alerts:
                alert_id = db.save_alert(alert)
                alert_ids.append(alert_id)

            return jsonify({
                'events_processed': len(events),
                'alerts_generated': len(alerts),
                'alert_ids': alert_ids
            })

        except ValueError as e:
            return jsonify({'error': 'Invalid request', 'message': str(e)}), 400
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return jsonify({'error': 'Scan failed', 'message': str(e)}), 500

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
