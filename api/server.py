"""
REST API server for LOTL Detection Framework
"""
import os
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, request
from flask_cors import CORS
from core.database import AlertDatabase
from core.rule_loader import RuleLoader
from core.engine import DetectionEngine
from core.config import get_config, get_database_path, get_rules_directory, get_logging_config
from collectors.windows.collector import WindowsCollector
from collectors.linux.collector import LinuxCollector
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
        config: Optional configuration dictionary

    Returns:
        Flask app instance
    """
    app = Flask(__name__)
    CORS(app)  # Enable CORS for all routes

    # Load configuration from config system
    try:
        app_config = get_config()
        logging_config = get_logging_config()

        # Set configuration from config system
        app.config['DATABASE_PATH'] = get_database_path()
        app.config['RULES_DIR'] = get_rules_directory()
        app.config['LOG_LEVEL'] = logging_config['level']
    except Exception as e:
        logger.warning(f"Failed to load config, using defaults: {e}")
        # Fallback to defaults
        app.config['DATABASE_PATH'] = 'alerts.db'
        app.config['RULES_DIR'] = 'rules'
        app.config['LOG_LEVEL'] = 'INFO'

    # Override with provided config (for testing)
    if config:
        app.config.update(config)

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, app.config['LOG_LEVEL']),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize components
    initialize_components(app)

    # Register routes
    register_routes(app)

    # Request logging
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

    # Initialize database
    db = AlertDatabase(app.config['DATABASE_PATH'])
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


def register_routes(app):
    """Register all API routes"""

    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        try:
            stats = db.get_stats()
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'rules_loaded': len(engine.rules),
                'total_alerts': stats['total_alerts']
            })
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({
                'status': 'unhealthy',
                'error': str(e)
            }), 500

    @app.route('/api/alerts', methods=['GET'])
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
    app.run(debug=True, host='0.0.0.0', port=5000)
