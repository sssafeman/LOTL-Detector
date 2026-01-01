"""
Database module for persistent alert storage
"""
import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
from core.engine import Alert
import logging

logger = logging.getLogger(__name__)


# Register datetime adapters/converters for SQLite
def _adapt_datetime(dt):
    """Convert datetime to ISO format string for SQLite"""
    return dt.isoformat()


def _convert_datetime(s):
    """Convert ISO format string from SQLite to datetime"""
    return datetime.fromisoformat(s.decode('utf-8'))


sqlite3.register_adapter(datetime, _adapt_datetime)
sqlite3.register_converter("DATETIME", _convert_datetime)


class AlertDatabase:
    """
    SQLite database for storing and querying detection alerts
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database connection and create schema if needed

        Args:
            db_path: Path to SQLite database file (default: from config)
        """
        # Use config if db_path not provided
        if db_path is None:
            try:
                from core.config import get_database_path
                db_path = get_database_path()
            except Exception:
                # Fallback to default if config fails
                db_path = "alerts.db"

        self.db_path = Path(db_path)
        self.connection = None
        self._connect()
        self._create_schema()
        logger.info(f"AlertDatabase initialized at {self.db_path}")

    def _connect(self):
        """Establish database connection"""
        self.connection = sqlite3.connect(
            str(self.db_path),
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            check_same_thread=False  # Allow multi-threaded access for Flask
        )
        self.connection.row_factory = sqlite3.Row
        logger.debug(f"Connected to database: {self.db_path}")

    def _create_schema(self):
        """Create database tables and indexes if they don't exist"""
        cursor = self.connection.cursor()

        # Create alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                platform TEXT NOT NULL,
                process_name TEXT NOT NULL,
                command_line TEXT NOT NULL,
                user TEXT NOT NULL,
                parent_process_name TEXT,
                timestamp DATETIME NOT NULL,
                mitre_attack TEXT,
                description TEXT,
                response TEXT,
                event_data TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for efficient queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_score ON alerts(score)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_platform ON alerts(platform)
        """)

        self.connection.commit()
        logger.debug("Database schema created/verified")

    def save_alert(self, alert: Alert) -> int:
        """
        Store an alert in the database

        Args:
            alert: Alert object to store

        Returns:
            Integer ID of the inserted alert
        """
        cursor = self.connection.cursor()

        # Convert MITRE and response lists to JSON
        mitre_json = json.dumps(alert.mitre_attack) if alert.mitre_attack else '[]'
        response_json = json.dumps(alert.response) if alert.response else '[]'
        event_json = json.dumps(alert.event.to_dict())

        cursor.execute("""
            INSERT INTO alerts (
                rule_id, rule_name, severity, score, platform,
                process_name, command_line, user, parent_process_name,
                timestamp, mitre_attack, description, response, event_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.rule_id,
            alert.rule_name,
            alert.severity,
            alert.score,
            alert.event.platform,
            alert.event.process_name,
            alert.event.command_line,
            alert.event.user,
            alert.event.parent_process_name,
            alert.timestamp,
            mitre_json,
            alert.description,
            response_json,
            event_json
        ))

        self.connection.commit()
        alert_id = cursor.lastrowid

        logger.info(f"Alert saved to database: ID={alert_id}, rule={alert.rule_id}, score={alert.score}")
        return alert_id

    def get_alerts(self, start_time: datetime = None, end_time: datetime = None,
                   limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query alerts with optional time filtering

        Args:
            start_time: Include alerts after this time
            end_time: Include alerts before this time
            limit: Maximum number of alerts to return

        Returns:
            List of alert dictionaries
        """
        cursor = self.connection.cursor()
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        alerts = []
        for row in rows:
            alert_dict = dict(row)
            # Parse JSON fields
            alert_dict['mitre_attack'] = json.loads(alert_dict['mitre_attack']) if alert_dict['mitre_attack'] else []
            alert_dict['response'] = json.loads(alert_dict['response']) if alert_dict['response'] else []
            alert_dict['event_data'] = json.loads(alert_dict['event_data']) if alert_dict['event_data'] else {}
            alerts.append(alert_dict)

        logger.debug(f"Retrieved {len(alerts)} alerts from database")
        return alerts

    def get_alerts_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Get all alerts of a specific severity level

        Args:
            severity: Severity level (critical, high, medium, low)

        Returns:
            List of alert dictionaries
        """
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT * FROM alerts
            WHERE severity = ?
            ORDER BY timestamp DESC
        """, (severity,))

        rows = cursor.fetchall()
        alerts = []
        for row in rows:
            alert_dict = dict(row)
            alert_dict['mitre_attack'] = json.loads(alert_dict['mitre_attack']) if alert_dict['mitre_attack'] else []
            alert_dict['response'] = json.loads(alert_dict['response']) if alert_dict['response'] else []
            alert_dict['event_data'] = json.loads(alert_dict['event_data']) if alert_dict['event_data'] else {}
            alerts.append(alert_dict)

        logger.debug(f"Retrieved {len(alerts)} alerts with severity={severity}")
        return alerts

    def get_alerts_by_platform(self, platform: str) -> List[Dict[str, Any]]:
        """
        Get all alerts for a specific platform

        Args:
            platform: Platform name (windows, linux, macos)

        Returns:
            List of alert dictionaries
        """
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT * FROM alerts
            WHERE platform = ?
            ORDER BY timestamp DESC
        """, (platform,))

        rows = cursor.fetchall()
        alerts = []
        for row in rows:
            alert_dict = dict(row)
            alert_dict['mitre_attack'] = json.loads(alert_dict['mitre_attack']) if alert_dict['mitre_attack'] else []
            alert_dict['response'] = json.loads(alert_dict['response']) if alert_dict['response'] else []
            alert_dict['event_data'] = json.loads(alert_dict['event_data']) if alert_dict['event_data'] else {}
            alerts.append(alert_dict)

        logger.debug(f"Retrieved {len(alerts)} alerts for platform={platform}")
        return alerts

    def get_high_score_alerts(self, min_score: int) -> List[Dict[str, Any]]:
        """
        Get alerts with scores above a threshold

        Args:
            min_score: Minimum score threshold

        Returns:
            List of alert dictionaries
        """
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT * FROM alerts
            WHERE score >= ?
            ORDER BY score DESC, timestamp DESC
        """, (min_score,))

        rows = cursor.fetchall()
        alerts = []
        for row in rows:
            alert_dict = dict(row)
            alert_dict['mitre_attack'] = json.loads(alert_dict['mitre_attack']) if alert_dict['mitre_attack'] else []
            alert_dict['response'] = json.loads(alert_dict['response']) if alert_dict['response'] else []
            alert_dict['event_data'] = json.loads(alert_dict['event_data']) if alert_dict['event_data'] else {}
            alerts.append(alert_dict)

        logger.debug(f"Retrieved {len(alerts)} alerts with score >= {min_score}")
        return alerts

    def get_stats(self) -> Dict[str, Any]:
        """
        Get database statistics

        Returns:
            Dictionary with statistics:
            - total_alerts: Total number of alerts
            - by_severity: Count by severity level
            - by_platform: Count by platform
            - score_distribution: Count by score range
            - alerts_last_24h: Count in last 24 hours
        """
        cursor = self.connection.cursor()

        # Total alerts
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]

        # By severity
        cursor.execute("""
            SELECT severity, COUNT(*)
            FROM alerts
            GROUP BY severity
        """)
        by_severity = {row[0]: row[1] for row in cursor.fetchall()}

        # By platform
        cursor.execute("""
            SELECT platform, COUNT(*)
            FROM alerts
            GROUP BY platform
        """)
        by_platform = {row[0]: row[1] for row in cursor.fetchall()}

        # Score distribution
        cursor.execute("""
            SELECT
                SUM(CASE WHEN score BETWEEN 0 AND 50 THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN score BETWEEN 51 AND 100 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN score BETWEEN 101 AND 150 THEN 1 ELSE 0 END) as high
            FROM alerts
        """)
        score_row = cursor.fetchone()
        score_distribution = {
            '0-50': score_row[0] or 0,
            '51-100': score_row[1] or 0,
            '101-150': score_row[2] or 0
        }

        # Alerts in last 24 hours
        twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
        cursor.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE timestamp >= ?
        """, (twenty_four_hours_ago,))
        alerts_last_24h = cursor.fetchone()[0]

        stats = {
            'total_alerts': total_alerts,
            'by_severity': by_severity,
            'by_platform': by_platform,
            'score_distribution': score_distribution,
            'alerts_last_24h': alerts_last_24h
        }

        logger.debug(f"Database stats: {total_alerts} total alerts")
        return stats

    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        return False
