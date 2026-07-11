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

        # Migration: add dedup and lifecycle columns if they don't exist
        self._migrate_schema(cursor)

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
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_fingerprint ON alerts(fingerprint)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_state ON alerts(state)
        """)

        # Create suppressions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS suppressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                fingerprint_version INTEGER NOT NULL DEFAULT 1,
                scope TEXT NOT NULL
                    CHECK (scope IN ('global', 'host')),
                scope_value TEXT,
                author TEXT NOT NULL,
                reason TEXT NOT NULL,
                starts_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
                    CHECK (active IN (0, 1)),
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                revoked_at DATETIME,
                revoked_by TEXT,
                revoke_reason TEXT,
                CHECK (
                    (scope = 'global' AND scope_value IS NULL)
                    OR
                    (scope = 'host' AND scope_value IS NOT NULL)
                ),
                CHECK (expires_at > starts_at)
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_supp_fingerprint ON suppressions(fingerprint)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_supp_active ON suppressions(active)
        """)

        # Create audit trail table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                previous_state TEXT,
                new_state TEXT,
                author TEXT NOT NULL,
                reason TEXT,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_alert ON alert_audit(alert_id)
        """)

        self.connection.commit()
        logger.debug("Database schema created/verified")

    def _migrate_schema(self, cursor):
        """Add new columns to existing alerts table if they don't exist."""
        # Check existing columns
        cursor.execute("PRAGMA table_info(alerts)")
        existing_cols = {row[1] for row in cursor.fetchall()}

        new_columns = [
            ("host", "TEXT DEFAULT ''"),
            ("fingerprint", "TEXT"),
            ("activity_fingerprint", "TEXT"),
            ("fingerprint_version", "INTEGER DEFAULT 1"),
            ("occurrence_count", "INTEGER DEFAULT 1"),
            ("first_seen", "DATETIME"),
            ("last_seen", "DATETIME"),
            ("state", "TEXT DEFAULT 'new'"),
            ("last_event_data", "TEXT"),
            ("updated_at", "DATETIME DEFAULT CURRENT_TIMESTAMP"),
        ]

        for col_name, col_def in new_columns:
            if col_name not in existing_cols:
                try:
                    cursor.execute(
                        f"ALTER TABLE alerts ADD COLUMN {col_name} {col_def}"
                    )
                    logger.info(f"Added column {col_name} to alerts table")
                except Exception as e:
                    logger.warning(f"Could not add column {col_name}: {e}")

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

    def save_alert_dedup(
        self, alert: Alert, dedup_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Store an alert with deduplication. If an open alert with the same
        fingerprint exists within the dedup window, increment its occurrence
        count instead of creating a new row.

        Args:
            alert: Alert object to store
            dedup_window_hours: Dedup window in hours (default 24)

        Returns:
            Dict with: alert_id, is_duplicate (bool), occurrence_count
        """
        from core.fingerprint import compute_fingerprint
        from datetime import timedelta

        fps = compute_fingerprint(alert)
        fingerprint = fps["fingerprint"]
        activity_fp = fps["activity_fingerprint"]
        host = fps["host"]

        # Check if suppressed
        if self._is_suppressed(fingerprint, activity_fp, host):
            logger.info(f"Alert suppressed: {alert.rule_id} (fingerprint matched active suppression)")
            return {"alert_id": None, "is_duplicate": False, "is_suppressed": True, "occurrence_count": 0}

        mitre_json = json.dumps(alert.mitre_attack) if alert.mitre_attack else '[]'
        response_json = json.dumps(alert.response) if alert.response else '[]'
        event_json = json.dumps(alert.event.to_dict())

        cursor = self.connection.cursor()
        window = timedelta(hours=dedup_window_hours)
        incoming_ts = alert.timestamp

        # Find existing open episode within the dedup window
        cursor.execute("""
            SELECT id, occurrence_count, first_seen, last_seen, state
            FROM alerts
            WHERE fingerprint = ?
              AND state IN ('new', 'acknowledged', 'investigating')
              AND last_seen >= ?
              AND first_seen <= ?
            ORDER BY last_seen DESC
            LIMIT 1
        """, (
            fingerprint,
            incoming_ts - window,
            incoming_ts + window,
        ))

        existing = cursor.fetchone()

        if existing:
            # Duplicate: update existing episode
            alert_id = existing[0]
            current_count = existing[1]
            cursor.execute("""
                UPDATE alerts
                SET occurrence_count = occurrence_count + 1,
                    first_seen = MIN(first_seen, ?),
                    last_seen = MAX(last_seen, ?),
                    timestamp = MAX(timestamp, ?),
                    score = MAX(score, ?),
                    updated_at = CURRENT_TIMESTAMP,
                    last_event_data = ?
                WHERE id = ?
            """, (
                incoming_ts, incoming_ts, incoming_ts,
                alert.score, event_json, alert_id,
            ))
            self.connection.commit()
            new_count = current_count + 1
            logger.info(f"Alert deduplicated: ID={alert_id}, rule={alert.rule_id}, occurrences={new_count}")
            return {
                "alert_id": alert_id,
                "is_duplicate": True,
                "is_suppressed": False,
                "occurrence_count": new_count,
            }
        else:
            # New episode: insert
            cursor.execute("""
                INSERT INTO alerts (
                    rule_id, rule_name, severity, score, platform,
                    process_name, command_line, user, parent_process_name,
                    timestamp, mitre_attack, description, response, event_data,
                    host, fingerprint, activity_fingerprint, fingerprint_version,
                    occurrence_count, first_seen, last_seen, state, last_event_data,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (
                alert.rule_id, alert.rule_name, alert.severity, alert.score,
                alert.event.platform, alert.event.process_name,
                alert.event.command_line, alert.event.user,
                alert.event.parent_process_name, alert.timestamp,
                mitre_json, alert.description, response_json, event_json,
                host, fingerprint, activity_fp, 1,
                1, incoming_ts, incoming_ts, event_json,
            ))
            self.connection.commit()
            alert_id = cursor.lastrowid
            logger.info(f"New alert episode saved: ID={alert_id}, rule={alert.rule_id}, score={alert.score}")
            return {
                "alert_id": alert_id,
                "is_duplicate": False,
                "is_suppressed": False,
                "occurrence_count": 1,
            }

    def _is_suppressed(
        self, fingerprint: str, activity_fingerprint: str, host: str
    ) -> bool:
        """Check if a fingerprint is actively suppressed."""
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT id FROM suppressions
            WHERE active = 1
              AND starts_at <= CURRENT_TIMESTAMP
              AND expires_at > CURRENT_TIMESTAMP
              AND (
                  (scope = 'global' AND fingerprint = ?)
                  OR
                  (scope = 'host' AND fingerprint = ? AND scope_value = ?)
              )
        """, (activity_fingerprint, fingerprint, host))
        return cursor.fetchone() is not None

    def add_suppression(
        self, fingerprint: str, scope: str, scope_value: str,
        author: str, reason: str, duration_hours: int,
        fingerprint_version: int = 1,
    ) -> int:
        """
        Create a new suppression.

        Args:
            fingerprint: The fingerprint to suppress
            scope: 'global' or 'host'
            scope_value: Host name if scope is 'host', None if 'global'
            author: Who created the suppression
            reason: Why it was created
            duration_hours: How long the suppression lasts
            fingerprint_version: Fingerprint version (default 1)

        Returns:
            Suppression ID
        """
        from datetime import datetime, timedelta, timezone
        expires = datetime.now(timezone.utc) + timedelta(hours=duration_hours)
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT INTO suppressions (
                fingerprint, fingerprint_version, scope, scope_value,
                author, reason, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (fingerprint, fingerprint_version, scope, scope_value, author, reason, expires))
        self.connection.commit()
        sid = cursor.lastrowid
        logger.info(f"Suppression created: ID={sid}, scope={scope}, duration={duration_hours}h")
        return sid

    def update_alert_state(
        self, alert_id: int, new_state: str, author: str, reason: str = ""
    ) -> bool:
        """
        Update an alert's lifecycle state and record an audit trail entry.

        Args:
            alert_id: Alert ID to update
            new_state: One of 'new', 'acknowledged', 'investigating', 'resolved', 'false_positive'
            author: Who made the change
            reason: Optional reason for the change

        Returns:
            True if updated, False if alert not found
        """
        valid_states = {"new", "acknowledged", "investigating", "resolved", "false_positive"}
        if new_state not in valid_states:
            raise ValueError(f"Invalid state: {new_state}. Valid: {sorted(valid_states)}")

        cursor = self.connection.cursor()
        # Get current state
        cursor.execute("SELECT state FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        if not row:
            return False
        previous_state = row[0]

        # Update state
        cursor.execute(
            "UPDATE alerts SET state = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (new_state, alert_id),
        )

        # Record audit trail
        cursor.execute("""
            INSERT INTO alert_audit (alert_id, action, previous_state, new_state, author, reason)
            VALUES (?, 'state_change', ?, ?, ?, ?)
        """, (alert_id, previous_state, new_state, author, reason))

        self.connection.commit()
        logger.info(f"Alert {alert_id} state changed: {previous_state} -> {new_state} by {author}")
        return True

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
