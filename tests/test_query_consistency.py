"""
Query consistency tests (finding E13).

The alerts endpoint applied only the first matching filter (severity or
platform or min_score) and dropped the others, time bounds, and limits;
export fetched the newest N records and filtered them afterwards; the
alert ID lookup scanned a bounded recent window. These tests pin one
consistent semantics: all supplied filters intersect, limits apply
after filtering, invalid parameters are client errors, and ID lookup is
a direct primary-key read.
"""
import json
import os
import tempfile
from datetime import datetime

import pytest

from collectors.base import Event
from core.database import AlertDatabase
from core.engine import Alert
from api.server import create_app

RULES_DIR = "rules"


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as handle:
        db_path = handle.name
    yield db_path
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def app(temp_db):
    return create_app({
        "DATABASE_PATH": temp_db,
        "RULES_DIR": RULES_DIR,
        "TESTING": True,
        "LOG_LEVEL": "ERROR",
    })


@pytest.fixture
def client(app):
    return app.test_client()


def _seed(db_path, specs):
    """Insert alerts described by (rule_id, severity, platform, score, ts)."""
    db = AlertDatabase(db_path)
    for rule_id, severity, platform, score, ts in specs:
        event = Event(
            timestamp=ts,
            platform=platform,
            process_name="p.exe",
            command_line=f"cmd {rule_id}",
            user="u",
            process_id=1,
        )
        db.save_alert(Alert(
            rule_id=rule_id,
            rule_name=f"Rule {rule_id}",
            severity=severity,
            event=event,
            timestamp=ts,
            mitre_attack=[],
            description="d",
            response=[],
            score=score,
        ))
    db.close()


MIXED = [
    # rule_id, severity, platform, score, timestamp
    ("WIN-201", "high", "windows", 95, datetime(2026, 6, 1, 10, 0, 0)),
    ("LNX-201", "high", "linux", 95, datetime(2026, 6, 1, 11, 0, 0)),
    ("WIN-202", "low", "windows", 10, datetime(2026, 6, 1, 12, 0, 0)),
    ("WIN-203", "critical", "windows", 130, datetime(2026, 6, 1, 13, 0, 0)),
]


def test_filters_intersect_on_alerts_endpoint(client, temp_db):
    _seed(temp_db, MIXED)
    response = client.get(
        "/api/alerts?severity=high&platform=windows&min_score=90"
    )
    assert response.status_code == 200
    alerts = response.get_json()["alerts"]
    assert [a["rule_id"] for a in alerts] == ["WIN-201"]


def test_time_bounds_combine_with_filters(client, temp_db):
    _seed(temp_db, [
        ("WIN-301", "low", "windows", 5, datetime(2026, 1, 1, 10, 0, 0)),
        ("WIN-302", "low", "windows", 6, datetime(2026, 6, 1, 10, 0, 0)),
    ])
    response = client.get("/api/alerts?severity=low&start_time=2026-05-01T00:00:00")
    assert response.status_code == 200
    alerts = response.get_json()["alerts"]
    assert [a["rule_id"] for a in alerts] == ["WIN-302"]


def test_limit_applies_after_filtering(client, temp_db):
    _seed(temp_db, [
        ("WIN-401", "high", "windows", 95, datetime(2026, 3, 1, 10, 0, 0)),
        ("WIN-402", "high", "windows", 96, datetime(2026, 3, 2, 10, 0, 0)),
        ("WIN-403", "high", "windows", 97, datetime(2026, 3, 3, 10, 0, 0)),
    ])
    response = client.get("/api/alerts?severity=high&limit=1")
    assert response.status_code == 200
    alerts = response.get_json()["alerts"]
    assert [a["rule_id"] for a in alerts] == ["WIN-403"]


@pytest.mark.parametrize("query", [
    "min_score=abc",
    "limit=abc",
    "limit=0",
    "limit=20001",
    "severity=banana",
    "platform=solaris",
])
def test_invalid_alert_query_parameters_are_client_errors(client, query):
    response = client.get(f"/api/alerts?{query}")
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_export_filters_before_applying_limit(client, temp_db):
    _seed(temp_db, [
        ("WIN-501", "low", "windows", 5, datetime(2026, 1, 1, 10, 0, 0)),
        ("WIN-502", "high", "windows", 95, datetime(2026, 6, 1, 10, 0, 0)),
        ("WIN-503", "high", "windows", 96, datetime(2026, 6, 2, 10, 0, 0)),
        ("WIN-504", "high", "windows", 97, datetime(2026, 6, 3, 10, 0, 0)),
    ])
    response = client.get("/api/export?kind=alerts&severity=low&limit=2")
    assert response.status_code == 200
    lines = [
        json.loads(line)
        for line in response.get_data(as_text=True).strip().splitlines()
    ]
    assert [line["rule"]["id"] for line in lines] == ["WIN-501"]


def test_export_and_alerts_endpoints_agree_on_filters(client, temp_db):
    _seed(temp_db, MIXED)

    alerts = client.get(
        "/api/alerts?severity=high&platform=windows&min_score=90"
    ).get_json()["alerts"]
    exported = client.get(
        "/api/export?kind=alerts&severity=high&platform=windows&min_score=90"
    )
    lines = [
        json.loads(line)
        for line in exported.get_data(as_text=True).strip().splitlines()
    ]
    assert [a["rule_id"] for a in alerts] == [line["rule"]["id"] for line in lines]


def test_export_rejects_unknown_kind(client):
    response = client.get("/api/export?kind=widgets")
    assert response.status_code == 400
    assert "error" in response.get_json()


@pytest.mark.parametrize("query", ["limit=0", "limit=abc", "limit=20001"])
def test_export_limit_validation(client, query):
    response = client.get(f"/api/export?{query}")
    assert response.status_code == 400


@pytest.mark.parametrize("query", ["limit=0", "min_score=abc"])
def test_incident_query_validation(client, query):
    response = client.get(f"/api/incidents?{query}")
    assert response.status_code == 400


def test_find_alert_is_a_direct_primary_key_read(client, temp_db, monkeypatch):
    """The ID lookup must not scan a bounded recent window."""
    _seed(temp_db, [
        ("WIN-601", "high", "windows", 95, datetime(2026, 6, 1, 10, 0, 0)),
    ])
    alert_id = client.get("/api/alerts").get_json()["alerts"][0]["id"]

    import core.database as database_module

    def forbidden_scan(*args, **kwargs):
        raise AssertionError("find_alert must not scan the alerts list")

    monkeypatch.setattr(
        database_module.AlertDatabase, "get_alerts", forbidden_scan
    )

    response = client.get(f"/api/alerts/{alert_id}")
    assert response.status_code == 200
    assert response.get_json()["rule_id"] == "WIN-601"


def test_get_alert_by_id_direct_lookup(temp_db):
    db = AlertDatabase(temp_db)
    try:
        alert_id = db.save_alert(_one_alert())
        found = db.get_alert_by_id(alert_id)
        assert found is not None
        assert found["id"] == alert_id
        assert db.get_alert_by_id(999999) is None
    finally:
        db.close()


def _one_alert():
    event = Event(
        timestamp=datetime(2026, 6, 1, 10, 0, 0),
        platform="windows",
        process_name="p.exe",
        command_line="cmd",
        user="u",
        process_id=1,
    )
    return Alert(
        rule_id="WIN-602",
        rule_name="R",
        severity="high",
        event=event,
        timestamp=event.timestamp,
        mitre_attack=[],
        description="d",
        response=[],
        score=90,
    )
