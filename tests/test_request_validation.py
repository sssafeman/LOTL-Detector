"""
Client request validation tests (finding E14).

Malformed client input (bad JSON, wrong content type, wrong types) must
produce stable 4xx client errors, never 500s, and 500 responses must not
leak internal exception text.
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
LINUX_FIXTURE = "tests/fixtures/linux"


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


@pytest.fixture
def seeded_alert_id(temp_db):
    db = AlertDatabase(temp_db)
    event = Event(
        timestamp=datetime(2026, 6, 1, 10, 0, 0),
        platform="windows",
        process_name="p.exe",
        command_line="c",
        user="u",
        process_id=1,
    )
    alert_id = db.save_alert(Alert(
        rule_id="WIN-701",
        rule_name="R",
        severity="high",
        event=event,
        timestamp=event.timestamp,
        mitre_attack=[],
        description="d",
        response=[],
        score=90,
    ))
    db.close()
    return alert_id


def test_scan_malformed_json_is_a_client_error(client):
    response = client.post(
        "/api/scan",
        data='{"platform": "windows", ',
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_scan_json_array_body_is_a_client_error(client):
    response = client.post(
        "/api/scan",
        data="[1, 2, 3]",
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_scan_wrong_content_type_is_a_client_error(client):
    response = client.post(
        "/api/scan",
        data="platform=windows",
        content_type="application/x-www-form-urlencoded",
    )
    assert response.status_code == 400
    assert "error" in response.get_json()


@pytest.mark.parametrize("endpoint,kwargs", [
    ("/api/scan", {"data": "{broken", "content_type": "application/json"}),
    ("/api/ingest", {"data": "{broken", "content_type": "application/json"}),
    ("/api/suppressions", {"data": "{broken", "content_type": "application/json"}),
])
def test_malformed_json_on_all_post_endpoints(client, endpoint, kwargs):
    response = client.post(endpoint, **kwargs)
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_update_state_with_unhashable_value_is_a_client_error(
    client, seeded_alert_id
):
    response = client.post(
        f"/api/alerts/{seeded_alert_id}/state",
        json={"state": ["new"]},
    )
    assert response.status_code == 400
    assert "error" in response.get_json()


@pytest.mark.parametrize("batch_size", ["abc", 0, -1, True, 999999])
def test_ingest_batch_size_validation(client, batch_size):
    response = client.post("/api/ingest", json={
        "platform": "linux",
        "log_path": LINUX_FIXTURE,
        "batch_size": batch_size,
    })
    assert response.status_code == 400
    assert "error" in response.get_json()


@pytest.mark.parametrize("duration", ["x", 0, -5, 100000, True])
def test_suppression_duration_validation(client, duration):
    response = client.post("/api/suppressions", json={
        "fingerprint": "fp-1",
        "reason": "test",
        "duration_hours": duration,
    })
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_suppression_valid_request_still_works(client):
    response = client.post("/api/suppressions", json={
        "fingerprint": "fp-1",
        "reason": "test",
        "duration_hours": 24,
    })
    assert response.status_code == 200
    assert response.get_json()["status"] == "created"


@pytest.mark.parametrize("scope_value", [[], ["x"], 5, "host-a"])
def test_global_scope_rejects_scope_value(client, scope_value):
    """S2 review finding 5: a non-null scope_value on global scope used
    to reach the database CHECK constraint and return a 500."""
    response = client.post("/api/suppressions", json={
        "fingerprint": "fp-1",
        "reason": "test",
        "duration_hours": 24,
        "scope": "global",
        "scope_value": scope_value,
    })
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_global_scope_accepts_empty_scope_value(client):
    response = client.post("/api/suppressions", json={
        "fingerprint": "fp-1",
        "reason": "test",
        "duration_hours": 24,
        "scope": "global",
        "scope_value": "",
    })
    assert response.status_code == 200


def test_internal_errors_do_not_leak_exception_text(client, monkeypatch):
    from api.workflows import ApiWorkflows

    def broken_stats(self):
        raise RuntimeError("secret-detail-xyz")

    monkeypatch.setattr(ApiWorkflows, "stats_payload", broken_stats)

    response = client.get("/api/stats")
    assert response.status_code == 500
    body = response.get_data(as_text=True)
    assert "secret-detail-xyz" not in body
    assert response.get_json()["error"]
