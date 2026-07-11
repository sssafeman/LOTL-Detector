"""
Tests for scoped API keys, rotation, and per-endpoint scope enforcement.
"""
import tempfile
import os

import pytest

from api.auth import (
    KeyStore,
    expand_scopes,
    KeyRecord,
)
from api.server import create_app

READ_KEY = "read-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SCAN_KEY = "scan-key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ADMIN_KEY = "admin-key-cccccccccccccccccccccccccccccc"


class TestExpandScopes:
    def test_admin_implies_all(self):
        assert expand_scopes(["admin"]) == frozenset(("read", "scan", "admin"))

    def test_scan_implies_read(self):
        assert expand_scopes(["scan"]) == frozenset(("read", "scan"))

    def test_read_only(self):
        assert expand_scopes(["read"]) == frozenset(("read",))

    def test_unknown_ignored(self):
        assert expand_scopes(["read", "superuser"]) == frozenset(("read",))


class TestKeyStore:
    def test_authenticate_returns_record(self):
        store = KeyStore.from_records([
            {"key": READ_KEY, "label": "reader", "scopes": ["read"]},
        ])
        rec = store.authenticate(READ_KEY)
        assert rec is not None
        assert rec.label == "reader"
        assert rec.has_scope("read")
        assert not rec.has_scope("scan")

    def test_authenticate_unknown_token(self):
        store = KeyStore.from_records([
            {"key": READ_KEY, "label": "reader", "scopes": ["read"]},
        ])
        assert store.authenticate("nope") is None

    def test_multiple_keys_for_rotation(self):
        store = KeyStore.from_records([
            {"key": READ_KEY, "label": "old", "scopes": ["read"]},
            {"key": SCAN_KEY, "label": "new", "scopes": ["scan"]},
        ])
        assert store.authenticate(READ_KEY).label == "old"
        assert store.authenticate(SCAN_KEY).label == "new"
        assert len(store) == 2

    def test_short_keys_skipped(self):
        store = KeyStore.from_records([
            {"key": "tooshort", "label": "bad", "scopes": ["read"]},
            {"key": READ_KEY, "label": "good", "scopes": ["read"]},
        ])
        assert len(store) == 1
        assert store.labels == ["good"]

    def test_single_key_gets_all_scopes(self):
        store = KeyStore.from_single(ADMIN_KEY)
        rec = store.authenticate(ADMIN_KEY)
        assert rec.has_scope("admin")
        assert rec.has_scope("read")

    def test_load_from_keys_file(self, tmp_path, monkeypatch):
        import json
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps([
            {"key": ADMIN_KEY, "label": "admin", "scopes": ["admin"]},
        ]))
        monkeypatch.setenv("LOTL_API_KEYS_FILE", str(keys_file))
        store = KeyStore.load()
        assert store is not None
        assert store.authenticate(ADMIN_KEY).has_scope("admin")


@pytest.fixture
def scoped_client():
    """App with three scoped keys, real auth enabled."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    app = create_app({
        "DATABASE_PATH": db_path,
        "RULES_DIR": "rules",
        "TESTING": True,
        "LOG_LEVEL": "ERROR",
        "API_KEYS": [
            {"key": READ_KEY, "label": "reader", "scopes": ["read"]},
            {"key": SCAN_KEY, "label": "scanner", "scopes": ["scan"]},
            {"key": ADMIN_KEY, "label": "admin", "scopes": ["admin"]},
        ],
    })
    client = app.test_client()
    yield client
    if os.path.exists(db_path):
        os.unlink(db_path)


def _hdr(key):
    return {"Authorization": f"Bearer {key}"}


class TestEndpointScopeEnforcement:
    def test_health_is_public(self, scoped_client):
        assert scoped_client.get("/api/health").status_code == 200

    def test_no_key_is_401(self, scoped_client):
        assert scoped_client.get("/api/alerts").status_code == 401

    def test_bad_key_is_401(self, scoped_client):
        assert scoped_client.get(
            "/api/alerts", headers=_hdr("wrong")
        ).status_code == 401

    def test_read_key_can_read(self, scoped_client):
        assert scoped_client.get(
            "/api/alerts", headers=_hdr(READ_KEY)
        ).status_code == 200

    def test_read_key_cannot_scan(self, scoped_client):
        resp = scoped_client.post(
            "/api/scan",
            json={"platform": "windows", "log_path": "tests/fixtures/windows"},
            headers=_hdr(READ_KEY),
        )
        assert resp.status_code == 403
        assert "scope" in resp.get_json()["message"]

    def test_scan_key_can_scan_and_read(self, scoped_client):
        assert scoped_client.get(
            "/api/alerts", headers=_hdr(SCAN_KEY)
        ).status_code == 200
        resp = scoped_client.post(
            "/api/scan",
            json={"platform": "windows", "log_path": "tests/fixtures/windows"},
            headers=_hdr(SCAN_KEY),
        )
        assert resp.status_code == 200

    def test_scan_key_cannot_admin(self, scoped_client):
        resp = scoped_client.post(
            "/api/alerts/1/state",
            json={"state": "resolved"},
            headers=_hdr(SCAN_KEY),
        )
        assert resp.status_code == 403

    def test_admin_key_can_do_everything(self, scoped_client):
        assert scoped_client.get(
            "/api/alerts", headers=_hdr(ADMIN_KEY)
        ).status_code == 200
        assert scoped_client.post(
            "/api/scan",
            json={"platform": "windows", "log_path": "tests/fixtures/windows"},
            headers=_hdr(ADMIN_KEY),
        ).status_code == 200
        # admin state change on a nonexistent alert returns 404, not 403
        resp = scoped_client.post(
            "/api/alerts/999999/state",
            json={"state": "resolved"},
            headers=_hdr(ADMIN_KEY),
        )
        assert resp.status_code in (200, 404)

    def test_rotation_both_keys_work(self, scoped_client):
        # reader and admin are distinct valid keys simultaneously
        assert scoped_client.get(
            "/api/alerts", headers=_hdr(READ_KEY)
        ).status_code == 200
        assert scoped_client.get(
            "/api/alerts", headers=_hdr(ADMIN_KEY)
        ).status_code == 200
