"""
Suppression expiry tests (finding E3).

Suppression times are stored in two formats: SQLite CURRENT_TIMESTAMP
writes "YYYY-MM-DD HH:MM:SS" (UTC, naive) while the datetime adapter
writes isoformat ("...T...+00:00"). The old check compared both as text
against CURRENT_TIMESTAMP, so an expired suppression with a "T"
timestamp stayed active for the rest of the UTC day.

The fixed check parses both formats and compares real instants.
"""
from datetime import datetime, timedelta, timezone

import pytest

from core.database import AlertDatabase


@pytest.fixture
def db(tmp_path):
    database = AlertDatabase(str(tmp_path / "suppressions.db"))
    yield database
    database.close()


def _iso(dt: datetime) -> str:
    """The exact format the datetime adapter writes (with T and offset)."""
    return dt.isoformat()


def _sqlite_style(dt: datetime) -> str:
    """The exact format CURRENT_TIMESTAMP writes (space, naive UTC)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _add(db, **overrides):
    params = {
        "fingerprint": "fp-host-1",
        "scope": "global",
        "scope_value": None,
        "author": "analyst",
        "reason": "known admin activity",
        "duration_hours": 24,
    }
    params.update(overrides)
    return db.add_suppression(**params)


def _set_expiry(db, suppression_id: int, value: str) -> None:
    db.connection.execute(
        "UPDATE suppressions SET expires_at = ? WHERE id = ?",
        (value, suppression_id),
    )
    db.connection.commit()


def test_active_suppression_matches_global_scope(db):
    _add(db, fingerprint="fp-host-1")
    assert db._is_suppressed("fp-host-1", "fp-host-1", "host-a") is True


def test_expired_suppression_adapter_format_is_inactive(db):
    """The original bug: an isoformat expiry earlier today stayed active."""
    sid = _add(db)
    _set_expiry(db, sid, _iso(datetime.now(timezone.utc) - timedelta(minutes=5)))

    for activity_fp in ("fp-host-1",):
        assert db._is_suppressed(activity_fp, activity_fp, "host-a") is False


def test_expired_suppression_sqlite_format_is_inactive(db):
    sid = _add(db)
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    db.connection.execute(
        """
        UPDATE suppressions
        SET starts_at = ?, expires_at = ?
        WHERE id = ?
        """,
        (
            _sqlite_style(past - timedelta(minutes=5)),
            _sqlite_style(past),
            sid,
        ),
    )
    db.connection.commit()
    assert db._is_suppressed("fp-host-1", "fp-host-1", "host-a") is False


def test_expiry_boundary_is_strictly_in_the_future(db):
    """At exactly now the suppression is over; one second later it is not."""
    sid = _add(db)

    _set_expiry(db, sid, _iso(datetime.now(timezone.utc)))
    assert db._is_suppressed("fp-host-1", "fp-host-1", "host-a") is False

    _set_expiry(db, sid, _iso(datetime.now(timezone.utc) + timedelta(seconds=1)))
    assert db._is_suppressed("fp-host-1", "fp-host-1", "host-a") is True


def test_suppression_that_has_not_started_is_inactive(db):
    sid = _add(db)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    db.connection.execute(
        "UPDATE suppressions SET starts_at = ? WHERE id = ?",
        (_sqlite_style(future), sid),
    )
    db.connection.commit()

    assert db._is_suppressed("fp-host-1", "fp-host-1", "host-a") is False


def test_host_scope_requires_matching_host(db):
    _add(db, scope="host", scope_value="host-a")
    assert db._is_suppressed("fp-host-1", "fp-host-1", "host-a") is True
    assert db._is_suppressed("fp-host-1", "fp-host-1", "host-b") is False


@pytest.mark.parametrize("bad", [0, -1, 100000, "24", None, True, float("nan")])
def test_invalid_duration_is_rejected(db, bad):
    with pytest.raises(ValueError):
        _add(db, duration_hours=bad)


def test_fractional_duration_is_accepted(db):
    sid = _add(db, duration_hours=0.5)
    assert sid > 0
