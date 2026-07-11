"""
Tests for alert deduplication, suppression, and lifecycle.
"""
import pytest
import tempfile
import os
from datetime import datetime, timedelta
from core.database import AlertDatabase
from core.engine import Alert, normalize_process_name
from core.rule_loader import Rule
from collectors.base import Event
from core.fingerprint import compute_fingerprint, normalize_command_line


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = AlertDatabase(db_path)
        yield db
    finally:
        os.unlink(db_path)


def make_test_alert(
    rule_id="WIN-002",
    process="powershell.exe",
    command="powershell.exe -encodedcommand SGVsbG8=",
    user="admin",
    parent="explorer.exe",
    platform="windows",
    timestamp=None,
):
    """Create a test alert."""
    event = Event(
        timestamp=timestamp or datetime.now(),
        platform=platform,
        process_name=process,
        command_line=command,
        user=user,
        process_id=1234,
        parent_process_name=parent,
    )
    rule = Rule({
        'name': 'Test Rule',
        'id': rule_id,
        'platform': platform,
        'severity': 'high',
        'detection': {'process_name': process},
        'mitre_attack': ['T1059.001'],
    })
    return Alert(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        event=event,
        timestamp=event.timestamp,
        mitre_attack=rule.mitre_attack,
        description="Test alert",
        response=["Investigate"],
        score=85,
    )


class TestFingerprinting:
    """Test alert fingerprint computation."""

    def test_same_alert_produces_same_fingerprint(self):
        alert1 = make_test_alert()
        alert2 = make_test_alert()
        fp1 = compute_fingerprint(alert1)
        fp2 = compute_fingerprint(alert2)
        assert fp1["fingerprint"] == fp2["fingerprint"]

    def test_different_command_produces_different_fingerprint(self):
        alert1 = make_test_alert(command="powershell.exe -enc abc")
        alert2 = make_test_alert(command="powershell.exe -enc def")
        fp1 = compute_fingerprint(alert1)
        fp2 = compute_fingerprint(alert2)
        assert fp1["fingerprint"] != fp2["fingerprint"]

    def test_different_rule_produces_different_fingerprint(self):
        alert1 = make_test_alert(rule_id="WIN-001")
        alert2 = make_test_alert(rule_id="WIN-002")
        fp1 = compute_fingerprint(alert1)
        fp2 = compute_fingerprint(alert2)
        assert fp1["fingerprint"] != fp2["fingerprint"]

    def test_activity_fingerprint_excludes_host(self):
        alert1 = make_test_alert()
        alert2 = make_test_alert()
        # Same alert, same activity fingerprint
        fp1 = compute_fingerprint(alert1)
        fp2 = compute_fingerprint(alert2)
        assert fp1["activity_fingerprint"] == fp2["activity_fingerprint"]

    def test_fingerprint_is_sha256_hex(self):
        alert = make_test_alert()
        fp = compute_fingerprint(alert)
        # SHA-256 produces 64 hex characters
        assert len(fp["fingerprint"]) == 64
        assert all(c in "0123456789abcdef" for c in fp["fingerprint"])

    def test_command_line_normalization_collapse_whitespace(self):
        normalized = normalize_command_line(
            "powershell.exe   -nop    -c   whoami", "windows"
        )
        assert normalized == "powershell.exe -nop -c whoami"

    def test_command_line_normalization_windows_casefold(self):
        normalized = normalize_command_line(
            "PowerShell.EXE -NoP -C whoami", "windows"
        )
        assert "powershell.exe" in normalized
        assert "-nop" in normalized

    def test_command_line_normalization_linux_preserves_case(self):
        normalized = normalize_command_line(
            "Bash -c whoami", "linux"
        )
        assert "Bash" in normalized


class TestDeduplication:
    """Test alert deduplication logic."""

    def test_first_alert_is_new_episode(self, temp_db):
        alert = make_test_alert()
        result = temp_db.save_alert_dedup(alert)
        assert result["is_duplicate"] is False
        assert result["is_suppressed"] is False
        assert result["occurrence_count"] == 1
        assert result["alert_id"] is not None

    def test_duplicate_alert_increments_count(self, temp_db):
        ts = datetime.now()
        alert1 = make_test_alert(timestamp=ts)
        alert2 = make_test_alert(timestamp=ts + timedelta(minutes=5))

        result1 = temp_db.save_alert_dedup(alert1)
        result2 = temp_db.save_alert_dedup(alert2)

        assert result1["is_duplicate"] is False
        assert result2["is_duplicate"] is True
        assert result2["alert_id"] == result1["alert_id"]
        assert result2["occurrence_count"] == 2

    def test_different_alerts_create_separate_episodes(self, temp_db):
        ts = datetime.now()
        alert1 = make_test_alert(command="powershell.exe -enc abc", timestamp=ts)
        alert2 = make_test_alert(command="powershell.exe -enc def", timestamp=ts)

        result1 = temp_db.save_alert_dedup(alert1)
        result2 = temp_db.save_alert_dedup(alert2)

        assert result1["alert_id"] != result2["alert_id"]
        assert result1["occurrence_count"] == 1
        assert result2["occurrence_count"] == 1

    def test_three_duplicates_increment_to_three(self, temp_db):
        ts = datetime.now()
        for i in range(3):
            alert = make_test_alert(timestamp=ts + timedelta(minutes=i * 5))
            result = temp_db.save_alert_dedup(alert)

        assert result["occurrence_count"] == 3
        assert result["is_duplicate"] is True

    def test_alert_outside_dedup_window_creates_new_episode(self, temp_db):
        ts = datetime.now()
        alert1 = make_test_alert(timestamp=ts)
        # 48 hours later, outside the 24h default window
        alert2 = make_test_alert(timestamp=ts + timedelta(hours=48))

        result1 = temp_db.save_alert_dedup(alert1)
        result2 = temp_db.save_alert_dedup(alert2)

        assert result1["alert_id"] != result2["alert_id"]
        assert result2["is_duplicate"] is False


class TestAlertLifecycle:
    """Test alert state transitions and audit trail."""

    def test_new_alert_has_new_state(self, temp_db):
        alert = make_test_alert()
        result = temp_db.save_alert_dedup(alert)
        cursor = temp_db.connection.cursor()
        cursor.execute("SELECT state FROM alerts WHERE id = ?", (result["alert_id"],))
        row = cursor.fetchone()
        assert row[0] == "new"

    def test_update_state_to_acknowledged(self, temp_db):
        alert = make_test_alert()
        result = temp_db.save_alert_dedup(alert)
        updated = temp_db.update_alert_state(
            result["alert_id"], "acknowledged", "analyst", "Reviewing"
        )
        assert updated is True

        cursor = temp_db.connection.cursor()
        cursor.execute("SELECT state FROM alerts WHERE id = ?", (result["alert_id"],))
        row = cursor.fetchone()
        assert row[0] == "acknowledged"

    def test_update_state_to_resolved(self, temp_db):
        alert = make_test_alert()
        result = temp_db.save_alert_dedup(alert)
        temp_db.update_alert_state(
            result["alert_id"], "investigating", "analyst", "Looking into it"
        )
        temp_db.update_alert_state(
            result["alert_id"], "resolved", "analyst", "Fixed"
        )

        cursor = temp_db.connection.cursor()
        cursor.execute("SELECT state FROM alerts WHERE id = ?", (result["alert_id"],))
        row = cursor.fetchone()
        assert row[0] == "resolved"

    def test_invalid_state_raises(self, temp_db):
        alert = make_test_alert()
        result = temp_db.save_alert_dedup(alert)
        with pytest.raises(ValueError):
            temp_db.update_alert_state(
                result["alert_id"], "invalid_state", "analyst"
            )

    def test_update_nonexistent_alert_returns_false(self, temp_db):
        updated = temp_db.update_alert_state(99999, "acknowledged", "analyst")
        assert updated is False

    def test_audit_trail_records_state_changes(self, temp_db):
        alert = make_test_alert()
        result = temp_db.save_alert_dedup(alert)
        temp_db.update_alert_state(
            result["alert_id"], "acknowledged", "analyst", "First review"
        )

        cursor = temp_db.connection.cursor()
        cursor.execute(
            "SELECT action, previous_state, new_state, author, reason FROM alert_audit WHERE alert_id = ?",
            (result["alert_id"],),
        )
        row = cursor.fetchone()
        assert row[0] == "state_change"
        assert row[1] == "new"
        assert row[2] == "acknowledged"
        assert row[3] == "analyst"
        assert row[4] == "First review"


class TestSuppression:
    """Test alert suppression."""

    def test_create_global_suppression(self, temp_db):
        sid = temp_db.add_suppression(
            "test_fingerprint_123", "global", None, "analyst", "Known false positive", 24
        )
        assert sid is not None

        cursor = temp_db.connection.cursor()
        cursor.execute("SELECT scope, active, reason FROM suppressions WHERE id = ?", (sid,))
        row = cursor.fetchone()
        assert row[0] == "global"
        assert row[1] == 1
        assert row[2] == "Known false positive"

    def test_create_host_scoped_suppression(self, temp_db):
        sid = temp_db.add_suppression(
            "test_fingerprint_456", "host", "workstation-01", "analyst", "Host-specific FP", 12
        )
        assert sid is not None

        cursor = temp_db.connection.cursor()
        cursor.execute("SELECT scope, scope_value FROM suppressions WHERE id = ?", (sid,))
        row = cursor.fetchone()
        assert row[0] == "host"
        assert row[1] == "workstation-01"

    def test_suppressed_alert_not_stored(self, temp_db):
        alert = make_test_alert()
        # First save to get the fingerprint
        result = temp_db.save_alert_dedup(alert)
        fp = compute_fingerprint(alert)

        # Suppress the activity fingerprint globally
        temp_db.add_suppression(
            fp["activity_fingerprint"], "global", None, "analyst", "Suppressing this pattern", 24
        )

        # Next alert with same fingerprint should be suppressed
        alert2 = make_test_alert(timestamp=datetime.now() + timedelta(minutes=10))
        result2 = temp_db.save_alert_dedup(alert2)
        assert result2["is_suppressed"] is True
        assert result2["alert_id"] is None


class TestProcessNameNormalization:
    """Test exact basename matching (no more substring matching)."""

    def test_basename_extraction_from_full_path(self):
        assert normalize_process_name("C:\\Windows\\System32\\powershell.exe", "windows") == "powershell.exe"

    def test_basename_extraction_from_unix_path(self):
        assert normalize_process_name("/usr/bin/bash", "linux") == "bash"

    def test_windows_case_insensitive(self):
        assert normalize_process_name("PowerShell.EXE", "windows") == "powershell.exe"

    def test_linux_case_sensitive(self):
        assert normalize_process_name("Bash", "linux") == "Bash"

    def test_empty_name(self):
        assert normalize_process_name("", "windows") == ""

    def test_none_name(self):
        assert normalize_process_name(None, "windows") == ""

    def test_substring_no_longer_matches(self):
        """notpowershell.exe should NOT match powershell.exe."""
        normalized1 = normalize_process_name("notpowershell.exe", "windows")
        normalized2 = normalize_process_name("powershell.exe", "windows")
        assert normalized1 != normalized2