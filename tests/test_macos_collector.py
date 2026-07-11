"""
Tests for the macOS Endpoint Security exec collector and parser.
"""
import json
from datetime import datetime, timezone

import pytest

from collectors.macos.collector import MacOSCollector
from collectors.macos.parser import (
    basename,
    parse_es_timestamp,
    parse_exec_event,
)

EXEC_RECORD = {
    "time": "2026-07-11T10:30:00.100Z",
    "process": {
        "executable": {"path": "/bin/zsh"},
        "ppid": 501,
        "audit_token": {"pid": 2201, "euid": 501},
    },
    "event": {
        "exec": {
            "target": {"executable": {"path": "/usr/bin/osascript"}},
            "args": ["osascript", "-e", "do shell script \"id\""],
        }
    },
}


class TestParserHelpers:
    def test_basename(self):
        assert basename("/usr/bin/osascript") == "osascript"
        assert basename("/bin/zsh/") == "zsh"
        assert basename("") == ""

    def test_timestamp_iso(self):
        dt = parse_es_timestamp("2026-07-11T10:30:00.100Z")
        assert dt.year == 2026 and dt.month == 7 and dt.day == 11

    def test_timestamp_epoch(self):
        dt = parse_es_timestamp(0)
        assert dt == datetime.fromtimestamp(0, tz=timezone.utc)

    def test_timestamp_bad_falls_back(self):
        dt = parse_es_timestamp("not-a-time")
        assert dt == datetime.fromtimestamp(0, tz=timezone.utc)


class TestParseExecEvent:
    def test_maps_target_to_process(self):
        fields = parse_exec_event(EXEC_RECORD)
        assert fields["process_name"] == "osascript"
        assert fields["command_line"] == 'osascript -e do shell script "id"'
        assert fields["parent_process_name"] == "zsh"
        assert fields["process_id"] == 2201
        assert fields["parent_process_id"] == 501
        assert fields["user"] == "uid:501"

    def test_root_user(self):
        rec = json.loads(json.dumps(EXEC_RECORD))
        rec["process"]["audit_token"]["euid"] = 0
        assert parse_exec_event(rec)["user"] == "root"

    def test_accepts_json_string(self):
        fields = parse_exec_event(json.dumps(EXEC_RECORD))
        assert fields["process_name"] == "osascript"

    def test_non_exec_event_returns_none(self):
        assert parse_exec_event({"event": {"open": {}}}) is None

    def test_malformed_json_returns_none(self):
        assert parse_exec_event("{not json") is None

    def test_non_dict_returns_none(self):
        assert parse_exec_event(12345) is None


class TestMacOSCollector:
    def test_platform(self):
        assert MacOSCollector().get_platform() == "macos"

    def test_collect_from_fixture(self):
        events = MacOSCollector().collect_events(
            "tests/fixtures/macos/malicious_mac001_osascript_shell.ndjson"
        )
        assert len(events) == 1
        e = events[0]
        assert e.platform == "macos"
        assert e.process_name == "osascript"
        assert "do shell script" in e.command_line
        assert e.parent_process_name == "zsh"

    def test_parse_event_raises_on_non_exec(self):
        with pytest.raises(ValueError):
            MacOSCollector().parse_event('{"event": {"open": {}}}')

    def test_events_from_lines_skips_blanks_and_bad(self):
        collector = MacOSCollector()
        lines = [
            json.dumps(EXEC_RECORD),
            "",
            "{garbage",
            json.dumps({"event": {"open": {}}}),  # non-exec
        ]
        events = collector.events_from_lines(lines)
        assert len(events) == 1

    def test_events_from_text_reports_consumed(self):
        collector = MacOSCollector()
        text = json.dumps(EXEC_RECORD) + "\n"
        events, consumed = collector.events_from_text(text)
        assert len(events) == 1
        assert consumed == len(text)

    def test_collect_directory(self, tmp_path):
        import shutil
        (tmp_path / "a.ndjson").write_text(json.dumps(EXEC_RECORD) + "\n")
        (tmp_path / "b.ndjson").write_text(json.dumps(EXEC_RECORD) + "\n")
        events = MacOSCollector().collect_events(str(tmp_path))
        assert len(events) == 2
