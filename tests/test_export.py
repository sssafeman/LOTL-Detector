"""
Tests for SIEM export formatters and sinks.
"""
import json
import os
import tempfile
from datetime import datetime

import pytest

from collectors.base import Event
from core.correlator import Correlator, load_chain_rules
from core.engine import Alert
from core.export import (
    FileSink,
    StdoutSink,
    SyslogSink,
    WebhookSink,
    build_sink,
    format_records,
    to_cef,
    to_ecs,
)


def make_alert():
    event = Event(
        timestamp=datetime(2026, 7, 11, 10, 0, 0),
        platform="windows",
        process_name="powershell.exe",
        command_line="powershell.exe -enc SQBFAFgA",
        user="alice",
        process_id=1000,
        parent_process_name="winword.exe",
        raw_data={"hostname": "ws01"},
    )
    return Alert(
        rule_id="WIN-002",
        rule_name="PowerShell Encoded Command Execution",
        severity="high",
        event=event,
        timestamp=event.timestamp,
        mitre_attack=["T1059.001", "T1027"],
        description="Encoded PowerShell",
        response=["Investigate"],
        score=95,
        risk_band="high",
    )


def make_incident():
    events = [
        Event(
            timestamp=datetime(2026, 7, 11, 10, 0, 0), platform="windows",
            process_name="WINWORD.EXE", command_line="winword.exe doc.docx",
            user="alice", process_id=100, parent_process_name="explorer.exe",
            parent_process_id=1, raw_data={"hostname": "ws01"},
        ),
        Event(
            timestamp=datetime(2026, 7, 11, 10, 1, 0), platform="windows",
            process_name="powershell.exe",
            command_line="powershell.exe -EncodedCommand SQBFAFgA",
            user="alice", process_id=200, parent_process_name="WINWORD.EXE",
            parent_process_id=100, raw_data={"hostname": "ws01"},
        ),
    ]
    return Correlator(load_chain_rules()).correlate(events)[0]


class TestCefFormat:
    def test_alert_cef_header_and_extensions(self):
        line = to_cef(make_alert())
        assert line.startswith("CEF:0|LOTL Detector|lotl-detector|1|WIN-002|")
        # High band maps to CEF severity 8
        assert "|8|" in line
        assert "suser=alice" in line
        assert "cs1Label=commandLine" in line
        assert "dvchost=ws01" in line
        assert "cn2=95" in line

    def test_cef_escapes_equals_in_command(self):
        alert = make_alert()
        alert.event.command_line = "cmd /c set X=1"
        line = to_cef(alert)
        assert "X\\=1" in line

    def test_incident_cef_includes_chain(self):
        line = to_cef(make_incident())
        assert line.startswith("CEF:0|LOTL Detector|lotl-detector|1|CHAIN-WIN-001|")
        assert "|10|" in line  # critical
        assert "cs2Label=processChain" in line
        assert "cn1Label=confidence" in line


class TestEcsFormat:
    def test_alert_ecs_structure(self):
        doc = to_ecs(make_alert())
        assert doc["@timestamp"] == "2026-07-11T10:00:00"
        assert doc["rule"]["id"] == "WIN-002"
        assert doc["process"]["name"] == "powershell.exe"
        assert doc["process"]["parent"]["name"] == "winword.exe"
        assert doc["user"]["name"] == "alice"
        assert doc["host"]["name"] == "ws01"
        assert doc["threat"]["technique"]["id"] == ["T1059.001", "T1027"]
        assert doc["event"]["risk_score"] == 95
        assert doc["observer"]["vendor"] == "LOTL Detector"

    def test_incident_ecs_structure(self):
        doc = to_ecs(make_incident())
        assert doc["rule"]["id"] == "CHAIN-WIN-001"
        assert doc["event"]["dataset"] == "lotl.incident"
        assert doc["lotl"]["kind"] == "incident"
        assert "->" in doc["lotl"]["process_chain"]
        assert doc["lotl"]["stage_count"] == 2

    def test_alert_from_db_row_dict(self):
        # Shape mirrors AlertDatabase.get_alerts output
        row = {
            "rule_id": "LNX-002", "rule_name": "Reverse Shell",
            "severity": "critical", "score": 130, "risk_band": "critical",
            "platform": "linux", "process_name": "bash",
            "command_line": "bash -i", "user": "www-data",
            "parent_process_name": None, "timestamp": "2026-07-11T10:00:00",
            "mitre_attack": ["T1059.004"], "description": "rev shell",
            "event_data": {"raw_data": {"hostname": "srv01"}},
        }
        doc = to_ecs(row)
        assert doc["rule"]["id"] == "LNX-002"
        assert doc["host"]["name"] == "srv01"
        cef = to_cef(row)
        assert "externalId=LNX-002" in cef


class TestFormatDispatch:
    def test_format_records_json_is_single_line(self):
        lines = format_records([make_alert()], "json")
        assert len(lines) == 1
        assert "\n" not in lines[0]
        parsed = json.loads(lines[0])
        assert parsed["rule"]["id"] == "WIN-002"

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError, match="Unknown export format"):
            format_records([make_alert()], "leef")


class TestSinks:
    def test_file_sink(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            sink = FileSink(path)
            count = sink.export([make_alert(), make_incident()], "json")
            assert count == 2
            with open(path) as fh:
                lines = fh.read().strip().splitlines()
            assert len(lines) == 2
            assert json.loads(lines[0])["rule"]["id"] == "WIN-002"
        finally:
            os.unlink(path)

    def test_syslog_sink_with_injected_transport(self):
        sent = []
        sink = SyslogSink(transport=lambda payload, addr: sent.append((payload, addr)))
        assert sink.emit("hello") is True
        payload, addr = sent[0]
        assert payload.startswith(b"<109>")  # facility 13 sev 5 = 109
        assert addr == ("127.0.0.1", 514)

    def test_webhook_retries_then_succeeds(self):
        attempts = []

        def flaky_transport(url, data, headers):
            attempts.append(url)
            if len(attempts) < 3:
                raise OSError("connection refused")
            return 200

        sink = WebhookSink(
            "http://siem.local/hook", max_retries=3,
            transport=flaky_transport, sleep=lambda s: None,
        )
        assert sink.emit('{"a":1}') is True
        assert len(attempts) == 3

    def test_webhook_gives_up_after_retries(self):
        def always_fail(url, data, headers):
            return 500

        sink = WebhookSink(
            "http://siem.local/hook", max_retries=2,
            transport=always_fail, sleep=lambda s: None,
        )
        assert sink.emit('{"a":1}') is False

    def test_build_sink_types(self):
        assert isinstance(build_sink({"type": "stdout"}), StdoutSink)
        assert isinstance(build_sink({"type": "file", "path": "/tmp/x.log"}), FileSink)
        assert isinstance(build_sink({"type": "syslog"}), SyslogSink)
        assert isinstance(
            build_sink({"type": "webhook", "url": "http://h/x"}), WebhookSink
        )
        with pytest.raises(ValueError):
            build_sink({"type": "smoke-signal"})
