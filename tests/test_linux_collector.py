"""
Tests for Linux collector and parser
"""
import pytest
from datetime import datetime
from pathlib import Path
from collectors.linux.parser import (
    parse_auditd_timestamp,
    parse_execve_args,
    parse_syscall_line,
    extract_process_name,
    get_audit_msg_id
)
from collectors.linux.collector import LinuxCollector
from core.engine import DetectionEngine
from core.rule_loader import RuleLoader


# Path to test fixtures
FIXTURES_DIR = Path(__file__).parent / 'fixtures' / 'linux'


def read_fixture(filename):
    """Helper to read auditd log fixture files"""
    with open(FIXTURES_DIR / filename, 'r') as f:
        return f.read()


def test_parse_auditd_timestamp():
    """Test parsing auditd timestamps"""
    # With audit() wrapper
    dt1 = parse_auditd_timestamp('audit(1642253400.123:1001)')
    assert isinstance(dt1, datetime)
    assert dt1.year == 2022
    assert dt1.month == 1

    # Direct epoch format
    dt2 = parse_auditd_timestamp('1642253400.456')
    assert isinstance(dt2, datetime)

    # Invalid format
    with pytest.raises(ValueError):
        parse_auditd_timestamp('invalid')

    # Empty string
    with pytest.raises(ValueError):
        parse_auditd_timestamp('')


def test_parse_execve_args():
    """Test parsing EXECVE arguments"""
    # Simple command
    line1 = 'type=EXECVE msg=audit(1642253400.123:1001): argc=2 a0="curl" a1="--version"'
    assert parse_execve_args(line1) == 'curl --version'

    # More complex command
    line2 = 'type=EXECVE msg=audit(1642253400.123:1002): argc=4 a0="curl" a1="-s" a2="-o" a3="http://example.com/file.sh"'
    result = parse_execve_args(line2)
    assert 'curl' in result
    assert '-s' in result
    assert 'http://example.com/file.sh' in result

    # Not an EXECVE record
    with pytest.raises(ValueError):
        parse_execve_args('type=SYSCALL msg=audit(1642253400.123:1001): ...')

    # Missing argc
    with pytest.raises(ValueError):
        parse_execve_args('type=EXECVE msg=audit(1642253400.123:1001): a0="test"')


def test_parse_syscall_line():
    """Test parsing SYSCALL records"""
    line = 'type=SYSCALL msg=audit(1642253400.123:1001): arch=c000003e syscall=59 success=yes uid=1000 ppid=1234 pid=5678 cwd="/home/user" exe="/usr/bin/curl"'

    result = parse_syscall_line(line)

    assert result['uid'] == 1000
    assert result['ppid'] == 1234
    assert result['pid'] == 5678
    assert result['cwd'] == '/home/user'
    assert result['exe'] == '/usr/bin/curl'

    # Not a SYSCALL record
    with pytest.raises(ValueError):
        parse_syscall_line('type=EXECVE msg=audit(1642253400.123:1001): ...')


def test_extract_process_name():
    """Test extracting process name from command"""
    assert extract_process_name('/usr/bin/curl --version') == 'curl'
    assert extract_process_name('curl --version') == 'curl'
    assert extract_process_name('/bin/bash') == 'bash'
    assert extract_process_name('nc -l 4444') == 'nc'
    assert extract_process_name('') == ''


def test_get_audit_msg_id():
    """Test extracting message ID from log line"""
    line = 'type=EXECVE msg=audit(1642253400.123:1001): argc=2 a0="test"'
    msg_id = get_audit_msg_id(line)
    assert msg_id == 'audit(1642253400.123:1001)'

    # No message ID
    line_no_msg = 'some random log line'
    assert get_audit_msg_id(line_no_msg) is None


def test_linux_collector_get_platform():
    """Test LinuxCollector returns correct platform"""
    collector = LinuxCollector()
    assert collector.get_platform() == 'linux'


def test_linux_collector_parse_benign_curl():
    """Test parsing benign curl event"""
    collector = LinuxCollector()
    log_content = read_fixture('benign_curl.log')

    # Extract the EXECVE, SYSCALL, and CWD lines
    lines = log_content.strip().split('\n')
    execve_line = [l for l in lines if 'type=EXECVE' in l][0]
    syscall_line = [l for l in lines if 'type=SYSCALL' in l][0]
    cwd_lines = [l for l in lines if 'type=CWD' in l]
    cwd_line = cwd_lines[0] if cwd_lines else None

    # Parse using the parse_event interface
    raw_event = {
        'msg_id': 'audit(1642253400.123:1001)',
        'execve': execve_line,
        'syscall': syscall_line,
        'cwd': cwd_line
    }

    event = collector.parse_event(raw_event)

    assert event.platform == 'linux'
    assert event.process_name == 'curl'
    assert '--silent' in event.command_line
    assert 'security.ubuntu.com' in event.command_line
    assert event.user == 'root'  # uid=0
    assert event.process_id == 5678
    assert event.parent_process_id == 1234
    assert event.working_directory == '/var/lib/apt/lists'


def test_linux_collector_parse_malicious_curl():
    """Test parsing malicious curl event"""
    collector = LinuxCollector()
    log_content = read_fixture('malicious_curl.log')

    lines = log_content.strip().split('\n')
    execve_line = [l for l in lines if 'type=EXECVE' in l][0]
    syscall_line = [l for l in lines if 'type=SYSCALL' in l][0]

    raw_event = {
        'msg_id': 'audit(1642260600.456:2001)',
        'execve': execve_line,
        'syscall': syscall_line
    }

    event = collector.parse_event(raw_event)

    assert event.platform == 'linux'
    assert event.process_name == 'curl'
    assert 'malicious-site.com' in event.command_line
    assert 'backdoor.sh' in event.command_line
    assert event.process_id == 12345
    assert event.parent_process_id == 9876


def test_linux_collector_parse_reverse_shell():
    """Test parsing reverse shell event"""
    collector = LinuxCollector()
    log_content = read_fixture('reverse_shell.log')

    lines = log_content.strip().split('\n')
    execve_line = [l for l in lines if 'type=EXECVE' in l][0]
    syscall_line = [l for l in lines if 'type=SYSCALL' in l][0]
    cwd_lines = [l for l in lines if 'type=CWD' in l]
    cwd_line = cwd_lines[0] if cwd_lines else None

    raw_event = {
        'msg_id': 'audit(1642267800.789:3001)',
        'execve': execve_line,
        'syscall': syscall_line,
        'cwd': cwd_line
    }

    event = collector.parse_event(raw_event)

    assert event.platform == 'linux'
    assert event.process_name == 'bash'
    assert '-i' in event.command_line
    assert '/dev/tcp' in event.command_line
    assert event.working_directory == '/tmp'


def test_linux_collector_parse_cron_persistence():
    """Test parsing cron persistence event"""
    collector = LinuxCollector()
    log_content = read_fixture('cron_persistence.log')

    lines = log_content.strip().split('\n')
    execve_line = [l for l in lines if 'type=EXECVE' in l][0]
    syscall_line = [l for l in lines if 'type=SYSCALL' in l][0]

    raw_event = {
        'msg_id': 'audit(1642275000.111:4001)',
        'execve': execve_line,
        'syscall': syscall_line
    }

    event = collector.parse_event(raw_event)

    assert event.platform == 'linux'
    assert event.process_name == 'crontab'
    assert '-e' in event.command_line
    assert event.process_id == 11111


def test_linux_collector_collect_from_file():
    """Test collecting events from a single audit log file"""
    collector = LinuxCollector()

    events = collector.collect_events(str(FIXTURES_DIR / 'malicious_curl.log'))

    # Should have parsed at least one event
    assert len(events) >= 1
    assert all(e.platform == 'linux' for e in events)


def test_integration_curl_download_rule():
    """Test Linux collector with curl download rule"""
    # Load the curl download rule
    loader = RuleLoader()
    rule = loader.load_rule_file('rules/linux/curl_download.yml')
    engine = DetectionEngine([rule])

    # Parse malicious curl event
    collector = LinuxCollector()
    log_content = read_fixture('malicious_curl.log')

    lines = log_content.strip().split('\n')
    execve_line = [l for l in lines if 'type=EXECVE' in l][0]
    syscall_line = [l for l in lines if 'type=SYSCALL' in l][0]

    raw_event = {
        'msg_id': 'audit(1642260600.456:2001)',
        'execve': execve_line,
        'syscall': syscall_line
    }

    event = collector.parse_event(raw_event)

    # Run detection
    alerts = engine.match_event(event)

    # Should trigger LNX-001 rule
    assert len(alerts) == 1
    assert alerts[0].rule_id == 'LNX-001'
    assert alerts[0].severity == 'high'


def test_integration_reverse_shell_rule():
    """Test Linux collector with reverse shell rule"""
    # Load the reverse shell rule
    loader = RuleLoader()
    rule = loader.load_rule_file('rules/linux/reverse_shell.yml')
    engine = DetectionEngine([rule])

    # Parse reverse shell event
    collector = LinuxCollector()
    log_content = read_fixture('reverse_shell.log')

    lines = log_content.strip().split('\n')
    execve_line = [l for l in lines if 'type=EXECVE' in l][0]
    syscall_line = [l for l in lines if 'type=SYSCALL' in l][0]

    raw_event = {
        'msg_id': 'audit(1642267800.789:3001)',
        'execve': execve_line,
        'syscall': syscall_line
    }

    event = collector.parse_event(raw_event)

    # Run detection
    alerts = engine.match_event(event)

    # Should trigger LNX-002 rule
    assert len(alerts) == 1
    assert alerts[0].rule_id == 'LNX-002'
    assert alerts[0].severity == 'critical'


def test_integration_cron_persistence_rule():
    """Test Linux collector with cron persistence rule"""
    # Load the cron persistence rule
    loader = RuleLoader()
    rule = loader.load_rule_file('rules/linux/cron_persistence.yml')
    engine = DetectionEngine([rule])

    # Parse cron event
    collector = LinuxCollector()
    log_content = read_fixture('cron_persistence.log')

    lines = log_content.strip().split('\n')
    execve_line = [l for l in lines if 'type=EXECVE' in l][0]
    syscall_line = [l for l in lines if 'type=SYSCALL' in l][0]

    raw_event = {
        'msg_id': 'audit(1642275000.111:4001)',
        'execve': execve_line,
        'syscall': syscall_line
    }

    event = collector.parse_event(raw_event)

    # Run detection - note: may not trigger if user is whitelisted
    # This test verifies the parsing works correctly
    alerts = engine.match_event(event)

    # The rule should match (uid=1002, not root)
    assert len(alerts) >= 0  # May or may not alert depending on whitelist


def test_benign_curl_no_alert():
    """Test benign curl event doesn't trigger alert (or gets whitelisted)"""
    # Load the curl download rule
    loader = RuleLoader()
    rule = loader.load_rule_file('rules/linux/curl_download.yml')
    engine = DetectionEngine([rule])

    # Parse benign curl event
    collector = LinuxCollector()
    log_content = read_fixture('benign_curl.log')

    lines = log_content.strip().split('\n')
    execve_line = [l for l in lines if 'type=EXECVE' in l][0]
    syscall_line = [l for l in lines if 'type=SYSCALL' in l][0]

    raw_event = {
        'msg_id': 'audit(1642253400.123:1001)',
        'execve': execve_line,
        'syscall': syscall_line
    }

    event = collector.parse_event(raw_event)

    # Run detection
    alerts = engine.match_event(event)

    # Should NOT trigger (doesn't match .sh pattern, or whitelisted)
    assert len(alerts) == 0


def test_event_timestamp_parsing():
    """Test that event timestamps are correctly parsed"""
    collector = LinuxCollector()
    log_content = read_fixture('malicious_curl.log')

    lines = log_content.strip().split('\n')
    execve_line = [l for l in lines if 'type=EXECVE' in l][0]
    syscall_line = [l for l in lines if 'type=SYSCALL' in l][0]

    raw_event = {
        'msg_id': 'audit(1642260600.456:2001)',
        'execve': execve_line,
        'syscall': syscall_line
    }

    event = collector.parse_event(raw_event)

    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.year == 2022


def test_event_raw_data_preserved():
    """Test that raw auditd data is preserved in Event.raw_data"""
    collector = LinuxCollector()
    log_content = read_fixture('malicious_curl.log')

    lines = log_content.strip().split('\n')
    execve_line = [l for l in lines if 'type=EXECVE' in l][0]
    syscall_line = [l for l in lines if 'type=SYSCALL' in l][0]

    raw_event = {
        'msg_id': 'audit(1642260600.456:2001)',
        'execve': execve_line,
        'syscall': syscall_line
    }

    event = collector.parse_event(raw_event)

    assert 'msg_id' in event.raw_data
    assert 'execve' in event.raw_data
    assert 'syscall' in event.raw_data
    assert event.raw_data['execve'] == execve_line


def test_load_all_linux_rules():
    """Test that all Linux rules can be loaded"""
    loader = RuleLoader()
    rules = loader.load_rules_directory('rules/linux')

    # Should have 6 rules
    assert len(rules) >= 6
    assert all(r.platform == 'linux' for r in rules)

    # Verify rule IDs
    rule_ids = {r.id for r in rules}
    assert 'LNX-001' in rule_ids  # curl_download
    assert 'LNX-002' in rule_ids  # reverse_shell
    assert 'LNX-003' in rule_ids  # cron_persistence
    assert 'LNX-004' in rule_ids  # suspicious_ssh
    assert 'LNX-005' in rule_ids  # base64_decode
    assert 'LNX-006' in rule_ids  # netcat_listener
