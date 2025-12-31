"""
Tests for Windows collector and parser
"""
import pytest
from datetime import datetime
from pathlib import Path
from collectors.windows.parser import (
    parse_sysmon_xml,
    extract_process_name,
    parse_sysmon_timestamp
)
from collectors.windows.collector import WindowsCollector
from core.engine import DetectionEngine
from core.rule_loader import RuleLoader


# Path to test fixtures
FIXTURES_DIR = Path(__file__).parent / 'fixtures' / 'windows'


def read_fixture(filename):
    """Helper to read XML fixture files"""
    with open(FIXTURES_DIR / filename, 'r') as f:
        return f.read()


def test_extract_process_name():
    """Test extracting process name from full path"""
    assert extract_process_name('C:\\Windows\\System32\\cmd.exe') == 'cmd.exe'
    assert extract_process_name('C:\\Program Files\\app.exe') == 'app.exe'
    assert extract_process_name('certutil.exe') == 'certutil.exe'
    assert extract_process_name('') == ''

    # Unix-style paths should also work
    assert extract_process_name('/usr/bin/bash') == 'bash'


def test_parse_sysmon_timestamp():
    """Test parsing Sysmon timestamps"""
    # With milliseconds
    dt1 = parse_sysmon_timestamp('2025-01-15 12:34:56.789')
    assert dt1.year == 2025
    assert dt1.month == 1
    assert dt1.day == 15
    assert dt1.hour == 12
    assert dt1.minute == 34
    assert dt1.second == 56

    # Without milliseconds
    dt2 = parse_sysmon_timestamp('2025-01-15 12:34:56')
    assert dt2.year == 2025
    assert dt2.hour == 12

    # Invalid format
    with pytest.raises(ValueError):
        parse_sysmon_timestamp('invalid')

    # Empty string
    with pytest.raises(ValueError):
        parse_sysmon_timestamp('')


def test_parse_benign_certutil_xml():
    """Test parsing benign certutil event"""
    xml = read_fixture('benign_certutil.xml')
    parsed = parse_sysmon_xml(xml)

    assert parsed['event_id'] == 1
    assert parsed['process_id'] == int('0x1a2b', 16)
    assert 'certutil.exe' in parsed['image'].lower()
    assert '-verify' in parsed['command_line']
    assert parsed['user'] == 'NT AUTHORITY\\SYSTEM'
    assert 'msiexec.exe' in parsed['parent_image'].lower()
    assert parsed['utc_time'] == '2025-01-15 10:30:00.123'


def test_parse_malicious_certutil_xml():
    """Test parsing malicious certutil event"""
    xml = read_fixture('malicious_certutil.xml')
    parsed = parse_sysmon_xml(xml)

    assert parsed['event_id'] == 1
    assert 'certutil.exe' in parsed['image'].lower()
    assert '-urlcache' in parsed['command_line']
    assert 'http://' in parsed['command_line']
    assert 'BadUser' in parsed['user']
    assert 'cmd.exe' in parsed['parent_image'].lower()


def test_parse_powershell_encoded_xml():
    """Test parsing PowerShell encoded command event"""
    xml = read_fixture('powershell_encoded.xml')
    parsed = parse_sysmon_xml(xml)

    assert parsed['event_id'] == 1
    assert 'powershell.exe' in parsed['image'].lower()
    assert '-EncodedCommand' in parsed['command_line']
    assert 'WINWORD.EXE' in parsed['parent_image']


def test_parse_xml_missing_required_field():
    """Test parsing fails gracefully when required fields are missing"""
    # XML missing CommandLine field
    incomplete_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>1</EventID>
      </System>
      <EventData>
        <Data Name="ProcessId">1234</Data>
        <Data Name="Image">C:\\test.exe</Data>
        <Data Name="User">TestUser</Data>
        <Data Name="UtcTime">2025-01-15 12:00:00</Data>
      </EventData>
    </Event>"""

    with pytest.raises(ValueError, match="Missing required field: CommandLine"):
        parse_sysmon_xml(incomplete_xml)


def test_parse_xml_invalid_event_id():
    """Test parsing rejects non-Event ID 1 events"""
    # Event ID 3 (Network Connection) instead of 1
    wrong_event_id_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>3</EventID>
      </System>
      <EventData>
        <Data Name="ProcessId">1234</Data>
      </EventData>
    </Event>"""

    with pytest.raises(ValueError, match="Unsupported Event ID: 3"):
        parse_sysmon_xml(wrong_event_id_xml)


def test_parse_invalid_xml():
    """Test parsing invalid XML fails gracefully"""
    with pytest.raises(ValueError, match="Invalid XML"):
        parse_sysmon_xml("This is not XML")


def test_windows_collector_get_platform():
    """Test WindowsCollector returns correct platform"""
    collector = WindowsCollector()
    assert collector.get_platform() == 'windows'


def test_windows_collector_parse_event():
    """Test WindowsCollector.parse_event creates Event object"""
    collector = WindowsCollector()
    xml = read_fixture('malicious_certutil.xml')

    event = collector.parse_event(xml)

    assert event.platform == 'windows'
    assert event.process_name == 'certutil.exe'
    assert '-urlcache' in event.command_line
    assert 'http://' in event.command_line
    assert 'BadUser' in event.user
    assert event.parent_process_name == 'cmd.exe'
    assert event.process_id == int('0x4d2', 16)
    assert isinstance(event.timestamp, datetime)


def test_windows_collector_parse_event_without_parent():
    """Test parsing event without parent process"""
    # Create minimal Event ID 1 XML without parent process
    xml_no_parent = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>1</EventID>
      </System>
      <EventData>
        <Data Name="ProcessId">0x1234</Data>
        <Data Name="Image">C:\\Windows\\System32\\test.exe</Data>
        <Data Name="CommandLine">test.exe</Data>
        <Data Name="User">TestUser</Data>
        <Data Name="UtcTime">2025-01-15 12:00:00</Data>
      </EventData>
    </Event>"""

    collector = WindowsCollector()
    event = collector.parse_event(xml_no_parent)

    assert event.parent_process_name is None
    assert event.parent_process_id is None


def test_windows_collector_handles_hex_process_ids():
    """Test that hex process IDs are converted to integers"""
    collector = WindowsCollector()
    xml = read_fixture('malicious_certutil.xml')

    event = collector.parse_event(xml)

    # Process ID in XML is 0x4d2 (1234 in decimal)
    assert event.process_id == 1234
    assert isinstance(event.process_id, int)


def test_integration_with_detection_engine():
    """Test Windows collector events work with DetectionEngine"""
    # Load the actual certutil rule
    loader = RuleLoader()
    rule = loader.load_rule_file('rules/windows/certutil_download.yml')
    engine = DetectionEngine([rule])

    # Parse malicious certutil event
    collector = WindowsCollector()
    xml = read_fixture('malicious_certutil.xml')
    event = collector.parse_event(xml)

    # Run detection
    alerts = engine.match_event(event)

    # Should trigger WIN-001 rule
    assert len(alerts) == 1
    assert alerts[0].rule_id == 'WIN-001'
    assert alerts[0].severity == 'high'
    assert alerts[0].score > 0


def test_benign_certutil_no_alert():
    """Test benign certutil event doesn't trigger alert"""
    # Load the certutil rule
    loader = RuleLoader()
    rule = loader.load_rule_file('rules/windows/certutil_download.yml')
    engine = DetectionEngine([rule])

    # Parse benign certutil event
    collector = WindowsCollector()
    xml = read_fixture('benign_certutil.xml')
    event = collector.parse_event(xml)

    # Run detection - should NOT trigger (no -urlcache + http)
    alerts = engine.match_event(event)

    # No alert should be generated (or whitelisted due to SYSTEM user)
    assert len(alerts) == 0


def test_powershell_event_parsing():
    """Test PowerShell encoded command event can be parsed"""
    collector = WindowsCollector()
    xml = read_fixture('powershell_encoded.xml')

    event = collector.parse_event(xml)

    assert event.platform == 'windows'
    assert event.process_name == 'powershell.exe'
    assert '-EncodedCommand' in event.command_line
    assert event.parent_process_name == 'WINWORD.EXE'
    assert 'SuspiciousUser' in event.user


def test_event_raw_data_preserved():
    """Test that raw XML and parsed data are preserved in Event.raw_data"""
    collector = WindowsCollector()
    xml = read_fixture('malicious_certutil.xml')

    event = collector.parse_event(xml)

    assert 'xml' in event.raw_data
    assert 'parsed' in event.raw_data
    assert event.raw_data['xml'] == xml
    assert isinstance(event.raw_data['parsed'], dict)


def test_timestamp_conversion():
    """Test Sysmon timestamp is correctly converted to datetime"""
    collector = WindowsCollector()
    xml = read_fixture('benign_certutil.xml')

    event = collector.parse_event(xml)

    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.year == 2025
    assert event.timestamp.month == 1
    assert event.timestamp.day == 15


def test_working_directory_extraction():
    """Test working directory is extracted from Sysmon event"""
    collector = WindowsCollector()
    xml = read_fixture('malicious_certutil.xml')

    event = collector.parse_event(xml)

    # The malicious certutil XML has CurrentDirectory set
    assert event.working_directory is not None
    assert 'Downloads' in event.working_directory


def test_parent_process_id_parsing():
    """Test parent process ID is correctly parsed"""
    collector = WindowsCollector()
    xml = read_fixture('malicious_certutil.xml')

    event = collector.parse_event(xml)

    # Parent process ID in XML is 0x3e8 (1000 in decimal)
    assert event.parent_process_id == 1000
    assert isinstance(event.parent_process_id, int)


def test_multiple_events_different_severities():
    """Test parsing multiple events with different detection outcomes"""
    collector = WindowsCollector()

    # Parse all three fixture events
    benign_xml = read_fixture('benign_certutil.xml')
    malicious_xml = read_fixture('malicious_certutil.xml')
    powershell_xml = read_fixture('powershell_encoded.xml')

    benign_event = collector.parse_event(benign_xml)
    malicious_event = collector.parse_event(malicious_xml)
    powershell_event = collector.parse_event(powershell_xml)

    # All should be valid Event objects
    assert benign_event.platform == 'windows'
    assert malicious_event.platform == 'windows'
    assert powershell_event.platform == 'windows'

    # Each should have different command lines
    assert 'verify' in benign_event.command_line.lower()
    assert 'urlcache' in malicious_event.command_line.lower()
    assert 'encodedcommand' in powershell_event.command_line.lower()
