"""
Tests for collector base class
"""
import pytest
from datetime import datetime
from collectors.base import Event, BaseCollector


def test_event_creation():
    """Test Event dataclass creation"""
    event = Event(
        timestamp=datetime.now(),
        platform="windows",
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        user="testuser",
        process_id=1234
    )
    
    assert event.process_name == "cmd.exe"
    assert event.platform == "windows"
    assert event.process_id == 1234


def test_event_to_dict():
    """Test Event serialization"""
    event = Event(
        timestamp=datetime(2025, 1, 1, 12, 0, 0),
        platform="linux",
        process_name="bash",
        command_line="/bin/bash",
        user="root",
        process_id=5678
    )
    
    result = event.to_dict()
    assert result['process_name'] == "bash"
    assert result['platform'] == "linux"
    assert 'timestamp' in result


def test_base_collector_is_abstract():
    """Test that BaseCollector cannot be instantiated"""
    with pytest.raises(TypeError):
        collector = BaseCollector()


# Mock collector for testing
class MockCollector(BaseCollector):
    def get_platform(self):
        return "mock"
    
    def collect_events(self, source, start_time=None, end_time=None):
        return []
    
    def parse_event(self, raw_event):
        return Event(
            timestamp=datetime.now(),
            platform="mock",
            process_name="mock.exe",
            command_line="mock",
            user="mockuser",
            process_id=1
        )


def test_mock_collector_implements_interface():
    """Test that mock collector works"""
    collector = MockCollector()
    assert collector.get_platform() == "mock"
    events = collector.collect_events("/fake/path")
    assert isinstance(events, list)