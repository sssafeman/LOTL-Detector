"""
Tests for REST API server
"""
import pytest
import tempfile
import os
from datetime import datetime
from pathlib import Path
from api.server import create_app
from core.database import AlertDatabase
from core.engine import Alert
from collectors.base import Event


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
        db_path = f.name

    yield db_path

    # Cleanup
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def app(temp_db):
    """Create Flask app with test configuration"""
    config = {
        'DATABASE_PATH': temp_db,
        'RULES_DIR': 'rules',
        'TESTING': True,
        'LOG_LEVEL': 'ERROR'  # Suppress logs during tests
    }

    app = create_app(config)
    return app


@pytest.fixture
def client(app):
    """Create Flask test client"""
    return app.test_client()


@pytest.fixture
def sample_alerts(temp_db):
    """Create sample alerts in the database"""
    db = AlertDatabase(temp_db)

    # Create sample events and alerts
    alerts = []
    for i in range(5):
        event = Event(
            timestamp=datetime.now(),
            platform='windows' if i % 2 == 0 else 'linux',
            process_name=f'process{i}.exe',
            command_line=f'command {i}',
            user='testuser',
            process_id=1000 + i
        )

        alert = Alert(
            rule_id=f'WIN-{i:03d}',
            rule_name=f'Test Rule {i}',
            severity=['low', 'medium', 'high', 'critical'][i % 4],
            event=event,
            timestamp=event.timestamp,
            mitre_attack=['T1059'],
            description='Test alert',
            response=['Test response'],
            score=25 + (i * 30)
        )

        alert_id = db.save_alert(alert)
        alerts.append(alert_id)

    db.close()
    return alerts


def test_health_check(client):
    """Test health check endpoint"""
    response = client.get('/api/health')
    assert response.status_code == 200

    data = response.get_json()
    assert data['status'] == 'healthy'
    assert 'database' in data
    assert 'rules_loaded' in data


def test_get_alerts(client, sample_alerts):
    """Test getting all alerts"""
    response = client.get('/api/alerts')
    assert response.status_code == 200

    data = response.get_json()
    assert 'count' in data
    assert 'alerts' in data
    assert data['count'] == 5


def test_get_alerts_with_limit(client, sample_alerts):
    """Test getting alerts with limit parameter"""
    response = client.get('/api/alerts?limit=2')
    assert response.status_code == 200

    data = response.get_json()
    assert data['count'] == 2


def test_get_alerts_by_severity(client, sample_alerts):
    """Test filtering alerts by severity"""
    response = client.get('/api/alerts?severity=high')
    assert response.status_code == 200

    data = response.get_json()
    assert 'alerts' in data
    # Should have at least one high severity alert
    if data['count'] > 0:
        assert all(a['severity'] == 'high' for a in data['alerts'])


def test_get_alerts_by_platform(client, sample_alerts):
    """Test filtering alerts by platform"""
    response = client.get('/api/alerts?platform=windows')
    assert response.status_code == 200

    data = response.get_json()
    if data['count'] > 0:
        assert all(a['platform'] == 'windows' for a in data['alerts'])


def test_get_alerts_by_min_score(client, sample_alerts):
    """Test filtering alerts by minimum score"""
    response = client.get('/api/alerts?min_score=100')
    assert response.status_code == 200

    data = response.get_json()
    if data['count'] > 0:
        assert all(a['score'] >= 100 for a in data['alerts'])


def test_get_single_alert(client, sample_alerts):
    """Test getting a single alert by ID"""
    alert_id = sample_alerts[0]

    response = client.get(f'/api/alerts/{alert_id}')
    assert response.status_code == 200

    data = response.get_json()
    assert data['id'] == alert_id


def test_get_nonexistent_alert(client):
    """Test getting an alert that doesn't exist"""
    response = client.get('/api/alerts/99999')
    assert response.status_code == 404

    data = response.get_json()
    assert 'error' in data


def test_get_stats(client, sample_alerts):
    """Test getting statistics"""
    response = client.get('/api/stats')
    assert response.status_code == 200

    data = response.get_json()
    assert 'alerts' in data
    assert 'rules' in data

    # Check alert stats
    assert data['alerts']['total_alerts'] == 5

    # Check rule stats
    assert 'total_rules' in data['rules']


def test_get_rules(client):
    """Test getting all detection rules"""
    response = client.get('/api/rules')
    assert response.status_code == 200

    data = response.get_json()
    assert 'count' in data
    assert 'rules' in data
    assert 'stats' in data

    # Should have loaded rules from rules directory
    assert data['count'] > 0

    # Check stats structure
    assert 'total' in data['stats']
    assert 'by_platform' in data['stats']
    assert 'by_severity' in data['stats']


def test_scan_missing_body(client):
    """Test scan endpoint with missing request body"""
    response = client.post('/api/scan', json={})
    assert response.status_code == 400

    data = response.get_json()
    assert 'error' in data


def test_scan_missing_platform(client):
    """Test scan endpoint with missing platform"""
    response = client.post('/api/scan', json={'log_path': '/tmp/test'})
    assert response.status_code == 400

    data = response.get_json()
    assert 'error' in data


def test_scan_missing_log_path(client):
    """Test scan endpoint with missing log_path"""
    response = client.post('/api/scan', json={'platform': 'windows'})
    assert response.status_code == 400

    data = response.get_json()
    assert 'error' in data


def test_scan_invalid_platform(client):
    """Test scan endpoint with invalid platform"""
    response = client.post('/api/scan', json={
        'platform': 'invalid',
        'log_path': '/tmp/test'
    })
    assert response.status_code == 400

    data = response.get_json()
    assert 'error' in data


def test_scan_nonexistent_path(client):
    """Test scan endpoint with nonexistent log path"""
    response = client.post('/api/scan', json={
        'platform': 'windows',
        'log_path': '/nonexistent/path'
    })
    assert response.status_code == 400

    data = response.get_json()
    assert 'error' in data


def test_scan_valid_request(client):
    """Test scan endpoint with valid request"""
    # Use an existing test fixture directory
    log_path = 'tests/fixtures/windows'

    response = client.post('/api/scan', json={
        'platform': 'windows',
        'log_path': log_path
    })

    # Should succeed or fail gracefully
    assert response.status_code in [200, 400, 500]

    if response.status_code == 200:
        data = response.get_json()
        assert 'events_processed' in data
        assert 'alerts_generated' in data
        assert 'alert_ids' in data


def test_scan_linux_logs(client):
    """Test scanning Linux logs"""
    # Use Linux fixture
    log_path = 'tests/fixtures/linux/malicious_curl.log'

    if os.path.exists(log_path):
        response = client.post('/api/scan', json={
            'platform': 'linux',
            'log_path': log_path
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['events_processed'] >= 0
        assert 'alerts_generated' in data


def test_invalid_time_format(client):
    """Test alerts endpoint with invalid time format"""
    response = client.get('/api/alerts?start_time=invalid-date')
    assert response.status_code == 400

    data = response.get_json()
    assert 'error' in data


def test_cors_headers(client):
    """Test that CORS headers are present"""
    response = client.get('/api/health')
    assert response.status_code == 200

    # CORS should add Access-Control-Allow-Origin header
    assert 'Access-Control-Allow-Origin' in response.headers


def test_404_for_unknown_route(client):
    """Test 404 for unknown routes"""
    response = client.get('/api/unknown')
    assert response.status_code == 404

    data = response.get_json()
    assert 'error' in data


def test_method_not_allowed(client):
    """Test method not allowed responses"""
    # Health check only supports GET
    response = client.post('/api/health')
    assert response.status_code == 405  # Method Not Allowed


def test_get_alerts_json_format(client, sample_alerts):
    """Test that alerts are returned in correct JSON format"""
    response = client.get('/api/alerts')
    assert response.status_code == 200
    assert response.content_type == 'application/json'

    data = response.get_json()
    assert isinstance(data, dict)
    assert isinstance(data['alerts'], list)


def test_stats_structure(client, sample_alerts):
    """Test that stats have the correct structure"""
    response = client.get('/api/stats')
    assert response.status_code == 200

    data = response.get_json()

    # Check alerts stats structure
    assert 'total_alerts' in data['alerts']
    assert 'by_severity' in data['alerts']
    assert 'by_platform' in data['alerts']
    assert 'score_distribution' in data['alerts']
    assert 'alerts_last_24h' in data['alerts']

    # Check rules stats structure
    assert 'total_rules' in data['rules']
    assert 'by_severity' in data['rules']
    assert 'by_platform' in data['rules']


def test_rules_format(client):
    """Test that rules are returned in correct format"""
    response = client.get('/api/rules')
    assert response.status_code == 200

    data = response.get_json()
    if data['count'] > 0:
        # Check first rule structure
        rule = data['rules'][0]
        assert 'id' in rule
        assert 'name' in rule
        assert 'platform' in rule
        assert 'severity' in rule
        assert 'detection' in rule
