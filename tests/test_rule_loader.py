"""
Tests for rule loader
"""
import pytest
import yaml
import json
from pathlib import Path
from core.rule_loader import RuleLoader, Rule
import jsonschema


def test_rule_loader_init():
    """Test rule loader initializes correctly"""
    loader = RuleLoader()
    assert loader.schema is not None
    assert isinstance(loader.schema, dict)


def test_load_example_rule():
    """Test loading the certutil example rule"""
    loader = RuleLoader()
    rule = loader.load_rule_file("rules/windows/certutil_download.yml")
    
    assert rule.id == "WIN-001"
    assert rule.name == "Certutil Download Suspicious File"
    assert rule.platform == "windows"
    assert rule.severity == "high"
    assert "T1105" in rule.mitre_attack


def test_invalid_rule_fails_validation(tmp_path):
    """Test that invalid rules are rejected"""
    # Create invalid rule (missing required fields)
    invalid_rule = {
        "name": "Test Rule",
        # Missing id, platform, severity, detection
    }
    
    rule_file = tmp_path / "invalid.yml"
    with open(rule_file, 'w') as f:
        yaml.dump(invalid_rule, f)
    
    loader = RuleLoader()
    with pytest.raises(jsonschema.ValidationError):
        loader.load_rule_file(rule_file)


def test_rule_to_dict():
    """Test Rule object can convert back to dict"""
    rule_dict = {
        'name': 'Test',
        'id': 'WIN-999',
        'platform': 'windows',
        'severity': 'low',
        'detection': {'process_name': 'test.exe'}
    }
    
    rule = Rule(rule_dict)
    result = rule.to_dict()
    
    assert result['name'] == 'Test'
    assert result['id'] == 'WIN-999'


def test_load_rules_directory():
    """Test loading all rules from directory"""
    loader = RuleLoader()
    rules = loader.load_rules_directory("rules")
    
    # Should load at least the example rule
    assert len(rules) >= 1
    assert any(r.id == "WIN-001" for r in rules)


def test_get_rule_by_id():
    """Test retrieving specific rule by ID"""
    loader = RuleLoader()
    loader.load_rules_directory("rules")
    
    rule = loader.get_rule_by_id("WIN-001")
    assert rule.name == "Certutil Download Suspicious File"


def test_filter_by_platform():
    """Test filtering rules by platform"""
    loader = RuleLoader()
    loader.load_rules_directory("rules")

    windows_rules = loader.get_rules_by_platform("windows")
    assert all(r.platform == "windows" for r in windows_rules)


def test_all_windows_rules_loaded():
    """Test that all 6 Windows rules are loaded correctly"""
    loader = RuleLoader()
    loader.load_rules_directory("rules")

    windows_rules = loader.get_rules_by_platform("windows")

    # Verify we have exactly 6 Windows rules
    assert len(windows_rules) == 6

    # Verify all expected rule IDs are present
    expected_ids = ["WIN-001", "WIN-002", "WIN-003", "WIN-004", "WIN-005", "WIN-006"]
    loaded_ids = [rule.id for rule in windows_rules]

    for expected_id in expected_ids:
        assert expected_id in loaded_ids, f"Rule {expected_id} not found"

    # Verify specific rules
    rule_map = {rule.id: rule for rule in windows_rules}

    # WIN-001: Certutil
    assert rule_map["WIN-001"].name == "Certutil Download Suspicious File"
    assert rule_map["WIN-001"].severity == "high"

    # WIN-002: PowerShell Encoded
    assert rule_map["WIN-002"].name == "PowerShell Encoded Command Execution"
    assert rule_map["WIN-002"].severity == "high"
    assert "T1059.001" in rule_map["WIN-002"].mitre_attack

    # WIN-003: WMI Lateral Movement
    assert rule_map["WIN-003"].name == "WMI Lateral Movement"
    assert rule_map["WIN-003"].severity == "high"
    assert "T1047" in rule_map["WIN-003"].mitre_attack

    # WIN-004: Regsvr32
    assert rule_map["WIN-004"].name == "Regsvr32 Application Whitelisting Bypass"
    assert rule_map["WIN-004"].severity == "high"
    assert "T1218.010" in rule_map["WIN-004"].mitre_attack

    # WIN-005: BITSAdmin
    assert rule_map["WIN-005"].name == "BITSAdmin Download Abuse"
    assert rule_map["WIN-005"].severity == "high"
    assert "T1197" in rule_map["WIN-005"].mitre_attack

    # WIN-006: MSHTA
    assert rule_map["WIN-006"].name == "MSHTA Suspicious Script Execution"
    assert rule_map["WIN-006"].severity == "medium"
    assert "T1218.005" in rule_map["WIN-006"].mitre_attack