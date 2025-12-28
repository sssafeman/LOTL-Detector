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