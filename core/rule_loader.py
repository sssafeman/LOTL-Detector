"""
Rule loader module - validates and loads YAML detection rules
"""
import yaml
import json
import jsonschema
from pathlib import Path
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class Rule:
    """Represents a single detection rule"""

    def __init__(self, rule_dict: Dict[str, Any]):
        self.name = rule_dict['name']
        self.id = rule_dict['id']
        self.platform = rule_dict['platform']
        self.severity = rule_dict['severity']
        self.mitre_attack = rule_dict.get('mitre_attack', [])
        self.description = rule_dict.get('description', '')
        self.detection = rule_dict['detection']
        self.false_positives = rule_dict.get('false_positives', [])
        self.whitelist = rule_dict.get('whitelist', {})
        self.response = rule_dict.get('response', [])

    def __repr__(self):
        return f"Rule(id={self.id}, name={self.name}, platform={self.platform})"

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule back to dictionary"""
        return {
            'name': self.name,
            'id': self.id,
            'platform': self.platform,
            'severity': self.severity,
            'mitre_attack': self.mitre_attack,
            'description': self.description,
            'detection': self.detection,
            'false_positives': self.false_positives,
            'whitelist': self.whitelist,
            'response': self.response
        }


class RuleLoader:
    """Loads and validates detection rules from YAML files"""

    def __init__(self, schema_path: str = "rules/schema.json"):
        """
        Initialize rule loader
        
        Args:
            schema_path: Path to JSON schema file for validation
        """
        self.schema_path = Path(schema_path)
        self.schema = self._load_schema()
        self.rules: List[Rule] = []

    def _load_schema(self) -> Dict[str, Any]:
        """Load JSON schema for rule validation"""
        try:
            with open(self.schema_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Schema file not found: {self.schema_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in schema file: {e}")
            raise

    def validate_rule(self, rule_dict: Dict[str, Any]) -> bool:
        """
        Validate a rule against the JSON schema
        
        Args:
            rule_dict: Rule data as dictionary
            
        Returns:
            True if valid
            
        Raises:
            jsonschema.ValidationError: If rule is invalid
        """
        jsonschema.validate(instance=rule_dict, schema=self.schema)
        return True

    def load_rule_file(self, rule_path: str) -> Rule:
        """
        Load a single rule file
        
        Args:
            rule_path: Path to YAML rule file
            
        Returns:
            Rule object
            
        Raises:
            FileNotFoundError: If rule file doesn't exist
            yaml.YAMLError: If YAML is malformed
            jsonschema.ValidationError: If rule is invalid
        """
        rule_path = Path(rule_path)

        with open(rule_path, 'r') as f:
            rule_dict = yaml.safe_load(f)

        # Validate against schema
        self.validate_rule(rule_dict)

        rule = Rule(rule_dict)
        logger.info(f"Loaded rule: {rule.id} - {rule.name}")
        return rule

    def load_rules_directory(self, rules_dir: str, platform: str = None) -> List[Rule]:
        """
        Load all rules from a directory
        
        Args:
            rules_dir: Directory containing rule files
            platform: Optional filter for specific platform (windows/linux/macos)
            
        Returns:
            List of Rule objects
        """
        rules_dir = Path(rules_dir)
        rules = []

        # Find all .yml and .yaml files
        rule_files = list(rules_dir.glob('**/*.yml')) + list(rules_dir.glob('**/*.yaml'))

        for rule_file in rule_files:
            try:
                rule = self.load_rule_file(rule_file)

                # Filter by platform if specified
                if platform is None or rule.platform == platform:
                    rules.append(rule)

            except Exception as e:
                logger.error(f"Failed to load rule {rule_file}: {e}")
                # Continue loading other rules

        self.rules = rules
        logger.info(f"Loaded {len(rules)} rules from {rules_dir}")
        return rules

    def get_rule_by_id(self, rule_id: str) -> Rule:
        """Get a specific rule by ID"""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        raise ValueError(f"Rule not found: {rule_id}")

    def get_rules_by_platform(self, platform: str) -> List[Rule]:
        """Get all rules for a specific platform"""
        return [rule for rule in self.rules if rule.platform == platform]

    def get_rules_by_severity(self, severity: str) -> List[Rule]:
        """Get all rules of a specific severity"""
        return [rule for rule in self.rules if rule.severity == severity]


# Convenience function
def load_rules(rules_dir: str = "rules", platform: str = None) -> List[Rule]:
    """
    Convenience function to load rules
    
    Args:
        rules_dir: Directory containing rules
        platform: Optional platform filter
        
    Returns:
        List of Rule objects
    """
    loader = RuleLoader()
    return loader.load_rules_directory(rules_dir, platform)
