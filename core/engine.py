"""
Detection engine - matches events against rules to generate alerts
"""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any
from collectors.base import Event
from core.rule_loader import Rule
from core.scorer import Scorer
import logging

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """
    Represents a detection alert when an event matches a rule
    """
    rule_id: str
    rule_name: str
    severity: str
    event: Event
    timestamp: datetime
    mitre_attack: List[str]
    description: str
    response: List[str]
    score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for storage/API"""
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat(),
            'mitre_attack': self.mitre_attack,
            'description': self.description,
            'response': self.response,
            'score': self.score,
            'event': self.event.to_dict()
        }

    def __repr__(self):
        return f"Alert(rule_id={self.rule_id}, severity={self.severity}, score={self.score}, process={self.event.process_name})"


class DetectionEngine:
    """
    Core detection engine that matches events against rules
    """

    def __init__(self, rules: List[Rule]):
        """
        Initialize detection engine with rules

        Args:
            rules: List of Rule objects to match against
        """
        self.rules = rules
        self.scorer = Scorer()
        logger.info(f"Detection engine initialized with {len(rules)} rules")

    def match_event(self, event: Event) -> List[Alert]:
        """
        Match a single event against all loaded rules

        Args:
            event: Event object to check

        Returns:
            List of Alert objects (can be multiple if event matches multiple rules)
        """
        alerts = []

        for rule in self.rules:
            # Skip if platforms don't match
            if rule.platform != event.platform:
                continue

            # Check if event matches the rule
            if self._matches_rule(event, rule):
                # Check whitelist - if whitelisted, skip this rule
                if self._is_whitelisted(event, rule):
                    logger.debug(f"Event whitelisted for rule {rule.id}: {event.process_name}")
                    continue

                # Calculate score
                score = self.scorer.score_alert(rule, event)

                # Create alert
                alert = Alert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    event=event,
                    timestamp=event.timestamp,
                    mitre_attack=rule.mitre_attack,
                    description=rule.description,
                    response=rule.response,
                    score=score
                )
                alerts.append(alert)
                logger.info(f"Alert generated: {rule.id} - {rule.name} (score: {score}) for process {event.process_name}")

        return alerts

    def match_events(self, events: List[Event]) -> List[Alert]:
        """
        Match multiple events against all rules

        Args:
            events: List of Event objects

        Returns:
            List of all generated alerts
        """
        all_alerts = []

        for event in events:
            alerts = self.match_event(event)
            all_alerts.extend(alerts)

        logger.info(f"Processed {len(events)} events, generated {len(all_alerts)} alerts")
        return all_alerts

    def _matches_rule(self, event: Event, rule: Rule) -> bool:
        """
        Check if an event matches a rule's detection criteria

        Args:
            event: Event to check
            rule: Rule to match against

        Returns:
            True if event matches the rule
        """
        detection = rule.detection

        # Check process name if specified
        if 'process_name' in detection:
            expected_process = detection['process_name'].lower()
            actual_process = event.process_name.lower()

            if expected_process not in actual_process:
                return False

        # Check command_contains (ALL items must be present - AND logic)
        if 'command_contains' in detection:
            command_line_lower = event.command_line.lower()

            for item in detection['command_contains']:
                if item.lower() not in command_line_lower:
                    return False

        # Check command_regex if specified
        if 'command_regex' in detection:
            pattern = detection['command_regex']
            if not re.search(pattern, event.command_line, re.IGNORECASE):
                return False

        # Check parent process if specified
        if 'parent_process' in detection:
            if not event.parent_process_name:
                return False

            expected_parent = detection['parent_process'].lower()
            actual_parent = event.parent_process_name.lower()

            if expected_parent not in actual_parent:
                return False

        # Check user pattern if specified
        if 'user_pattern' in detection:
            pattern = detection['user_pattern']
            if not re.search(pattern, event.user, re.IGNORECASE):
                return False

        # All checks passed
        return True

    def _is_whitelisted(self, event: Event, rule: Rule) -> bool:
        """
        Check if an event is whitelisted for a specific rule

        Args:
            event: Event to check
            rule: Rule with potential whitelist

        Returns:
            True if event is whitelisted (should NOT generate alert)
        """
        whitelist = rule.whitelist

        if not whitelist:
            return False

        # Check whitelisted users
        if 'users' in whitelist and whitelist['users']:
            for whitelisted_user in whitelist['users']:
                if whitelisted_user.lower() == event.user.lower():
                    logger.debug(f"Event whitelisted by user: {event.user}")
                    return True

        # Check whitelisted parent processes
        if 'parent_processes' in whitelist and whitelist['parent_processes']:
            if event.parent_process_name:
                for whitelisted_parent in whitelist['parent_processes']:
                    if whitelisted_parent.lower() in event.parent_process_name.lower():
                        logger.debug(f"Event whitelisted by parent process: {event.parent_process_name}")
                        return True

        # Check whitelisted paths
        if 'paths' in whitelist and whitelist['paths']:
            if event.working_directory:
                for whitelisted_path in whitelist['paths']:
                    if whitelisted_path.lower() in event.working_directory.lower():
                        logger.debug(f"Event whitelisted by path: {event.working_directory}")
                        return True

        return False

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about loaded rules

        Returns:
            Dictionary with rule statistics
        """
        if not self.rules:
            return {'total_rules': 0}

        severity_counts = {}
        for rule in self.rules:
            severity_counts[rule.severity] = severity_counts.get(rule.severity, 0) + 1

        platform_counts = {}
        for rule in self.rules:
            platform_counts[rule.platform] = platform_counts.get(rule.platform, 0) + 1

        return {
            'total_rules': len(self.rules),
            'by_severity': severity_counts,
            'by_platform': platform_counts
        }
