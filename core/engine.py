"""
Detection engine - matches events against rules to generate alerts
"""
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Tuple
from collectors.base import Event
from core.rule_loader import Rule
from core.scorer import (
    Scorer, MatchEvidence, ContextEvidence, ScoreResult, SCORING_VERSION,
)
from core.command_analyzer import analyze_command
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
    # v2 scoring fields
    risk_band: str = "low"
    severity_subscore: int = 0
    confidence_subscore: int = 0
    scoring_version: int = 1
    score_breakdown: Dict[str, Any] = field(default_factory=dict)

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
            'risk_band': self.risk_band,
            'scoring_version': self.scoring_version,
            'severity_subscore': self.severity_subscore,
            'confidence_subscore': self.confidence_subscore,
            'score_breakdown': self.score_breakdown if self.score_breakdown else None,
            'event': self.event.to_dict()
        }

    def __repr__(self):
        return f"Alert(rule_id={self.rule_id}, severity={self.severity}, score={self.score}, risk_band={self.risk_band}, process={self.event.process_name})"


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

            # Check if event matches the rule and get match evidence
            match_result = self._matches_rule_with_evidence(event, rule)
            if match_result is not None:
                # Check whitelist - if whitelisted, skip this rule
                if self._is_whitelisted(event, rule):
                    logger.debug(f"Event whitelisted for rule {rule.id}: {event.process_name}")
                    continue

                # Build context evidence from the event
                context = self._build_context_evidence(event, rule, match_result)

                # Calculate v2 score with full evidence
                score_result = self.scorer.score(rule, match_result, context)

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
                    score=score_result.score,
                    risk_band=score_result.risk_band,
                    severity_subscore=score_result.severity_subscore,
                    confidence_subscore=score_result.confidence_subscore,
                    scoring_version=score_result.scoring_version,
                    score_breakdown=score_result.breakdown,
                )
                alerts.append(alert)
                logger.info(f"Alert generated: {rule.id} - {rule.name} (score: {score_result.score}, risk: {score_result.risk_band}) for process {event.process_name}")

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
        return self._matches_rule_with_evidence(event, rule) is not None

    def _matches_rule_with_evidence(
        self, event: Event, rule: Rule
    ) -> MatchEvidence | None:
        """
        Check if an event matches a rule and return match evidence.

        Args:
            event: Event to check
            rule: Rule to match against

        Returns:
            MatchEvidence if matched, None if not matched
        """
        detection = rule.detection
        configured: List[str] = []
        matched: List[str] = []
        partially_matched: List[str] = []
        has_or_semantics = False

        # Track configured criteria
        for key in (
            "process_name", "command_contains", "command_contains_any",
            "command_regex", "parent_process", "user_pattern",
        ):
            if key in detection and detection[key]:
                configured.append(key)

        # Check process name if specified
        if 'process_name' in detection:
            configured.append("process_name") if "process_name" not in configured else None
            expected_process = detection['process_name'].lower()
            actual_process = event.process_name.lower()

            if expected_process not in actual_process:
                return None
            matched.append("process_name")

        # Check command_contains (ALL items must be present - AND logic)
        if 'command_contains' in detection:
            command_line_lower = event.command_line.lower()

            for item in detection['command_contains']:
                if item.lower() not in command_line_lower:
                    # AND logic: one missing means no match
                    partially_matched.append("command_contains")
                    return None
            matched.append("command_contains")

        # Check command_contains_any (ANY item present - OR logic)
        if 'command_contains_any' in detection:
            has_or_semantics = True
            command_line_lower = event.command_line.lower()
            items = detection['command_contains_any']

            if not items:
                return None

            if any(item.lower() in command_line_lower for item in items):
                matched.append("command_contains_any")
            else:
                return None

        # Check command_regex if specified
        if 'command_regex' in detection:
            pattern = detection['command_regex']
            if not re.search(pattern, event.command_line, re.IGNORECASE):
                return None
            matched.append("command_regex")

        # Check parent process if specified
        if 'parent_process' in detection:
            if not event.parent_process_name:
                return None

            expected_parent = detection['parent_process'].lower()
            actual_parent = event.parent_process_name.lower()

            if expected_parent not in actual_parent:
                return None
            matched.append("parent_process")

        # Check user pattern if specified
        if 'user_pattern' in detection:
            pattern = detection['user_pattern']
            if not re.search(pattern, event.user, re.IGNORECASE):
                return None
            matched.append("user_pattern")

        # All checks passed. Build and return match evidence.
        # Remove duplicates while preserving order
        configured_unique = list(dict.fromkeys(configured))
        matched_unique = list(dict.fromkeys(matched))

        semantics = "or" if has_or_semantics else "and"
        required_missing = (
            semantics == "and"
            and len(matched_unique) < len(configured_unique)
        )

        return MatchEvidence(
            configured_criteria=tuple(configured_unique),
            matched_criteria=tuple(matched_unique),
            partially_matched_criteria=tuple(partially_matched),
            semantics=semantics,
            required_criteria_missing=required_missing,
        )

    def _build_context_evidence(
        self,
        event: Event,
        rule: Rule,
        match: MatchEvidence,
    ) -> ContextEvidence:
        """
        Build context enrichment evidence from the event for scoring.

        Determines parent context, user context, command anomalies,
        whitelist adjacency, and admin context classifications.
        """
        # Parent context classification
        parent_reason = "missing_telemetry"
        rule_parent = rule.detection.get("parent_process")
        if rule_parent and event.parent_process_name:
            if rule_parent.lower() in event.parent_process_name.lower():
                parent_reason = "suspicious_parent_match"
            else:
                parent_reason = "neutral_lineage"
        elif event.parent_process_name:
            parent_reason = "neutral_lineage"

        # User context classification
        user_reason = "neutral"

        # Command anomaly indicators
        anomalies = tuple(analyze_command(event.command_line))

        # SYSTEM/root running interactive commands with anomalies is suspicious
        if event.user:
            user_upper = event.user.upper()
            if user_upper in ("SYSTEM", "NT AUTHORITY\\SYSTEM", "ROOT"):
                if any(a in ("encoded_payload", "download_cradle") for a in anomalies):
                    user_reason = "system_interactive_shell"

        # Whitelist adjacency (alert passed whitelist check, so no exact match)
        whitelist_reason = "no_match"

        # Admin context (not evaluated in this version)
        admin_reason = "not_admin_context"

        return ContextEvidence(
            parent_reason=parent_reason,
            user_reason=user_reason,
            command_anomalies=anomalies,
            whitelist_reason=whitelist_reason,
            admin_reason=admin_reason,
        )

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
