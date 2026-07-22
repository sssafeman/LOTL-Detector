"""
Detection engine - matches events against rules to generate alerts
"""
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Tuple

from collectors.base import Event
from core.command_analyzer import analyze_command
from core.rule_loader import Rule
from core.scorer import (
    ContextEvidence,
    MatchEvidence,
    Scorer,
    ScoreResult,
)

logger = logging.getLogger(__name__)

_SYSTEM_USERS = frozenset(("SYSTEM", "NT AUTHORITY\\SYSTEM", "ROOT"))
_SUSPICIOUS_SYSTEM_ANOMALIES = frozenset(
    ("encoded_payload", "download_cradle")
)


def normalize_process_name(name: str, platform: str) -> str:
    """
    Extract and normalize the process basename for exact comparison.

    Strips path prefixes, converts to lowercase on Windows, preserves
    case on Linux. Removes trailing whitespace.

    Args:
        name: Process name or full path from event
        platform: 'windows', 'linux', or 'macos'

    Returns:
        Normalized basename (e.g. 'powershell.exe', 'bash')
    """
    if not name:
        return ""
    # Extract basename from path
    basename = os.path.basename(name.strip())
    # Handle both / and \ separators
    basename = basename.replace("\\", "/").split("/")[-1]
    # Windows is case-insensitive, Linux is case-sensitive
    if platform == "windows":
        basename = basename.lower()
    return basename


def _process_names_match(
    expected: str,
    actual: str,
    expected_platform: str,
    actual_platform: str,
) -> bool:
    """Compare process basenames using each value's platform semantics."""
    return normalize_process_name(
        expected, expected_platform
    ) == normalize_process_name(actual, actual_platform)


def _matches_process_name(event: Event, rule: Rule) -> bool:
    """Match the event process against the configured process basename."""
    return _process_names_match(
        rule.detection["process_name"].strip(),
        event.process_name,
        rule.platform,
        event.platform,
    )


def _matches_command_contains(event: Event, rule: Rule) -> bool:
    """Require every configured command fragment to be present."""
    command_line = event.command_line.lower()
    return all(
        item.lower() in command_line
        for item in rule.detection["command_contains"]
    )


def _matches_command_contains_any(event: Event, rule: Rule) -> bool:
    """Require at least one configured command fragment to be present."""
    items = rule.detection["command_contains_any"]
    if not items:
        return False

    command_line = event.command_line.lower()
    return any(item.lower() in command_line for item in items)


def _matches_regex(event_value: str, rule: Rule, criterion: str) -> bool:
    """Match a value with the rule's cached regex or its fallback pattern."""
    compiled = rule.get_compiled_regex(criterion)
    if compiled:
        return compiled.search(event_value) is not None

    pattern = rule.detection[criterion]
    return re.search(pattern, event_value, re.IGNORECASE) is not None


def _matches_command_regex(event: Event, rule: Rule) -> bool:
    """Match the command line against the configured regex."""
    return _matches_regex(event.command_line, rule, "command_regex")


def _matches_parent_process(event: Event, rule: Rule) -> bool:
    """Match the event parent against the configured process basename."""
    if not event.parent_process_name:
        return False

    return _process_names_match(
        rule.detection["parent_process"].strip(),
        event.parent_process_name,
        rule.platform,
        event.platform,
    )


def _matches_user_pattern(event: Event, rule: Rule) -> bool:
    """Match the event user against the configured regex."""
    return _matches_regex(event.user, rule, "user_pattern")


_CriterionMatcher = Callable[[Event, Rule], bool]
_CRITERION_MATCHERS: Tuple[Tuple[str, _CriterionMatcher], ...] = (
    ("process_name", _matches_process_name),
    ("command_contains", _matches_command_contains),
    ("command_contains_any", _matches_command_contains_any),
    ("command_regex", _matches_command_regex),
    ("parent_process", _matches_parent_process),
    ("user_pattern", _matches_user_pattern),
)
_DETECTION_CRITERIA = tuple(
    criterion for criterion, _matcher in _CRITERION_MATCHERS
)


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
            'score_breakdown': (
                self.score_breakdown if self.score_breakdown else None
            ),
            'event': self.event.to_dict()
        }

    def __repr__(self) -> str:
        return (
            f"Alert(rule_id={self.rule_id}, severity={self.severity}, "
            f"score={self.score}, risk_band={self.risk_band}, "
            f"process={self.event.process_name})"
        )


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
            alert = self._match_rule(event, rule)
            if alert is not None:
                alerts.append(alert)

        return alerts

    def _match_rule(self, event: Event, rule: Rule) -> Alert | None:
        """Return an alert when one rule applies to an event."""
        if rule.platform != event.platform:
            return None

        match_result = self._matches_rule_with_evidence(event, rule)
        if match_result is None:
            return None

        if self._is_whitelisted(event, rule):
            logger.debug(
                f"Event whitelisted for rule {rule.id}: "
                f"{event.process_name}"
            )
            return None

        context = self._build_context_evidence(event, rule, match_result)
        score_result = self.scorer.score(rule, match_result, context)
        alert = self._create_alert(event, rule, score_result)
        logger.info(
            f"Alert generated: {rule.id} - {rule.name} "
            f"(score: {score_result.score}, "
            f"risk: {score_result.risk_band}) "
            f"for process {event.process_name}"
        )
        return alert

    @staticmethod
    def _create_alert(
        event: Event,
        rule: Rule,
        score_result: ScoreResult,
    ) -> Alert:
        """Create an alert from a matched rule and its score."""
        return Alert(
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

        logger.info(
            f"Processed {len(events)} events, "
            f"generated {len(all_alerts)} alerts"
        )
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
        configured = self._configured_criteria(detection)
        matched: List[str] = []

        for criterion, matcher in _CRITERION_MATCHERS:
            if criterion not in detection:
                continue
            if not matcher(event, rule):
                return None
            matched.append(criterion)

        configured_unique = tuple(dict.fromkeys(configured))
        matched_unique = tuple(dict.fromkeys(matched))
        semantics = "or" if "command_contains_any" in detection else "and"
        required_missing = (
            semantics == "and"
            and len(matched_unique) < len(configured_unique)
        )

        return MatchEvidence(
            configured_criteria=configured_unique,
            matched_criteria=matched_unique,
            partially_matched_criteria=(),
            semantics=semantics,
            required_criteria_missing=required_missing,
        )

    @staticmethod
    def _configured_criteria(detection: Dict[str, Any]) -> List[str]:
        """List nonempty configured criteria in matching order."""
        configured = [
            criterion
            for criterion in _DETECTION_CRITERIA
            if criterion in detection and detection[criterion]
        ]
        if "process_name" in detection and "process_name" not in configured:
            configured.append("process_name")
        return configured

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
        parent_reason = self._classify_parent_context(event, rule)
        anomalies = tuple(analyze_command(event.command_line))
        user_reason = self._classify_user_context(event, anomalies)

        return ContextEvidence(
            parent_reason=parent_reason,
            user_reason=user_reason,
            command_anomalies=anomalies,
            whitelist_reason="no_match",
            admin_reason="not_admin_context",
        )

    @staticmethod
    def _classify_parent_context(event: Event, rule: Rule) -> str:
        """Classify parent process evidence for scoring."""
        rule_parent = rule.detection.get("parent_process")
        if not event.parent_process_name:
            return "missing_telemetry"
        if not rule_parent:
            return "neutral_lineage"
        if _process_names_match(
            rule_parent,
            event.parent_process_name,
            rule.platform,
            event.platform,
        ):
            return "suspicious_parent_match"
        return "neutral_lineage"

    @staticmethod
    def _classify_user_context(
        event: Event,
        anomalies: Tuple[str, ...],
    ) -> str:
        """Classify suspicious privileged user activity for scoring."""
        if not event.user or event.user.upper() not in _SYSTEM_USERS:
            return "neutral"
        if any(
            anomaly in _SUSPICIOUS_SYSTEM_ANOMALIES
            for anomaly in anomalies
        ):
            return "system_interactive_shell"
        return "neutral"

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

        return (
            self._is_user_whitelisted(event, whitelist)
            or self._is_parent_whitelisted(event, whitelist)
            or self._is_path_whitelisted(event, whitelist)
        )

    @staticmethod
    def _is_user_whitelisted(
        event: Event,
        whitelist: Dict[str, Any],
    ) -> bool:
        """Check the whitelist's case insensitive user entries."""
        users = whitelist.get("users")
        if not users:
            return False

        event_user = event.user.lower()
        if any(user.lower() == event_user for user in users):
            logger.debug(f"Event whitelisted by user: {event.user}")
            return True
        return False

    @staticmethod
    def _is_parent_whitelisted(
        event: Event,
        whitelist: Dict[str, Any],
    ) -> bool:
        """Check the whitelist's normalized parent process entries."""
        parents = whitelist.get("parent_processes")
        if not parents or not event.parent_process_name:
            return False

        actual_parent = normalize_process_name(
            event.parent_process_name, event.platform
        )
        if any(
            normalize_process_name(parent, event.platform) == actual_parent
            for parent in parents
        ):
            logger.debug(
                "Event whitelisted by parent process: "
                f"{event.parent_process_name}"
            )
            return True
        return False

    @staticmethod
    def _is_path_whitelisted(
        event: Event,
        whitelist: Dict[str, Any],
    ) -> bool:
        """Check whether the working directory contains a listed path."""
        paths = whitelist.get("paths")
        if not paths or not event.working_directory:
            return False

        working_directory = event.working_directory.lower()
        if any(path.lower() in working_directory for path in paths):
            logger.debug(
                f"Event whitelisted by path: {event.working_directory}"
            )
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
        platform_counts = {}
        for rule in self.rules:
            severity_counts[rule.severity] = (
                severity_counts.get(rule.severity, 0) + 1
            )
            platform_counts[rule.platform] = (
                platform_counts.get(rule.platform, 0) + 1
            )

        return {
            'total_rules': len(self.rules),
            'by_severity': severity_counts,
            'by_platform': platform_counts
        }
