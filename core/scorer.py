"""
Alert scoring module - calculates risk scores for detected alerts
"""
from typing import Dict, Any, List
from core.rule_loader import Rule
from collectors.base import Event
import logging

logger = logging.getLogger(__name__)


class Scorer:
    """
    Calculates risk scores for alerts based on severity and context
    """

    # Base scores by severity level
    SEVERITY_SCORES = {
        'critical': 100,
        'high': 75,
        'medium': 50,
        'low': 25
    }

    # Bonus points
    DETECTION_CRITERION_BONUS = 20  # Per criterion beyond process_name
    PARENT_PROCESS_BONUS = 15       # When parent process context exists
    MITRE_TECHNIQUE_BONUS = 10      # Per MITRE ATT&CK technique

    # Score limits
    MAX_SCORE = 150
    MIN_SCORE = 0

    def __init__(self):
        """Initialize the scorer"""
        logger.debug("Scorer initialized")

    def score_alert(self, rule: Rule, event: Event) -> int:
        """
        Calculate a risk score for an alert

        Args:
            rule: The rule that was matched
            event: The event that triggered the rule

        Returns:
            Integer score between 0 and 150
        """
        # Start with base severity score
        score = self.SEVERITY_SCORES.get(rule.severity, 0)

        # Count detection criteria beyond process_name
        detection_criteria_count = self._count_detection_criteria(rule)
        score += detection_criteria_count * self.DETECTION_CRITERION_BONUS

        # Bonus for parent process context
        if event.parent_process_name:
            score += self.PARENT_PROCESS_BONUS
            logger.debug(f"Adding parent process bonus: +{self.PARENT_PROCESS_BONUS}")

        # Bonus for MITRE ATT&CK techniques
        mitre_count = len(rule.mitre_attack) if rule.mitre_attack else 0
        mitre_bonus = mitre_count * self.MITRE_TECHNIQUE_BONUS
        score += mitre_bonus
        if mitre_count > 0:
            logger.debug(f"Adding MITRE bonus for {mitre_count} techniques: +{mitre_bonus}")

        # Ensure score is within bounds and is an integer
        score = max(self.MIN_SCORE, min(score, self.MAX_SCORE))

        logger.info(f"Alert score calculated: {score} for rule {rule.id}")
        return int(score)

    def _count_detection_criteria(self, rule: Rule) -> int:
        """
        Count detection criteria beyond process_name

        Args:
            rule: The rule to analyze

        Returns:
            Count of additional detection criteria
        """
        detection = rule.detection
        count = 0

        # Count each type of detection criterion (excluding process_name)
        if 'command_contains' in detection and detection['command_contains']:
            count += 1
            logger.debug("Detection criterion found: command_contains")

        if 'command_regex' in detection and detection['command_regex']:
            count += 1
            logger.debug("Detection criterion found: command_regex")

        if 'parent_process' in detection and detection['parent_process']:
            count += 1
            logger.debug("Detection criterion found: parent_process")

        if 'user_pattern' in detection and detection['user_pattern']:
            count += 1
            logger.debug("Detection criterion found: user_pattern")

        logger.debug(f"Total detection criteria beyond process_name: {count}")
        return count

    def get_severity_thresholds(self) -> Dict[str, int]:
        """
        Get the base severity score thresholds

        Returns:
            Dictionary mapping severity levels to base scores
        """
        return self.SEVERITY_SCORES.copy()

    def interpret_score(self, score: int) -> str:
        """
        Provide a human-readable interpretation of a score

        Args:
            score: The risk score

        Returns:
            String interpretation of the score
        """
        if score >= 120:
            return "Critical - Immediate action required"
        elif score >= 90:
            return "High - Prioritize investigation"
        elif score >= 60:
            return "Medium - Review when possible"
        elif score >= 30:
            return "Low - Monitor for patterns"
        else:
            return "Informational - Low priority"
