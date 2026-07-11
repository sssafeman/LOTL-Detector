"""
Alert scoring module v2.

Multiplicative severity and confidence model.
Score = clamp(round(severity_subscore * (0.25 + 0.75 * confidence/100) * 1.5), 0, 150)

Severity (rule-defined, potential impact) and confidence (event-derived,
match strength) are separated. MITRE technique count contributes zero
to the score. Parent process existence alone contributes nothing.

The scorer consumes pre-evaluated evidence. It does not re-run rule
matching, query directories, or determine business hours. Those belong
in the detector or context enrichment layer.
"""
from dataclasses import dataclass, field
from math import floor
from typing import List, Dict, Any, Tuple, Optional
from core.rule_loader import Rule
from collectors.base import Event
from core.command_analyzer import analyze_command
import logging

logger = logging.getLogger(__name__)

# Severity subscores: rule-defined potential impact
SEVERITY_SUBSCORES: Dict[str, int] = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}

# Non-linear criteria strength deltas.
# The second independent criterion provides more corroboration than the fourth.
CRITERIA_DELTAS: Dict[int, int] = {
    0: 0,
    1: 5,
    2: 16,
    3: 25,
    4: 30,
}

# Command anomaly indicator weights (additive, capped)
COMMAND_ANOMALY_WEIGHTS: Dict[str, int] = {
    "encoded_payload": 12,
    "download_cradle": 10,
    "obfuscation": 8,
    "unusual_path": 5,
    "suspicious_flags": 5,
    "high_entropy_argument": 4,
}

CONFIDENCE_BASE = 35
COMMAND_ANOMALY_CAP = 25
CONFIDENCE_MIN = 0
CONFIDENCE_MAX = 100
SCORE_MIN = 0
SCORE_MAX = 150
SCORING_VERSION = 2

# Parent context deltas: -5 to +15
PARENT_DELTAS: Dict[str, int] = {
    "missing_telemetry": 0,
    "suspicious_parent_match": 15,
    "anomalous_lineage": 8,
    "neutral_lineage": 0,
    "common_benign_lineage": -5,
}

# User context deltas: 0 to +15
USER_DELTAS: Dict[str, int] = {
    "system_interactive_shell": 15,
    "non_admin_privileged_tool": 12,
    "unexpected_process_owner": 8,
    "unusual_user_baseline": 5,
    "neutral": 0,
    "missing_telemetry": 0,
}

# Whitelist adjacency deltas: -30 to 0
WHITELIST_DELTAS: Dict[str, int] = {
    "exact_match": -30,
    "high_similarity": -20,
    "moderate_similarity": -10,
    "no_match": 0,
    "not_evaluated": 0,
}

# Admin context deltas: -20 to 0
ADMIN_DELTAS: Dict[str, int] = {
    "full_approved_context": -20,
    "three_conditions": -10,
    "two_conditions": -5,
    "not_admin_context": 0,
    "not_evaluated": 0,
}


class InvalidRuleSeverity(ValueError):
    """Raised when a rule has an unrecognized severity level."""
    pass


@dataclass(frozen=True)
class MatchEvidence:
    """Evidence from the detection engine about which criteria matched."""
    configured_criteria: Tuple[str, ...]
    matched_criteria: Tuple[str, ...]
    partially_matched_criteria: Tuple[str, ...]
    semantics: str  # "and" or "or"
    required_criteria_missing: bool


@dataclass(frozen=True)
class ContextEvidence:
    """Context enrichment evidence from the event and environment."""
    parent_reason: str
    user_reason: str
    command_anomalies: Tuple[str, ...]
    whitelist_reason: str
    admin_reason: str


@dataclass
class ScoreResult:
    """Complete scoring result with breakdown."""
    score: int
    risk_band: str
    severity_subscore: int
    confidence_subscore: int
    scoring_version: int
    breakdown: Dict[str, Any]


class Scorer:
    """
    Calculates risk scores using a multiplicative severity and confidence model.

    v1 compatibility: score_alert(rule, event) returns just the integer score
    using neutral/default context evidence. Use score(rule, match, context)
    for the full v2 breakdown.
    """

    def score(
        self,
        rule: Rule,
        match: MatchEvidence,
        context: ContextEvidence,
    ) -> ScoreResult:
        """
        Calculate a full risk score with breakdown.

        Args:
            rule: The matched rule
            match: Detection evidence from the engine
            context: Context enrichment evidence

        Returns:
            ScoreResult with score, risk_band, subscores, and breakdown
        """
        severity = self._severity_subscore(rule.severity)
        factors: List[Dict[str, Any]] = []

        # 1. Detection criteria strength (non-linear)
        criteria_delta = self._criteria_delta(match)
        matched_set = sorted(set(match.matched_criteria))
        configured_set = sorted(set(match.configured_criteria))
        factors.append(self._factor(
            name="detection_criteria",
            delta=criteria_delta,
            reason=f"{len(matched_set)}_criteria_matched",
            evidence={
                "configured": configured_set,
                "matched": matched_set,
            },
        ))

        # 2. Parent and child process consistency
        parent_delta = PARENT_DELTAS.get(context.parent_reason, 0)
        factors.append(self._factor(
            "parent_context",
            parent_delta,
            context.parent_reason,
        ))

        # 3. User context
        user_delta = USER_DELTAS.get(context.user_reason, 0)
        factors.append(self._factor(
            "user_context",
            user_delta,
            context.user_reason,
        ))

        # 4. Command line anomaly indicators (additive, capped at 25)
        anomaly_names = sorted(set(context.command_anomalies))
        anomaly_raw = sum(
            COMMAND_ANOMALY_WEIGHTS.get(name, 0) for name in anomaly_names
        )
        anomaly_delta = min(anomaly_raw, COMMAND_ANOMALY_CAP)
        factors.append(self._factor(
            name="command_anomaly",
            delta=anomaly_delta,
            reason=(
                "command_anomalies_detected"
                if anomaly_names
                else "none_detected"
            ),
            evidence={
                "indicators": anomaly_names,
                "uncapped_delta": anomaly_raw,
                "cap": COMMAND_ANOMALY_CAP,
            },
        ))

        # 5. Whitelist adjacency
        whitelist_delta = WHITELIST_DELTAS.get(context.whitelist_reason, 0)
        factors.append(self._factor(
            "whitelist_adjacency",
            whitelist_delta,
            context.whitelist_reason,
        ))

        # 6. Admin context (suppressed if user anomaly is positive)
        if user_delta > 0:
            admin_delta = 0
            admin_reason = "not_applied_due_to_user_anomaly"
        else:
            admin_delta = ADMIN_DELTAS.get(context.admin_reason, 0)
            admin_reason = context.admin_reason
        factors.append(self._factor(
            "admin_context",
            admin_delta,
            admin_reason,
        ))

        # 7. Partial match penalty
        partial_delta, partial_reason = self._partial_match_delta(match)
        factors.append(self._factor(
            "partial_match",
            partial_delta,
            partial_reason,
            {
                "partially_matched": sorted(
                    set(match.partially_matched_criteria)
                )
            },
        ))

        # Calculate raw and clamped confidence
        raw_confidence = CONFIDENCE_BASE + sum(
            f["delta"] for f in factors
        )
        confidence = self._clamp(raw_confidence, CONFIDENCE_MIN, CONFIDENCE_MAX)

        # Multiplicative formula: severity * confidence_multiplier * scale
        confidence_multiplier = 0.25 + 0.75 * confidence / 100.0
        raw_score = severity * confidence_multiplier * 1.5
        rounded_score = floor(raw_score + 0.5)  # round half up, not banker's
        final_score = self._clamp(rounded_score, SCORE_MIN, SCORE_MAX)

        breakdown = {
            "severity": {
                "rule_severity": rule.severity,
                "subscore": severity,
                "mitre_techniques": list(rule.mitre_attack) if rule.mitre_attack else [],
                "mitre_contribution": 0,
            },
            "confidence": {
                "base": CONFIDENCE_BASE,
                "raw": raw_confidence,
                "clamped": confidence,
                "factors": factors,
            },
            "combination": {
                "formula_version": "severity_confidence_v2",
                "severity": severity,
                "confidence": confidence,
                "confidence_multiplier": round(confidence_multiplier, 6),
                "scale": 1.5,
                "raw_score": round(raw_score, 6),
                "rounded_score": final_score,
            },
        }

        result = ScoreResult(
            score=final_score,
            risk_band=self._risk_band(final_score),
            severity_subscore=severity,
            confidence_subscore=confidence,
            scoring_version=SCORING_VERSION,
            breakdown=breakdown,
        )

        logger.info(
            f"v2 score: {final_score} (severity={severity}, "
            f"confidence={confidence}, risk_band={result.risk_band}) "
            f"for rule {rule.id}"
        )
        return result

    def score_value(
        self,
        rule: Rule,
        match: MatchEvidence,
        context: ContextEvidence,
    ) -> int:
        """Compatibility wrapper: returns only the integer score."""
        return self.score(rule, match, context).score

    # v1 backward compatibility method
    def score_alert(self, rule: Rule, event: Event) -> int:
        """
        v1 compatibility: calculate score from rule and event alone.

        Uses neutral/default context evidence. For full v2 breakdown,
        use score() with MatchEvidence and ContextEvidence.

        Args:
            rule: The matched rule
            event: The triggering event

        Returns:
            Integer score 0-150
        """
        # Build minimal match evidence from the rule's detection criteria
        configured = self._get_configured_criteria(rule)
        # Assume all configured criteria matched (alert fired)
        matched = tuple(configured)
        match = MatchEvidence(
            configured_criteria=tuple(configured),
            matched_criteria=matched,
            partially_matched_criteria=(),
            semantics="and",
            required_criteria_missing=False,
        )

        # Build context evidence from the event
        anomalies = tuple(analyze_command(event.command_line))
        parent_reason = "suspicious_parent_match" if (
            rule.detection.get("parent_process")
            and event.parent_process_name
            and rule.detection["parent_process"].lower()
            in event.parent_process_name.lower()
        ) else ("neutral_lineage" if event.parent_process_name else "missing_telemetry")

        # Check if event was whitelisted (shouldn't reach here, but defensive)
        whitelist_reason = "no_match"

        # SYSTEM user with encoded commands is suspicious
        user_reason = "neutral"
        if event.user and event.user.upper() in ("SYSTEM", "NT AUTHORITY\\SYSTEM"):
            # SYSTEM running interactive commands is suspicious
            if any(a in anomalies for a in ("encoded_payload", "download_cradle")):
                user_reason = "system_interactive_shell"

        context = ContextEvidence(
            parent_reason=parent_reason,
            user_reason=user_reason,
            command_anomalies=anomalies,
            whitelist_reason=whitelist_reason,
            admin_reason="not_admin_context",
        )

        return self.score_value(rule, match, context)

    def _severity_subscore(self, severity_name: str) -> int:
        """Map rule severity to numeric subscore."""
        normalized = severity_name.lower().strip()
        if normalized not in SEVERITY_SUBSCORES:
            raise InvalidRuleSeverity(
                f"Unknown severity: {severity_name}. "
                f"Valid: {list(SEVERITY_SUBSCORES.keys())}"
            )
        return SEVERITY_SUBSCORES[normalized]

    def _criteria_delta(self, match: MatchEvidence) -> int:
        """Get non-linear delta based on number of matched criteria."""
        matched_count = min(len(set(match.matched_criteria)), 4)
        return CRITERIA_DELTAS[matched_count]

    def _partial_match_delta(
        self, match: MatchEvidence
    ) -> Tuple[int, str]:
        """Calculate partial match penalty and reason code."""
        if match.semantics == "and" and match.required_criteria_missing:
            return -15, "required_criteria_missing"

        configured_count = len(set(match.configured_criteria))
        matched_count = len(set(match.matched_criteria))

        if (
            match.semantics == "or"
            and configured_count >= 3
            and matched_count == 1
        ):
            return -8, "single_branch_of_broad_or"

        if match.partially_matched_criteria:
            return -5, "criterion_partially_matched"

        return 0, "full_rule_match"

    def _get_configured_criteria(self, rule: Rule) -> List[str]:
        """Extract list of configured detection criteria from a rule."""
        detection = rule.detection
        criteria = []
        for key in (
            "process_name",
            "command_contains",
            "command_contains_any",
            "command_regex",
            "parent_process",
            "user_pattern",
        ):
            if key in detection and detection[key]:
                criteria.append(key)
        return criteria

    @staticmethod
    def _factor(
        name: str,
        delta: int,
        reason: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build a factor dict for the breakdown."""
        return {
            "name": name,
            "delta": delta,
            "reason": reason,
            "evidence": evidence or {},
        }

    @staticmethod
    def _risk_band(score: int) -> str:
        """Map final score to risk band label."""
        if score >= 120:
            return "critical"
        if score >= 90:
            return "high"
        if score >= 60:
            return "medium"
        return "low"

    @staticmethod
    def _clamp(value: int, minimum: int, maximum: int) -> int:
        """Clamp value to [minimum, maximum]."""
        return max(minimum, min(maximum, value))

    # v1 compatibility: keep old constants for any code that references them
    SEVERITY_SCORES = SEVERITY_SUBSCORES
    DETECTION_CRITERION_BONUS = 20
    PARENT_PROCESS_BONUS = 15
    MITRE_TECHNIQUE_BONUS = 10
    MAX_SCORE = SCORE_MAX
    MIN_SCORE = SCORE_MIN

    def get_severity_thresholds(self) -> Dict[str, int]:
        """Get severity subscore thresholds (v1 compat)."""
        return SEVERITY_SUBSCORES.copy()

    def interpret_score(self, score: int) -> str:
        """Provide human-readable interpretation of a score (v1 compat)."""
        if score >= 120:
            return "Critical: Immediate action required"
        elif score >= 90:
            return "High: Prioritize investigation"
        elif score >= 60:
            return "Medium: Review when possible"
        elif score >= 30:
            return "Low: Monitor for patterns"
        else:
            return "Informational: Low priority"