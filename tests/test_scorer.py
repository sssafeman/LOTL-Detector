"""
Tests for v2 alert scoring system.

Tests the multiplicative severity and confidence model.
Formula: score = clamp(round(severity * (0.25 + 0.75 * confidence/100) * 1.5), 0, 150)
"""
import pytest
from datetime import datetime
from core.scorer import (
    Scorer, MatchEvidence, ContextEvidence,
    SEVERITY_SUBSCORES, CRITERIA_DELTAS, COMMAND_ANOMALY_WEIGHTS,
    CONFIDENCE_BASE, SCORING_VERSION, InvalidRuleSeverity,
)
from core.rule_loader import Rule
from collectors.base import Event


def make_rule(severity="high", detection=None, mitre_attack=None):
    """Create a test rule with defaults."""
    return Rule({
        'name': 'Test Rule',
        'id': 'WIN-001',
        'platform': 'windows',
        'severity': severity,
        'detection': detection or {'process_name': 'test.exe'},
        'mitre_attack': mitre_attack or [],
    })


def make_match(configured=("process_name",), matched=("process_name",),
               partial=(), semantics="and", required_missing=False):
    """Create MatchEvidence with defaults."""
    return MatchEvidence(
        configured_criteria=tuple(configured),
        matched_criteria=tuple(matched),
        partially_matched_criteria=tuple(partial),
        semantics=semantics,
        required_criteria_missing=required_missing,
    )


def make_context(parent="neutral_lineage", user="neutral",
                 anomalies=(), whitelist="no_match", admin="not_admin_context"):
    """Create ContextEvidence with defaults."""
    return ContextEvidence(
        parent_reason=parent,
        user_reason=user,
        command_anomalies=tuple(anomalies),
        whitelist_reason=whitelist,
        admin_reason=admin,
    )


class TestScorerInitialization:
    """Test scorer initialization and constants."""

    def test_scorer_initialization(self):
        scorer = Scorer()
        assert scorer is not None

    def test_scoring_version(self):
        assert SCORING_VERSION == 2

    def test_severity_subscores(self):
        assert SEVERITY_SUBSCORES == {
            "low": 25, "medium": 50, "high": 75, "critical": 100
        }

    def test_criteria_deltas_nonlinear(self):
        """Criteria strength is non-linear: second criterion adds more than fourth."""
        assert CRITERIA_DELTAS == {0: 0, 1: 5, 2: 16, 3: 25, 4: 30}

    def test_confidence_base(self):
        assert CONFIDENCE_BASE == 35

    def test_command_anomaly_weights(self):
        assert COMMAND_ANOMALY_WEIGHTS["encoded_payload"] == 12
        assert COMMAND_ANOMALY_WEIGHTS["download_cradle"] == 10


class TestSeveritySubscore:
    """Test severity subscore mapping."""

    def test_each_severity_maps_exactly(self):
        scorer = Scorer()
        for sev, expected in SEVERITY_SUBSCORES.items():
            rule = make_rule(severity=sev)
            match = make_match()
            context = make_context()
            result = scorer.score(rule, match, context)
            assert result.severity_subscore == expected

    def test_invalid_severity_raises(self):
        scorer = Scorer()
        rule = make_rule(severity="super_critical")
        match = make_match()
        context = make_context()
        with pytest.raises(InvalidRuleSeverity):
            scorer.score(rule, match, context)

    def test_severity_case_insensitive(self):
        scorer = Scorer()
        rule = make_rule(severity="HIGH")
        match = make_match()
        context = make_context()
        result = scorer.score(rule, match, context)
        assert result.severity_subscore == 75


class TestMitreZeroContribution:
    """MITRE technique count contributes zero to score."""

    def test_mitre_count_has_zero_effect(self):
        scorer = Scorer()
        rule_no_mitre = make_rule(severity="high", mitre_attack=[])
        rule_two_mitre = make_rule(severity="high", mitre_attack=["T1059", "T1027"])

        match = make_match()
        context = make_context()

        result1 = scorer.score(rule_no_mitre, match, context)
        result2 = scorer.score(rule_two_mitre, match, context)

        assert result1.score == result2.score
        assert result1.breakdown["severity"]["mitre_contribution"] == 0
        assert result2.breakdown["severity"]["mitre_contribution"] == 0


class TestCriteriaStrength:
    """Test non-linear detection criteria strength deltas."""

    def test_zero_criteria_matched(self):
        scorer = Scorer()
        rule = make_rule(severity="high")
        match = make_match(configured=(), matched=())
        context = make_context()
        result = scorer.score(rule, match, context)
        # 0 criteria: delta 0, confidence = 35 + 0 + neutral context
        assert result.confidence_subscore == 35

    def test_one_criterion_matched(self):
        scorer = Scorer()
        rule = make_rule(severity="high")
        match = make_match(configured=("process_name",), matched=("process_name",))
        context = make_context()
        result = scorer.score(rule, match, context)
        # 1 criterion: +5
        assert result.confidence_subscore == 35 + 5

    def test_two_criteria_matched(self):
        scorer = Scorer()
        rule = make_rule(severity="high")
        match = make_match(
            configured=("process_name", "command_contains"),
            matched=("process_name", "command_contains"),
        )
        context = make_context()
        result = scorer.score(rule, match, context)
        # 2 criteria: +16
        assert result.confidence_subscore == 35 + 16

    def test_three_criteria_matched(self):
        scorer = Scorer()
        rule = make_rule(severity="high")
        match = make_match(
            configured=("process_name", "command_contains", "parent_process"),
            matched=("process_name", "command_contains", "parent_process"),
        )
        context = make_context()
        result = scorer.score(rule, match, context)
        # 3 criteria: +25
        assert result.confidence_subscore == 35 + 25

    def test_four_criteria_matched(self):
        scorer = Scorer()
        rule = make_rule(severity="high")
        match = make_match(
            configured=("process_name", "command_contains", "command_regex", "parent_process"),
            matched=("process_name", "command_contains", "command_regex", "parent_process"),
        )
        context = make_context()
        result = scorer.score(rule, match, context)
        # 4 criteria: +30
        assert result.confidence_subscore == 35 + 30

    def test_duplicate_criteria_do_not_inflate(self):
        """Duplicate criteria entries should not increase the count."""
        scorer = Scorer()
        rule = make_rule(severity="high")
        match = make_match(
            configured=("process_name", "process_name", "process_name"),
            matched=("process_name", "process_name", "process_name"),
        )
        context = make_context()
        result = scorer.score(rule, match, context)
        # Should count as 1 unique criterion
        assert result.confidence_subscore == 35 + 5


class TestCombinationFormula:
    """Test the multiplicative severity and confidence formula."""

    def test_critical_confidence_0_gives_38(self):
        """critical(100) * (0.25 + 0.75*0/100) * 1.5 = 100 * 0.25 * 1.5 = 37.5 -> 38"""
        scorer = Scorer()
        rule = make_rule(severity="critical")
        match = make_match(configured=(), matched=())
        # Need confidence = 0. Base 35, need -35 from factors.
        # Use exact whitelist match (-30) and full admin context (-20) = -50
        # 35 - 50 = -15, clamped to 0
        context = make_context(whitelist="exact_match", admin="full_approved_context")
        result = scorer.score(rule, match, context)
        assert result.confidence_subscore == 0
        assert result.score == 38

    def test_critical_confidence_100_gives_150(self):
        """critical(100) * (0.25 + 0.75*100/100) * 1.5 = 100 * 1.0 * 1.5 = 150"""
        scorer = Scorer()
        rule = make_rule(severity="critical")
        # Need confidence = 100. Base 35, need +65.
        # 4 criteria (+30) + suspicious parent (+15) + system interactive (+15) + encoded + cradle (capped at 25) = 85
        # 35 + 85 = 120, clamped to 100
        match = make_match(
            configured=("process_name", "command_contains", "command_regex", "parent_process"),
            matched=("process_name", "command_contains", "command_regex", "parent_process"),
        )
        context = make_context(
            parent="suspicious_parent_match",
            user="system_interactive_shell",
            anomalies=("encoded_payload", "download_cradle"),
        )
        result = scorer.score(rule, match, context)
        assert result.confidence_subscore == 100
        assert result.score == 150

    def test_high_confidence_100_gives_113(self):
        """high(75) * (0.25 + 0.75*100/100) * 1.5 = 75 * 1.0 * 1.5 = 112.5 -> 113"""
        scorer = Scorer()
        rule = make_rule(severity="high")
        match = make_match(
            configured=("process_name", "command_contains", "command_regex", "parent_process"),
            matched=("process_name", "command_contains", "command_regex", "parent_process"),
        )
        context = make_context(
            parent="suspicious_parent_match",
            user="system_interactive_shell",
            anomalies=("encoded_payload", "download_cradle"),
        )
        result = scorer.score(rule, match, context)
        assert result.confidence_subscore == 100
        assert result.score == 113

    def test_medium_confidence_100_gives_75(self):
        """medium(50) * 1.0 * 1.5 = 75"""
        scorer = Scorer()
        rule = make_rule(severity="medium")
        match = make_match(
            configured=("process_name", "command_contains", "command_regex", "parent_process"),
            matched=("process_name", "command_contains", "command_regex", "parent_process"),
        )
        context = make_context(
            parent="suspicious_parent_match",
            user="system_interactive_shell",
            anomalies=("encoded_payload", "download_cradle"),
        )
        result = scorer.score(rule, match, context)
        assert result.confidence_subscore == 100
        assert result.score == 75

    def test_low_confidence_100_gives_38(self):
        """low(25) * 1.0 * 1.5 = 37.5 -> 38"""
        scorer = Scorer()
        rule = make_rule(severity="low")
        match = make_match(
            configured=("process_name", "command_contains", "command_regex", "parent_process"),
            matched=("process_name", "command_contains", "command_regex", "parent_process"),
        )
        context = make_context(
            parent="suspicious_parent_match",
            user="system_interactive_shell",
            anomalies=("encoded_payload", "download_cradle"),
        )
        result = scorer.score(rule, match, context)
        assert result.confidence_subscore == 100
        assert result.score == 38


class TestRiskBands:
    """Test risk band threshold mapping."""

    def test_low_band_0_to_59(self):
        scorer = Scorer()
        assert scorer._risk_band(0) == "low"
        assert scorer._risk_band(30) == "low"
        assert scorer._risk_band(59) == "low"

    def test_medium_band_60_to_89(self):
        scorer = Scorer()
        assert scorer._risk_band(60) == "medium"
        assert scorer._risk_band(75) == "medium"
        assert scorer._risk_band(89) == "medium"

    def test_high_band_90_to_119(self):
        scorer = Scorer()
        assert scorer._risk_band(90) == "high"
        assert scorer._risk_band(100) == "high"
        assert scorer._risk_band(119) == "high"

    def test_critical_band_120_to_150(self):
        scorer = Scorer()
        assert scorer._risk_band(120) == "critical"
        assert scorer._risk_band(150) == "critical"


class TestScoreBreakdown:
    """Test score breakdown structure."""

    def test_breakdown_has_severity_section(self):
        scorer = Scorer()
        rule = make_rule(severity="high", mitre_attack=["T1059"])
        match = make_match()
        context = make_context()
        result = scorer.score(rule, match, context)
        assert "severity" in result.breakdown
        assert result.breakdown["severity"]["rule_severity"] == "high"
        assert result.breakdown["severity"]["subscore"] == 75
        assert "T1059" in result.breakdown["severity"]["mitre_techniques"]
        assert result.breakdown["severity"]["mitre_contribution"] == 0

    def test_breakdown_has_confidence_section(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context()
        result = scorer.score(rule, match, context)
        assert "confidence" in result.breakdown
        assert result.breakdown["confidence"]["base"] == CONFIDENCE_BASE
        assert "raw" in result.breakdown["confidence"]
        assert "clamped" in result.breakdown["confidence"]
        assert "factors" in result.breakdown["confidence"]

    def test_breakdown_has_combination_section(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context()
        result = scorer.score(rule, match, context)
        assert "combination" in result.breakdown
        assert result.breakdown["combination"]["formula_version"] == "severity_confidence_v2"
        assert result.breakdown["combination"]["scale"] == 1.5

    def test_all_factor_groups_present(self):
        """Every factor group must appear, including zero contributions."""
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context()
        result = scorer.score(rule, match, context)
        factor_names = [f["name"] for f in result.breakdown["confidence"]["factors"]]
        assert "detection_criteria" in factor_names
        assert "parent_context" in factor_names
        assert "user_context" in factor_names
        assert "command_anomaly" in factor_names
        assert "whitelist_adjacency" in factor_names
        assert "admin_context" in factor_names
        assert "partial_match" in factor_names

    def test_factor_deltas_are_signed_integers(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context()
        result = scorer.score(rule, match, context)
        for factor in result.breakdown["confidence"]["factors"]:
            assert isinstance(factor["delta"], int)
            assert "reason" in factor
            assert "evidence" in factor


class TestScoreBounds:
    """Test score is always within bounds."""

    def test_score_always_between_0_and_150(self):
        scorer = Scorer()
        for severity in ("low", "medium", "high", "critical"):
            rule = make_rule(severity=severity)
            for parent in ("missing_telemetry", "suspicious_parent_match", "common_benign_lineage"):
                for whitelist in ("no_match", "exact_match", "high_similarity"):
                    match = make_match()
                    context = make_context(parent=parent, whitelist=whitelist)
                    result = scorer.score(rule, match, context)
                    assert 0 <= result.score <= 150, (
                        f"Score {result.score} out of bounds for {severity}/{parent}/{whitelist}"
                    )

    def test_score_is_integer(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context()
        result = scorer.score(rule, match, context)
        assert isinstance(result.score, int)


class TestParentContext:
    """Test parent process context deltas."""

    def test_missing_parent_telemetry_is_neutral(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context(parent="missing_telemetry")
        result = scorer.score(rule, match, context)
        # Parent factor should have delta 0
        parent_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "parent_context"
        )
        assert parent_factor["delta"] == 0

    def test_suspicious_parent_match_gives_plus_15(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context(parent="suspicious_parent_match")
        result = scorer.score(rule, match, context)
        parent_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "parent_context"
        )
        assert parent_factor["delta"] == 15

    def test_benign_lineage_gives_minus_5(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context(parent="common_benign_lineage")
        result = scorer.score(rule, match, context)
        parent_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "parent_context"
        )
        assert parent_factor["delta"] == -5


class TestUserContext:
    """Test user context deltas."""

    def test_system_interactive_shell_gives_plus_15(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context(user="system_interactive_shell")
        result = scorer.score(rule, match, context)
        user_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "user_context"
        )
        assert user_factor["delta"] == 15

    def test_neutral_user_gives_zero(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context(user="neutral")
        result = scorer.score(rule, match, context)
        user_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "user_context"
        )
        assert user_factor["delta"] == 0


class TestCommandAnomaly:
    """Test command anomaly indicator scoring."""

    def test_no_anomalies_gives_zero(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context(anomalies=())
        result = scorer.score(rule, match, context)
        anomaly_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "command_anomaly"
        )
        assert anomaly_factor["delta"] == 0

    def test_single_anomaly_adds_weight(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context(anomalies=("encoded_payload",))
        result = scorer.score(rule, match, context)
        anomaly_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "command_anomaly"
        )
        assert anomaly_factor["delta"] == 12

    def test_multiple_anomalies_capped_at_25(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context(anomalies=(
            "encoded_payload", "download_cradle", "obfuscation",
            "unusual_path", "suspicious_flags", "high_entropy_argument",
        ))
        result = scorer.score(rule, match, context)
        anomaly_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "command_anomaly"
        )
        # Raw: 12+10+8+5+5+4 = 44, capped at 25
        assert anomaly_factor["delta"] == 25
        assert anomaly_factor["evidence"]["uncapped_delta"] == 44


class TestAdminSuppression:
    """Test admin context suppression and double-counting prevention."""

    def test_full_admin_context_gives_minus_20(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context(user="neutral", admin="full_approved_context")
        result = scorer.score(rule, match, context)
        admin_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "admin_context"
        )
        assert admin_factor["delta"] == -20

    def test_user_anomaly_prevents_admin_suppression(self):
        """If user context is anomalous, admin suppression is not applied."""
        scorer = Scorer()
        rule = make_rule()
        match = make_match()
        context = make_context(user="system_interactive_shell", admin="full_approved_context")
        result = scorer.score(rule, match, context)
        admin_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "admin_context"
        )
        assert admin_factor["delta"] == 0
        assert admin_factor["reason"] == "not_applied_due_to_user_anomaly"


class TestV1Compatibility:
    """Test v1 backward compatibility method."""

    def test_score_alert_returns_integer(self):
        scorer = Scorer()
        rule = make_rule(severity="high")
        event = Event(
            timestamp=datetime.now(),
            platform="windows",
            process_name="powershell.exe",
            command_line="powershell.exe -encodedcommand SGVsbG8=",
            user="admin",
            process_id=1234,
        )
        score = scorer.score_alert(rule, event)
        assert isinstance(score, int)
        assert 0 <= score <= 150

    def test_score_value_returns_integer(self):
        scorer = Scorer()
        rule = make_rule(severity="high")
        match = make_match()
        context = make_context()
        score = scorer.score_value(rule, match, context)
        assert isinstance(score, int)

    def test_interpret_score_works(self):
        scorer = Scorer()
        assert "Critical" in scorer.interpret_score(120)
        assert "High" in scorer.interpret_score(90)
        assert "Medium" in scorer.interpret_score(60)
        assert "Low" in scorer.interpret_score(30)

    def test_get_severity_thresholds(self):
        scorer = Scorer()
        thresholds = scorer.get_severity_thresholds()
        assert thresholds == SEVERITY_SUBSCORES


class TestPartialMatch:
    """Test partial match penalties."""

    def test_full_match_no_penalty(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match(
            configured=("process_name", "command_contains"),
            matched=("process_name", "command_contains"),
            required_missing=False,
        )
        context = make_context()
        result = scorer.score(rule, match, context)
        partial_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "partial_match"
        )
        assert partial_factor["delta"] == 0

    def test_and_with_missing_required_gives_minus_15(self):
        scorer = Scorer()
        rule = make_rule()
        match = make_match(
            configured=("process_name", "command_contains"),
            matched=("process_name",),
            required_missing=True,
            semantics="and",
        )
        context = make_context()
        result = scorer.score(rule, match, context)
        partial_factor = next(
            f for f in result.breakdown["confidence"]["factors"] if f["name"] == "partial_match"
        )
        assert partial_factor["delta"] == -15