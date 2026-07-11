"""
Score calibration tests.

The v2 scoring weights came from the MoA design spec but were never
checked against labeled fixtures. This suite runs the full malicious
fixture corpus through the real pipeline and locks in the resulting
band distribution, then asserts the spec's structural invariants and
the directionality and monotonicity of every confidence factor.

If a weight changes, the per-rule band lock below tells you exactly
which detection shifted. Do not edit the expected bands to make a test
pass without understanding why the score moved: the spec warns against
tuning weights merely to reproduce a distribution.

Reference: docs/score-calibration.md, docs/moa-scoring-design-2026-07-11.md.
"""
from pathlib import Path

import pytest

from collectors.linux.collector import LinuxCollector
from collectors.windows.collector import WindowsCollector
from core.engine import DetectionEngine
from core.rule_loader import Rule, RuleLoader
from core.scorer import (
    CRITERIA_DELTAS,
    SEVERITY_SUBSCORES,
    ContextEvidence,
    MatchEvidence,
    Scorer,
)

FIXTURES = Path("tests/fixtures")

# Locked band per malicious fixture, captured from the real pipeline.
# Format: fixture filename -> (rule_id, expected_risk_band).
# These encode the calibrated behavior. A change here is a calibration
# change and must be justified against the spec invariants below.
WINDOWS_CORPUS = {
    "malicious_certutil.xml": ("WIN-001", "medium"),
    "powershell_encoded.xml": ("WIN-002", "medium"),
    "wmi_lateral_movement.xml": ("WIN-003", "medium"),
    "regsvr32_abuse.xml": ("WIN-004", "medium"),
    "bitsadmin_download.xml": ("WIN-005", "medium"),
    "mshta_execution.xml": ("WIN-006", "low"),
    "malicious_win007_powershell_cradle.xml": ("WIN-007", "high"),
    "malicious_win008_rundll32_js.xml": ("WIN-008", "medium"),
    "malicious_win009_reg_sam_export.xml": ("WIN-009", "high"),
    "malicious_win010_msiexec_remote.xml": ("WIN-010", "medium"),
    "malicious_win011_cmstp_inf.xml": ("WIN-011", "medium"),
}

LINUX_CORPUS = {
    "malicious_curl.log": ("LNX-001", "medium"),
    "reverse_shell.log": ("LNX-002", "medium"),
    "cron_persistence.log": ("LNX-003", "medium"),
    "ssh_suspicious.log": ("LNX-004", "low"),
    "base64_decode.log": ("LNX-005", "medium"),
    "netcat_listener.log": ("LNX-006", "medium"),
    "malicious_lnx007_python_reverse_shell.log": ("LNX-007", "high"),
    "malicious_lnx008_systemd_persistence.log": ("LNX-008", "medium"),
    "malicious_lnx009_ld_preload.log": ("LNX-009", "medium"),
    "malicious_lnx010_authorized_keys.log": ("LNX-010", "medium"),
    "malicious_lnx011_wget_execute.log": ("LNX-011", "medium"),
}


@pytest.fixture(scope="module")
def engine():
    return DetectionEngine(RuleLoader().load_rules_directory("rules"))


def _alert_for(engine, collector, path, rule_id):
    """Return the alert for rule_id from a fixture, or None."""
    for event in collector.collect_events(str(path)):
        for alert in engine.match_event(event):
            if alert.rule_id == rule_id:
                return alert
    return None


class TestCorpusBandLock:
    """The malicious corpus lands in its calibrated bands."""

    @pytest.mark.parametrize(
        "fixture,rule_id,band",
        [(f, r, b) for f, (r, b) in WINDOWS_CORPUS.items()],
        ids=list(WINDOWS_CORPUS.keys()),
    )
    def test_windows_band(self, engine, fixture, rule_id, band):
        alert = _alert_for(
            engine, WindowsCollector(), FIXTURES / "windows" / fixture, rule_id
        )
        assert alert is not None, f"{fixture} did not trigger {rule_id}"
        assert alert.risk_band == band, (
            f"{rule_id} band drifted: got {alert.risk_band} "
            f"(score {alert.score}, confidence {alert.confidence_subscore}), "
            f"expected {band}"
        )

    @pytest.mark.parametrize(
        "fixture,rule_id,band",
        [(f, r, b) for f, (r, b) in LINUX_CORPUS.items()],
        ids=list(LINUX_CORPUS.keys()),
    )
    def test_linux_band(self, engine, fixture, rule_id, band):
        alert = _alert_for(
            engine, LinuxCollector(), FIXTURES / "linux" / fixture, rule_id
        )
        assert alert is not None, f"{fixture} did not trigger {rule_id}"
        assert alert.risk_band == band, (
            f"{rule_id} band drifted: got {alert.risk_band} "
            f"(score {alert.score}, confidence {alert.confidence_subscore}), "
            f"expected {band}"
        )


class TestSpecInvariants:
    """Structural invariants from the scoring design (section 5.4)."""

    def test_no_non_critical_rule_reaches_critical_band(self, engine):
        for corpus, collector, sub in (
            (WINDOWS_CORPUS, WindowsCollector(), "windows"),
            (LINUX_CORPUS, LinuxCollector(), "linux"),
        ):
            for fixture, (rule_id, _) in corpus.items():
                alert = _alert_for(
                    engine, collector, FIXTURES / sub / fixture, rule_id
                )
                if alert and alert.severity != "critical":
                    assert alert.risk_band != "critical", (
                        f"{rule_id} ({alert.severity}) reached critical band; "
                        "only critical-severity rules may."
                    )

    def test_low_and_medium_rules_respect_ceilings(self):
        """
        Low rules never exceed low band; medium rules never exceed medium,
        even at maximum confidence. Verified against the scorer directly.
        """
        scorer = Scorer()
        full_context = ContextEvidence(
            parent_reason="suspicious_parent_match",
            user_reason="system_interactive_shell",
            command_anomalies=("encoded_payload", "download_cradle", "obfuscation"),
            whitelist_reason="no_match",
            admin_reason="not_admin_context",
        )
        strong_match = MatchEvidence(
            configured_criteria=("process_name", "command_contains", "command_regex", "user_pattern"),
            matched_criteria=("process_name", "command_contains", "command_regex", "user_pattern"),
            partially_matched_criteria=(),
            semantics="and",
            required_criteria_missing=False,
        )
        for severity, ceiling in (("low", 59), ("medium", 89)):
            rule = Rule({
                "name": "Ceiling probe", "id": "WIN-999",
                "platform": "windows", "severity": severity,
                "detection": {"process_name": "x.exe"},
            })
            result = scorer.score(rule, strong_match, full_context)
            assert result.score <= ceiling, (
                f"{severity} rule scored {result.score} at max confidence, "
                f"exceeding its {ceiling} ceiling"
            )


class TestFactorDirectionality:
    """Every confidence factor moves the score in the documented direction."""

    def _score(self, match, context, severity="high"):
        rule = Rule({
            "name": "probe", "id": "WIN-999", "platform": "windows",
            "severity": severity, "detection": {"process_name": "x.exe"},
        })
        return Scorer().score(rule, match, context).score

    def _match(self, n):
        crit = ("process_name", "command_contains", "command_regex", "user_pattern")[:n]
        return MatchEvidence(
            configured_criteria=crit, matched_criteria=crit,
            partially_matched_criteria=(), semantics="and",
            required_criteria_missing=False,
        )

    def _ctx(self, **over):
        base = dict(
            parent_reason="neutral_lineage", user_reason="neutral",
            command_anomalies=(), whitelist_reason="no_match",
            admin_reason="not_admin_context",
        )
        base.update(over)
        return ContextEvidence(**base)

    def test_criteria_deltas_monotonic_nondecreasing(self):
        values = [CRITERIA_DELTAS[i] for i in range(5)]
        assert values == sorted(values)
        assert values[0] == 0

    def test_more_criteria_scores_higher(self):
        s1 = self._score(self._match(1), self._ctx())
        s2 = self._score(self._match(2), self._ctx())
        s4 = self._score(self._match(4), self._ctx())
        assert s1 < s2 < s4

    def test_suspicious_parent_raises_score(self):
        base = self._score(self._match(2), self._ctx())
        raised = self._score(
            self._match(2), self._ctx(parent_reason="suspicious_parent_match")
        )
        assert raised > base

    def test_benign_lineage_lowers_score(self):
        base = self._score(self._match(2), self._ctx())
        lowered = self._score(
            self._match(2), self._ctx(parent_reason="common_benign_lineage")
        )
        assert lowered < base

    def test_command_anomalies_raise_score(self):
        base = self._score(self._match(2), self._ctx())
        raised = self._score(
            self._match(2),
            self._ctx(command_anomalies=("encoded_payload", "download_cradle")),
        )
        assert raised > base

    def test_whitelist_adjacency_lowers_score(self):
        base = self._score(self._match(2), self._ctx())
        lowered = self._score(
            self._match(2), self._ctx(whitelist_reason="high_similarity")
        )
        assert lowered < base

    def test_partial_match_penalty_lowers_score(self):
        full = self._match(3)
        partial = MatchEvidence(
            configured_criteria=("process_name", "command_contains", "command_regex"),
            matched_criteria=("process_name", "command_contains"),
            partially_matched_criteria=("command_regex",),
            semantics="and",
            required_criteria_missing=True,
        )
        assert self._score(partial, self._ctx()) < self._score(full, self._ctx())


class TestSeparation:
    """Confirmed-malicious matches score strictly above a benign-context control."""

    def test_malicious_beats_benign_context_same_rule(self, engine):
        # WIN-002 malicious fixture versus a synthetic benign-context score
        # for the same rule: single criterion, benign lineage, whitelist
        # adjacency, no anomalies.
        alert = _alert_for(
            engine, WindowsCollector(),
            FIXTURES / "windows" / "powershell_encoded.xml", "WIN-002",
        )
        assert alert is not None

        rule = RuleLoader().load_rules_directory("rules")
        win002 = next(r for r in rule if r.id == "WIN-002")
        benign_control = Scorer().score(
            win002,
            MatchEvidence(
                configured_criteria=("process_name", "command_contains_any"),
                matched_criteria=("command_contains_any",),
                partially_matched_criteria=("process_name",),
                semantics="or",
                required_criteria_missing=False,
            ),
            ContextEvidence(
                parent_reason="common_benign_lineage",
                user_reason="neutral",
                command_anomalies=(),
                whitelist_reason="high_similarity",
                admin_reason="two_conditions",
            ),
        )
        assert alert.score > benign_control.score
