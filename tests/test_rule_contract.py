"""
Rule contract tests: CI-enforced guarantees for every bundled rule.

These tests exist because command_contains_any was once silently ignored
by the engine while still validating against the schema. The contract:

1. Every bundled YAML file loads and validates, none is silently skipped.
2. Rule IDs are unique across the bundle.
3. Every operator the schema permits is actually enforced by the engine
   (a rule using only that operator must match and reject correctly)
   and counted by the scorer as match evidence.
4. Every configured regex is precompiled at load time.
5. Chain rules satisfy the same guarantees against their own schema,
   matcher, and correlator.
"""
from datetime import datetime
from pathlib import Path

import pytest

from collectors.base import Event
from core.correlator import ChainRuleLoader, ChainStage
from core.engine import DetectionEngine
from core.process_tree import ProcessNode
from core.rule_loader import Rule, RuleLoader

RULES_DIR = Path("rules")

# Operators the engine's _matches_rule_with_evidence enforces. Adding an
# operator to schema.json without extending the engine must fail here.
ENGINE_OPERATORS = {
    "process_name",
    "command_contains",
    "command_contains_any",
    "command_regex",
    "parent_process",
    "user_pattern",
}

# Operators ChainStage.matches enforces.
CHAIN_STAGE_OPERATORS = {
    "process_name",
    "process_name_any",
    "command_contains",
    "command_contains_any",
    "command_regex",
    "user_pattern",
}


def atomic_rule_files():
    """All bundled atomic rule files (chain rules live in correlation/)."""
    files = [
        f for f in
        list(RULES_DIR.glob("**/*.yml")) + list(RULES_DIR.glob("**/*.yaml"))
        if "correlation" not in f.parts
    ]
    assert files, "No bundled rule files found; run from project root"
    return sorted(files)


def chain_rule_files():
    """All bundled chain rule files."""
    chain_dir = RULES_DIR / "correlation"
    files = sorted(
        list(chain_dir.glob("**/*.yml")) + list(chain_dir.glob("**/*.yaml"))
    )
    assert files, "No bundled chain rule files found"
    return files


def make_event(**overrides):
    """Baseline event for operator enforcement tests."""
    defaults = dict(
        timestamp=datetime(2026, 7, 11, 12, 0, 0),
        platform="windows",
        process_name="powershell.exe",
        command_line="powershell.exe -Command Get-Process",
        user="alice",
        process_id=1000,
        parent_process_name="explorer.exe",
        parent_process_id=1,
    )
    defaults.update(overrides)
    return Event(**defaults)


def make_rule(detection):
    """Minimal valid rule wrapping one detection block."""
    return Rule({
        "name": "Contract Probe",
        "id": "WIN-999",
        "platform": "windows",
        "severity": "high",
        "detection": detection,
    })


class TestBundledRulesLoad:
    """Guarantees 1, 2, 4: loading, uniqueness, regex compilation."""

    @pytest.mark.parametrize(
        "rule_file", atomic_rule_files(), ids=lambda f: f.name
    )
    def test_rule_file_loads_and_validates(self, rule_file):
        loader = RuleLoader()
        rule = loader.load_rule_file(str(rule_file))
        assert rule.id
        assert rule.detection

    def test_no_bundled_rule_silently_skipped(self):
        loader = RuleLoader()
        loaded = loader.load_rules_directory(str(RULES_DIR))
        assert len(loaded) == len(atomic_rule_files()), (
            "A bundled rule failed to load and was silently skipped"
        )

    def test_no_duplicate_rule_ids(self):
        loader = RuleLoader()
        loaded = loader.load_rules_directory(str(RULES_DIR))
        ids = [rule.id for rule in loaded]
        duplicates = {i for i in ids if ids.count(i) > 1}
        assert not duplicates, f"Duplicate rule IDs: {duplicates}"

    def test_configured_regexes_are_precompiled(self):
        loader = RuleLoader()
        for rule in loader.load_rules_directory(str(RULES_DIR)):
            for key in ("command_regex", "user_pattern"):
                if rule.detection.get(key):
                    assert rule.get_compiled_regex(key) is not None, (
                        f"Rule {rule.id} has {key} but no compiled pattern"
                    )

    def test_every_used_operator_is_engine_supported(self):
        loader = RuleLoader()
        for rule in loader.load_rules_directory(str(RULES_DIR)):
            used = set(rule.detection.keys())
            unsupported = used - ENGINE_OPERATORS
            assert not unsupported, (
                f"Rule {rule.id} uses operators the engine ignores: {unsupported}"
            )


class TestSchemaEngineParity:
    """Guarantee 3: schema, engine, and scorer agree on every operator."""

    def test_schema_operators_equal_engine_operators(self):
        loader = RuleLoader()
        schema_ops = set(
            loader.schema["properties"]["detection"]["properties"].keys()
        )
        assert schema_ops == ENGINE_OPERATORS, (
            "schema.json and engine operator support diverged: "
            f"schema-only={schema_ops - ENGINE_OPERATORS}, "
            f"engine-only={ENGINE_OPERATORS - schema_ops}"
        )

    # For each operator: a detection block, an event that must match,
    # and an event that must not.
    OPERATOR_CASES = {
        "process_name": (
            {"process_name": "powershell.exe"},
            make_event(),
            make_event(process_name="notepad.exe"),
        ),
        "command_contains": (
            {"command_contains": ["-Command", "Get-Process"]},
            make_event(),
            make_event(command_line="powershell.exe -Command Get-Date"),
        ),
        "command_contains_any": (
            {"command_contains_any": ["-encodedcommand", "-Command"]},
            make_event(),
            make_event(command_line="powershell.exe -File a.ps1"),
        ),
        "command_regex": (
            {"command_regex": "Get-Pro.ess"},
            make_event(),
            make_event(command_line="powershell.exe -Command Get-Date"),
        ),
        "parent_process": (
            {"parent_process": "explorer.exe"},
            make_event(),
            make_event(parent_process_name="services.exe"),
        ),
        "user_pattern": (
            {"user_pattern": "^ali"},
            make_event(),
            make_event(user="bob"),
        ),
    }

    @pytest.mark.parametrize("operator", sorted(ENGINE_OPERATORS))
    def test_operator_enforced_and_scored(self, operator):
        detection, matching, non_matching = self.OPERATOR_CASES[operator]
        engine = DetectionEngine([make_rule(detection)])

        alerts = engine.match_event(matching)
        assert len(alerts) == 1, f"Engine ignored operator {operator}"

        # The scorer must have counted the operator as match evidence,
        # not merely tolerated it.
        breakdown = alerts[0].score_breakdown
        criteria_factor = next(
            f for f in breakdown["confidence"]["factors"]
            if f["name"] == "detection_criteria"
        )
        assert operator in criteria_factor["evidence"]["matched"], (
            f"Scorer did not count {operator} as matched evidence"
        )

        assert engine.match_event(non_matching) == [], (
            f"Operator {operator} failed to reject a non-matching event"
        )


class TestChainRuleContract:
    """Same guarantees for chain rules."""

    @pytest.mark.parametrize(
        "chain_file", chain_rule_files(), ids=lambda f: f.name
    )
    def test_chain_file_loads_and_validates(self, chain_file):
        loader = ChainRuleLoader()
        chain = loader.load_chain_file(str(chain_file))
        assert len(chain.stages) >= 2

    def test_no_chain_silently_skipped(self):
        loader = ChainRuleLoader()
        loaded = loader.load_chains_directory(str(RULES_DIR / "correlation"))
        assert len(loaded) == len(chain_rule_files())

    def test_no_duplicate_chain_ids(self):
        loader = ChainRuleLoader()
        loaded = loader.load_chains_directory(str(RULES_DIR / "correlation"))
        ids = [chain.id for chain in loaded]
        assert len(ids) == len(set(ids))

    def test_chain_ids_do_not_collide_with_atomic_ids(self):
        atomic = {r.id for r in RuleLoader().load_rules_directory(str(RULES_DIR))}
        chains = {
            c.id for c in
            ChainRuleLoader().load_chains_directory(str(RULES_DIR / "correlation"))
        }
        assert not (atomic & chains)

    def test_chain_schema_operators_equal_stage_matcher(self):
        loader = ChainRuleLoader()
        schema_ops = set(
            loader.schema["properties"]["stages"]["items"]
            ["properties"]["match"]["properties"].keys()
        )
        assert schema_ops == CHAIN_STAGE_OPERATORS

    STAGE_CASES = {
        "process_name": ({"process_name": "powershell.exe"}, True),
        "process_name_any": ({"process_name_any": ["cmd.exe", "powershell.exe"]}, True),
        "command_contains": ({"command_contains": ["-Command", "Get-Process"]}, True),
        "command_contains_any": ({"command_contains_any": ["-Command", "-enc"]}, True),
        "command_regex": ({"command_regex": "Get-Pro.ess"}, True),
        "user_pattern": ({"user_pattern": "^ali"}, True),
    }

    @pytest.mark.parametrize("operator", sorted(CHAIN_STAGE_OPERATORS))
    def test_stage_operator_enforced(self, operator):
        match, _ = self.STAGE_CASES[operator]
        stage = ChainStage(
            {"name": "probe", "match": match}, "CHAIN-WIN-999", 0
        )
        matching = ProcessNode(
            key="h|1000|0", process_name="powershell.exe",
            platform="windows", host="h", pid=1000, event=make_event(),
        )
        rejecting = ProcessNode(
            key="h|1001|1", process_name="svchost.exe",
            platform="windows", host="h", pid=1001,
            event=make_event(
                process_name="svchost.exe", command_line="svchost.exe -k netsvcs",
                user="bob", process_id=1001,
            ),
        )
        assert stage.matches(matching, "windows"), (
            f"ChainStage ignored operator {operator}"
        )
        assert not stage.matches(rejecting, "windows"), (
            f"ChainStage operator {operator} failed to reject"
        )
