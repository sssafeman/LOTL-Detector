"""Integration tests for detection rules and their fixture events."""

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple, Type

import pytest

from collectors.base import BaseCollector, Event
from collectors.linux.collector import LinuxCollector
from collectors.macos.collector import MacOSCollector
from collectors.windows.collector import WindowsCollector
from core.engine import Alert, DetectionEngine
from core.rule_loader import Rule, RuleLoader


FIXTURES_DIR = Path("tests/fixtures")
FIXTURE_DIRS = {
    "windows": FIXTURES_DIR / "windows",
    "linux": FIXTURES_DIR / "linux",
    "macos": FIXTURES_DIR / "macos",
}
COLLECTOR_TYPES: Dict[str, Type[BaseCollector]] = {
    "windows": WindowsCollector,
    "linux": LinuxCollector,
    "macos": MacOSCollector,
}
EXPECTED_PLATFORM_COUNTS = {
    "windows": 11,
    "linux": 11,
    "macos": 7,
}

_CollectorFactory = Callable[[str], BaseCollector]


@dataclass(frozen=True)
class _MaliciousCase:
    platform: str
    fixture: str
    rule_id: str
    severity: str
    score_floor: int
    score_ceiling: Optional[int]
    techniques: Tuple[str, ...]


@dataclass(frozen=True)
class _BenignCase:
    platform: str
    fixture: str
    rule_id: str


MALICIOUS_CASES = (
    _MaliciousCase(
        "windows",
        "malicious_certutil.xml",
        "WIN-001",
        "high",
        60,
        100,
        ("T1105",),
    ),
    _MaliciousCase(
        "windows",
        "powershell_encoded.xml",
        "WIN-002",
        "high",
        60,
        120,
        ("T1059.001", "T1027"),
    ),
    _MaliciousCase(
        "windows",
        "wmi_lateral_movement.xml",
        "WIN-003",
        "high",
        60,
        120,
        ("T1047",),
    ),
    _MaliciousCase(
        "windows",
        "regsvr32_abuse.xml",
        "WIN-004",
        "high",
        60,
        100,
        ("T1218.010",),
    ),
    _MaliciousCase(
        "windows",
        "bitsadmin_download.xml",
        "WIN-005",
        "high",
        60,
        100,
        ("T1197",),
    ),
    _MaliciousCase(
        "windows",
        "mshta_execution.xml",
        "WIN-006",
        "medium",
        30,
        80,
        ("T1218.005",),
    ),
    _MaliciousCase(
        "windows",
        "malicious_win007_powershell_cradle.xml",
        "WIN-007",
        "high",
        60,
        120,
        ("T1059.001", "T1105"),
    ),
    _MaliciousCase(
        "windows",
        "malicious_win008_rundll32_js.xml",
        "WIN-008",
        "high",
        60,
        120,
        ("T1218.011",),
    ),
    _MaliciousCase(
        "windows",
        "malicious_win009_reg_sam_export.xml",
        "WIN-009",
        "critical",
        90,
        150,
        ("T1003.002",),
    ),
    _MaliciousCase(
        "windows",
        "malicious_win010_msiexec_remote.xml",
        "WIN-010",
        "high",
        60,
        120,
        ("T1218.007", "T1105"),
    ),
    _MaliciousCase(
        "windows",
        "malicious_win011_cmstp_inf.xml",
        "WIN-011",
        "high",
        60,
        120,
        ("T1218.003",),
    ),
    _MaliciousCase(
        "linux",
        "malicious_curl.log",
        "LNX-001",
        "high",
        60,
        100,
        ("T1105",),
    ),
    _MaliciousCase(
        "linux",
        "reverse_shell.log",
        "LNX-002",
        "critical",
        60,
        120,
        ("T1059.004",),
    ),
    _MaliciousCase(
        "linux",
        "cron_persistence.log",
        "LNX-003",
        "high",
        60,
        100,
        ("T1053.003",),
    ),
    _MaliciousCase(
        "linux",
        "ssh_suspicious.log",
        "LNX-004",
        "medium",
        30,
        60,
        ("T1021.004",),
    ),
    _MaliciousCase(
        "linux",
        "base64_decode.log",
        "LNX-005",
        "high",
        60,
        100,
        ("T1027",),
    ),
    _MaliciousCase(
        "linux",
        "netcat_listener.log",
        "LNX-006",
        "high",
        60,
        100,
        ("T1071",),
    ),
    _MaliciousCase(
        "linux",
        "malicious_lnx007_python_reverse_shell.log",
        "LNX-007",
        "critical",
        90,
        150,
        ("T1059.006",),
    ),
    _MaliciousCase(
        "linux",
        "malicious_lnx008_systemd_persistence.log",
        "LNX-008",
        "high",
        60,
        120,
        ("T1543.002",),
    ),
    _MaliciousCase(
        "linux",
        "malicious_lnx009_ld_preload.log",
        "LNX-009",
        "high",
        60,
        120,
        ("T1574.006",),
    ),
    _MaliciousCase(
        "linux",
        "malicious_lnx010_authorized_keys.log",
        "LNX-010",
        "high",
        60,
        120,
        ("T1098.004",),
    ),
    _MaliciousCase(
        "linux",
        "malicious_lnx011_wget_execute.log",
        "LNX-011",
        "high",
        60,
        120,
        ("T1105", "T1059.004"),
    ),
    _MaliciousCase(
        "macos",
        "malicious_mac001_osascript_shell.ndjson",
        "MAC-001",
        "high",
        0,
        None,
        ("T1059.002",),
    ),
    _MaliciousCase(
        "macos",
        "malicious_mac002_curl_pipe_shell.ndjson",
        "MAC-002",
        "high",
        0,
        None,
        ("T1105",),
    ),
    _MaliciousCase(
        "macos",
        "malicious_mac003_launchagent.ndjson",
        "MAC-003",
        "high",
        0,
        None,
        ("T1543.001",),
    ),
    _MaliciousCase(
        "macos",
        "malicious_mac004_spctl_disable.ndjson",
        "MAC-004",
        "critical",
        0,
        None,
        ("T1553.001",),
    ),
    _MaliciousCase(
        "macos",
        "malicious_mac005_dscl_account.ndjson",
        "MAC-005",
        "high",
        0,
        None,
        ("T1136.001",),
    ),
    _MaliciousCase(
        "macos",
        "malicious_mac006_keychain_dump.ndjson",
        "MAC-006",
        "critical",
        0,
        None,
        ("T1555.001",),
    ),
    _MaliciousCase(
        "macos",
        "malicious_mac007_sudoers.ndjson",
        "MAC-007",
        "high",
        0,
        None,
        ("T1548.003",),
    ),
)

BENIGN_CASES = (
    _BenignCase("windows", "benign_certutil.xml", "WIN-001"),
    _BenignCase("windows", "benign_win007_powershell.xml", "WIN-007"),
    _BenignCase("windows", "benign_win008_rundll32.xml", "WIN-008"),
    _BenignCase("windows", "benign_win009_reg.xml", "WIN-009"),
    _BenignCase("windows", "benign_win010_msiexec.xml", "WIN-010"),
    _BenignCase("windows", "benign_win011_cmstp.xml", "WIN-011"),
    _BenignCase("linux", "benign_curl.log", "LNX-001"),
    _BenignCase("linux", "benign_lnx007_python.log", "LNX-007"),
    _BenignCase("linux", "benign_lnx008_systemctl.log", "LNX-008"),
    _BenignCase("linux", "benign_lnx009_ld_preload.log", "LNX-009"),
    _BenignCase("linux", "benign_lnx010_authorized_keys.log", "LNX-010"),
    _BenignCase("linux", "benign_lnx011_wget.log", "LNX-011"),
    _BenignCase("macos", "benign_mac001_osascript.ndjson", "MAC-001"),
    _BenignCase("macos", "benign_mac002_curl.ndjson", "MAC-002"),
    _BenignCase("macos", "benign_mac003_launchctl.ndjson", "MAC-003"),
    _BenignCase("macos", "benign_mac004_spctl.ndjson", "MAC-004"),
    _BenignCase("macos", "benign_mac005_dscl.ndjson", "MAC-005"),
    _BenignCase("macos", "benign_mac006_security.ndjson", "MAC-006"),
    _BenignCase("macos", "benign_mac007_sudoers_read.ndjson", "MAC-007"),
)

EXPECTED_RULE_IDS = frozenset(case.rule_id for case in MALICIOUS_CASES)
FIXTURES_BY_PLATFORM = {
    platform: tuple(
        case.fixture
        for case in MALICIOUS_CASES + BENIGN_CASES
        if case.platform == platform
    )
    for platform in COLLECTOR_TYPES
}


@pytest.fixture
def loaded_rules() -> List[Rule]:
    """Load the complete bundled ruleset."""
    return RuleLoader().load_rules_directory("rules")


@pytest.fixture
def detection_engine(loaded_rules: List[Rule]) -> DetectionEngine:
    """Build a fresh detection engine for each integration case."""
    return DetectionEngine(loaded_rules)


@pytest.fixture
def collector_for() -> _CollectorFactory:
    """Return a factory for fresh platform collectors."""
    def create(platform: str) -> BaseCollector:
        return COLLECTOR_TYPES[platform]()

    return create


def _collect_single_event(
    collector: BaseCollector,
    platform: str,
    fixture_name: str,
) -> Event:
    """Parse one fixture and validate its event contract."""
    fixture_path = FIXTURE_DIRS[platform] / fixture_name
    events = collector.collect_events(str(fixture_path))
    assert len(events) == 1, f"{fixture_name} should parse exactly one event"
    assert events[0].platform == platform, (
        f"{fixture_name} should produce a {platform} event"
    )
    return events[0]


def _alert_for(
    collector: BaseCollector,
    engine: DetectionEngine,
    platform: str,
    fixture_name: str,
    rule_id: str,
) -> Optional[Alert]:
    """Return the requested rule alert produced by a fixture, if present."""
    event = _collect_single_event(collector, platform, fixture_name)
    alerts = engine.match_event(event)
    return next((alert for alert in alerts if alert.rule_id == rule_id), None)


def _assert_score(alert: Alert, case: _MaliciousCase) -> None:
    """Validate the score contract for a malicious fixture case."""
    if case.score_ceiling is None:
        assert alert.score > case.score_floor, (
            f"Score {alert.score} should be above {case.score_floor}"
        )
        return

    assert case.score_floor <= alert.score <= case.score_ceiling, (
        f"Score {alert.score} should be in range "
        f"{case.score_floor}-{case.score_ceiling}"
    )


class TestRuleDetectionIntegration:
    """Verify malicious and benign fixtures against every covered rule."""

    @pytest.mark.parametrize(
        "case",
        MALICIOUS_CASES,
        ids=[case.rule_id for case in MALICIOUS_CASES],
    )
    def test_malicious_fixture_triggers(
        self,
        collector_for: _CollectorFactory,
        detection_engine: DetectionEngine,
        case: _MaliciousCase,
    ) -> None:
        collector = collector_for(case.platform)
        alert = _alert_for(
            collector,
            detection_engine,
            case.platform,
            case.fixture,
            case.rule_id,
        )

        assert alert is not None, f"Should trigger {case.rule_id}"
        assert alert.severity == case.severity, (
            f"{case.rule_id} should have {case.severity} severity"
        )
        _assert_score(alert, case)
        for technique in case.techniques:
            assert technique in alert.mitre_attack, (
                f"{case.rule_id} should include {technique}"
            )

    @pytest.mark.parametrize(
        "case",
        BENIGN_CASES,
        ids=[case.rule_id for case in BENIGN_CASES],
    )
    def test_benign_fixture_does_not_trigger(
        self,
        collector_for: _CollectorFactory,
        detection_engine: DetectionEngine,
        case: _BenignCase,
    ) -> None:
        collector = collector_for(case.platform)
        alert = _alert_for(
            collector,
            detection_engine,
            case.platform,
            case.fixture,
            case.rule_id,
        )
        assert alert is None, (
            f"Benign fixture {case.fixture} should not trigger {case.rule_id}"
        )


class TestRuleLoadingIntegration:
    """Verify rule loading and detection engine initialization."""

    def test_all_rules_load_successfully(self, loaded_rules: List[Rule]) -> None:
        platform_counts = Counter(rule.platform for rule in loaded_rules)
        loaded_rule_ids = [rule.id for rule in loaded_rules]

        assert dict(platform_counts) == EXPECTED_PLATFORM_COUNTS
        assert len(loaded_rule_ids) == len(EXPECTED_RULE_IDS)
        assert set(loaded_rule_ids) == EXPECTED_RULE_IDS

    def test_detection_engine_initializes_with_all_rules(
        self,
        loaded_rules: List[Rule],
        detection_engine: DetectionEngine,
    ) -> None:
        assert len(detection_engine.rules) == len(loaded_rules)
        platform_counts = Counter(rule.platform for rule in detection_engine.rules)
        assert dict(platform_counts) == EXPECTED_PLATFORM_COUNTS

    @pytest.mark.parametrize(
        "platform,fixture_names",
        tuple(FIXTURES_BY_PLATFORM.items()),
        ids=tuple(FIXTURES_BY_PLATFORM),
    )
    def test_all_fixtures_parse_successfully(
        self,
        collector_for: _CollectorFactory,
        platform: str,
        fixture_names: Tuple[str, ...],
    ) -> None:
        collector = collector_for(platform)
        for fixture_name in fixture_names:
            _collect_single_event(collector, platform, fixture_name)
