"""
Integration tests for LOTL detection rules with their corresponding fixtures.

This test suite verifies end-to-end functionality:
1. Rules load correctly
2. Fixtures parse into valid Events
3. Detection engine matches events to rules
4. Alerts have correct rule ID, severity, and score
5. Benign samples don't trigger false positives
"""
import pytest
from pathlib import Path
from core.rule_loader import RuleLoader
from core.engine import DetectionEngine
from collectors.windows.collector import WindowsCollector
from collectors.linux.collector import LinuxCollector


# Test fixtures base path
FIXTURES_DIR = Path("tests/fixtures")
WINDOWS_FIXTURES = FIXTURES_DIR / "windows"
LINUX_FIXTURES = FIXTURES_DIR / "linux"


class TestWindowsRuleIntegration:
    """Integration tests for Windows detection rules"""

    @pytest.fixture
    def rule_loader(self):
        """Create a rule loader instance"""
        return RuleLoader()

    @pytest.fixture
    def windows_collector(self):
        """Create a Windows collector instance"""
        return WindowsCollector()

    @pytest.fixture
    def detection_engine(self, rule_loader):
        """Create a detection engine with all rules loaded"""
        rules = rule_loader.load_rules_directory("rules")
        return DetectionEngine(rules)

    def test_win001_certutil_triggers_on_malicious_fixture(self, windows_collector, detection_engine):
        """WIN-001: Certutil download should trigger on malicious fixture"""
        # Load and parse malicious fixture
        fixture_path = WINDOWS_FIXTURES / "malicious_certutil.xml"
        events = windows_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the certutil alert
        certutil_alert = next((a for a in alerts if a.rule_id == "WIN-001"), None)
        assert certutil_alert is not None, "Should trigger WIN-001 rule"

        # Verify alert properties
        assert certutil_alert.severity == "high", "Should have HIGH severity"
        assert 100 <= certutil_alert.score <= 150, f"Score {certutil_alert.score} should be in range 100-150"
        assert "T1105" in certutil_alert.mitre_attack, "Should include T1105 MITRE technique"

    def test_win001_certutil_no_alert_on_benign_fixture(self, windows_collector, detection_engine):
        """WIN-001: Certutil should NOT trigger on benign fixture"""
        # Load and parse benign fixture
        fixture_path = WINDOWS_FIXTURES / "benign_certutil.xml"
        events = windows_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        # Should not trigger WIN-001 (certutil download rule)
        certutil_alerts = [a for a in alerts if a.rule_id == "WIN-001"]
        assert len(certutil_alerts) == 0, "Benign certutil should NOT trigger WIN-001"

    def test_win002_powershell_encoded_triggers_on_fixture(self, windows_collector, detection_engine):
        """WIN-002: PowerShell encoded command should trigger on fixture"""
        # Load and parse fixture
        fixture_path = WINDOWS_FIXTURES / "powershell_encoded.xml"
        events = windows_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the PowerShell alert
        ps_alert = next((a for a in alerts if a.rule_id == "WIN-002"), None)
        assert ps_alert is not None, "Should trigger WIN-002 rule"

        # Verify alert properties
        assert ps_alert.severity == "high", "Should have HIGH severity"
        assert 100 <= ps_alert.score <= 150, f"Score {ps_alert.score} should be in range 100-150"
        assert "T1059.001" in ps_alert.mitre_attack, "Should include T1059.001 MITRE technique"
        assert "T1027" in ps_alert.mitre_attack, "Should include T1027 MITRE technique"

    def test_win003_wmi_lateral_movement_triggers_on_fixture(self, windows_collector, detection_engine):
        """WIN-003: WMI lateral movement should trigger on fixture"""
        # Load and parse fixture
        fixture_path = WINDOWS_FIXTURES / "wmi_lateral_movement.xml"
        events = windows_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the WMI alert
        wmi_alert = next((a for a in alerts if a.rule_id == "WIN-003"), None)
        assert wmi_alert is not None, "Should trigger WIN-003 rule"

        # Verify alert properties
        assert wmi_alert.severity == "high", "Should have HIGH severity"
        assert 100 <= wmi_alert.score <= 150, f"Score {wmi_alert.score} should be in range 100-150"
        assert "T1047" in wmi_alert.mitre_attack, "Should include T1047 MITRE technique"

    def test_win004_regsvr32_abuse_triggers_on_fixture(self, windows_collector, detection_engine):
        """WIN-004: Regsvr32 abuse should trigger on fixture"""
        # Load and parse fixture
        fixture_path = WINDOWS_FIXTURES / "regsvr32_abuse.xml"
        events = windows_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the regsvr32 alert
        regsvr32_alert = next((a for a in alerts if a.rule_id == "WIN-004"), None)
        assert regsvr32_alert is not None, "Should trigger WIN-004 rule"

        # Verify alert properties
        assert regsvr32_alert.severity == "high", "Should have HIGH severity"
        assert 100 <= regsvr32_alert.score <= 150, f"Score {regsvr32_alert.score} should be in range 100-150"
        assert "T1218.010" in regsvr32_alert.mitre_attack, "Should include T1218.010 MITRE technique"

    def test_win005_bitsadmin_download_triggers_on_fixture(self, windows_collector, detection_engine):
        """WIN-005: BITSAdmin download should trigger on fixture"""
        # Load and parse fixture
        fixture_path = WINDOWS_FIXTURES / "bitsadmin_download.xml"
        events = windows_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the BITSAdmin alert
        bits_alert = next((a for a in alerts if a.rule_id == "WIN-005"), None)
        assert bits_alert is not None, "Should trigger WIN-005 rule"

        # Verify alert properties
        assert bits_alert.severity == "high", "Should have HIGH severity"
        assert 100 <= bits_alert.score <= 150, f"Score {bits_alert.score} should be in range 100-150"
        assert "T1197" in bits_alert.mitre_attack, "Should include T1197 MITRE technique"

    def test_win006_mshta_execution_triggers_on_fixture(self, windows_collector, detection_engine):
        """WIN-006: MSHTA execution should trigger on fixture"""
        # Load and parse fixture
        fixture_path = WINDOWS_FIXTURES / "mshta_execution.xml"
        events = windows_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the MSHTA alert
        mshta_alert = next((a for a in alerts if a.rule_id == "WIN-006"), None)
        assert mshta_alert is not None, "Should trigger WIN-006 rule"

        # Verify alert properties
        assert mshta_alert.severity == "medium", "Should have MEDIUM severity"
        assert 50 <= mshta_alert.score <= 100, f"Score {mshta_alert.score} should be in range 50-100"
        assert "T1218.005" in mshta_alert.mitre_attack, "Should include T1218.005 MITRE technique"


class TestLinuxRuleIntegration:
    """Integration tests for Linux detection rules"""

    @pytest.fixture
    def rule_loader(self):
        """Create a rule loader instance"""
        return RuleLoader()

    @pytest.fixture
    def linux_collector(self):
        """Create a Linux collector instance"""
        return LinuxCollector()

    @pytest.fixture
    def detection_engine(self, rule_loader):
        """Create a detection engine with all rules loaded"""
        rules = rule_loader.load_rules_directory("rules")
        return DetectionEngine(rules)

    def test_lnx001_curl_download_triggers_on_malicious_fixture(self, linux_collector, detection_engine):
        """LNX-001: Curl/Wget download should trigger on malicious fixture"""
        # Load and parse malicious fixture
        fixture_path = LINUX_FIXTURES / "malicious_curl.log"
        events = linux_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the curl download alert
        curl_alert = next((a for a in alerts if a.rule_id == "LNX-001"), None)
        assert curl_alert is not None, "Should trigger LNX-001 rule"

        # Verify alert properties
        assert curl_alert.severity == "high", "Should have HIGH severity"
        assert 100 <= curl_alert.score <= 150, f"Score {curl_alert.score} should be in range 100-150"
        assert "T1105" in curl_alert.mitre_attack, "Should include T1105 MITRE technique"

    def test_lnx001_curl_download_no_alert_on_benign_fixture(self, linux_collector, detection_engine):
        """LNX-001: Curl should NOT trigger on benign fixture"""
        # Load and parse benign fixture
        fixture_path = LINUX_FIXTURES / "benign_curl.log"
        events = linux_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        # Should not trigger LNX-001 (curl download rule)
        curl_alerts = [a for a in alerts if a.rule_id == "LNX-001"]
        assert len(curl_alerts) == 0, "Benign curl should NOT trigger LNX-001"

    def test_lnx002_reverse_shell_triggers_on_fixture(self, linux_collector, detection_engine):
        """LNX-002: Bash/Netcat reverse shell should trigger on fixture"""
        # Load and parse fixture
        fixture_path = LINUX_FIXTURES / "reverse_shell.log"
        events = linux_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the reverse shell alert
        shell_alert = next((a for a in alerts if a.rule_id == "LNX-002"), None)
        assert shell_alert is not None, "Should trigger LNX-002 rule"

        # Verify alert properties
        assert shell_alert.severity == "critical", "Should have CRITICAL severity"
        assert 120 <= shell_alert.score <= 150, f"Score {shell_alert.score} should be in range 120-150"
        assert "T1059.004" in shell_alert.mitre_attack, "Should include T1059.004 MITRE technique"

    def test_lnx003_cron_persistence_triggers_on_fixture(self, linux_collector, detection_engine):
        """LNX-003: Crontab modification should trigger on fixture"""
        # Load and parse fixture
        fixture_path = LINUX_FIXTURES / "cron_persistence.log"
        events = linux_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the cron persistence alert
        cron_alert = next((a for a in alerts if a.rule_id == "LNX-003"), None)
        assert cron_alert is not None, "Should trigger LNX-003 rule"

        # Verify alert properties
        assert cron_alert.severity == "high", "Should have HIGH severity"
        assert 100 <= cron_alert.score <= 150, f"Score {cron_alert.score} should be in range 100-150"
        assert "T1053.003" in cron_alert.mitre_attack, "Should include T1053.003 MITRE technique"

    @pytest.mark.skip(reason="Fixture not yet created for LNX-004")
    def test_lnx004_ssh_suspicious_triggers_on_fixture(self, linux_collector, detection_engine):
        """LNX-004: SSH with suspicious flags should trigger on fixture"""
        # TODO: Create ssh_suspicious.log fixture
        pass

    @pytest.mark.skip(reason="Fixture not yet created for LNX-005")
    def test_lnx005_base64_decode_triggers_on_fixture(self, linux_collector, detection_engine):
        """LNX-005: Base64 decode piped to shell should trigger on fixture"""
        # TODO: Create base64_decode.log fixture
        pass

    @pytest.mark.skip(reason="Fixture not yet created for LNX-006")
    def test_lnx006_netcat_listener_triggers_on_fixture(self, linux_collector, detection_engine):
        """LNX-006: Netcat listening should trigger on fixture"""
        # TODO: Create netcat_listener.log fixture
        pass


class TestRuleLoadingIntegration:
    """Integration tests for rule loading and detection engine initialization"""

    def test_all_rules_load_successfully(self):
        """Verify all 12 rules load without errors"""
        loader = RuleLoader()
        rules = loader.load_rules_directory("rules")

        assert len(rules) == 12, "Should load exactly 12 rules"

        # Verify Windows rules
        windows_rules = [r for r in rules if r.platform == "windows"]
        assert len(windows_rules) == 6, "Should have 6 Windows rules"

        # Verify Linux rules
        linux_rules = [r for r in rules if r.platform == "linux"]
        assert len(linux_rules) == 6, "Should have 6 Linux rules"

        # Verify all expected rule IDs are present
        expected_rule_ids = [
            "WIN-001", "WIN-002", "WIN-003", "WIN-004", "WIN-005", "WIN-006",
            "LNX-001", "LNX-002", "LNX-003", "LNX-004", "LNX-005", "LNX-006"
        ]

        loaded_rule_ids = [r.id for r in rules]
        for expected_id in expected_rule_ids:
            assert expected_id in loaded_rule_ids, f"Rule {expected_id} should be loaded"

    def test_detection_engine_initializes_with_all_rules(self):
        """Verify detection engine initializes correctly with all rules"""
        loader = RuleLoader()
        rules = loader.load_rules_directory("rules")
        engine = DetectionEngine(rules)

        # Engine should have all rules loaded
        assert len(engine.rules) == 12, "Engine should have 12 rules"

        # Verify engine can filter by platform
        windows_rules = [r for r in engine.rules if r.platform == "windows"]
        linux_rules = [r for r in engine.rules if r.platform == "linux"]

        assert len(windows_rules) == 6, "Should have 6 Windows rules in engine"
        assert len(linux_rules) == 6, "Should have 6 Linux rules in engine"

    def test_all_windows_fixtures_parse_successfully(self):
        """Verify all Windows fixtures parse without errors"""
        collector = WindowsCollector()

        fixtures = [
            "benign_certutil.xml",
            "malicious_certutil.xml",
            "powershell_encoded.xml",
            "wmi_lateral_movement.xml",
            "regsvr32_abuse.xml",
            "bitsadmin_download.xml",
            "mshta_execution.xml"
        ]

        for fixture in fixtures:
            fixture_path = WINDOWS_FIXTURES / fixture
            events = collector.collect_events(str(fixture_path))
            assert len(events) == 1, f"{fixture} should parse exactly one event"
            assert events[0].platform == "windows", f"{fixture} event should be Windows platform"

    def test_all_linux_fixtures_parse_successfully(self):
        """Verify all Linux fixtures parse without errors"""
        collector = LinuxCollector()

        fixtures = [
            "benign_curl.log",
            "malicious_curl.log",
            "reverse_shell.log",
            "cron_persistence.log"
        ]

        for fixture in fixtures:
            fixture_path = LINUX_FIXTURES / fixture
            events = collector.collect_events(str(fixture_path))
            assert len(events) == 1, f"{fixture} should parse exactly one event"
            assert events[0].platform == "linux", f"{fixture} event should be Linux platform"
