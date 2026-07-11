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
        assert 60 <= certutil_alert.score <= 100, f"Score {certutil_alert.score} should be in range 60-100 (v2 multiplicative)"
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
        assert 60 <= ps_alert.score <= 120, f"Score {ps_alert.score} should be in range 60-120 (v2 multiplicative)"
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
        assert 60 <= wmi_alert.score <= 120, f"Score {wmi_alert.score} should be in range 60-120 (v2 multiplicative)"
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
        assert 60 <= regsvr32_alert.score <= 100, f"Score {regsvr32_alert.score} should be in range 60-100 (v2 multiplicative)"
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
        assert 60 <= bits_alert.score <= 100, f"Score {bits_alert.score} should be in range 60-100 (v2 multiplicative)"
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
        assert 30 <= mshta_alert.score <= 80, f"Score {mshta_alert.score} should be in range 30-80 (v2 multiplicative, medium severity)"
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
        assert 60 <= curl_alert.score <= 100, f"Score {curl_alert.score} should be in range 60-100 (v2 multiplicative)"
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
        assert 60 <= shell_alert.score <= 120, f"Score {shell_alert.score} should be in range 60-120 (v2 multiplicative)"
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
        assert 60 <= cron_alert.score <= 100, f"Score {cron_alert.score} should be in range 60-100 (v2 multiplicative)"
        assert "T1053.003" in cron_alert.mitre_attack, "Should include T1053.003 MITRE technique"

    def test_lnx004_ssh_suspicious_triggers_on_fixture(self, linux_collector, detection_engine):
        """LNX-004: SSH with suspicious flags should trigger on fixture"""
        # Load and parse fixture
        fixture_path = LINUX_FIXTURES / "ssh_suspicious.log"
        events = linux_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the SSH alert
        ssh_alert = next((a for a in alerts if a.rule_id == "LNX-004"), None)
        assert ssh_alert is not None, "Should trigger LNX-004 rule"

        # Verify alert properties
        assert ssh_alert.severity == "medium", "Should have MEDIUM severity"
        assert 30 <= ssh_alert.score <= 60, f"Score {ssh_alert.score} should be in range 30-60 (v2 multiplicative, medium severity)"
        assert "T1021.004" in ssh_alert.mitre_attack, "Should include T1021.004 MITRE technique"

    def test_lnx005_base64_decode_triggers_on_fixture(self, linux_collector, detection_engine):
        """LNX-005: Base64 decode piped to shell should trigger on fixture"""
        # Load and parse fixture
        fixture_path = LINUX_FIXTURES / "base64_decode.log"
        events = linux_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the base64 decode alert
        base64_alert = next((a for a in alerts if a.rule_id == "LNX-005"), None)
        assert base64_alert is not None, "Should trigger LNX-005 rule"

        # Verify alert properties
        assert base64_alert.severity == "high", "Should have HIGH severity"
        assert 60 <= base64_alert.score <= 100, f"Score {base64_alert.score} should be in range 60-100 (v2 multiplicative)"
        assert "T1027" in base64_alert.mitre_attack, "Should include T1027 MITRE technique"

    def test_lnx006_netcat_listener_triggers_on_fixture(self, linux_collector, detection_engine):
        """LNX-006: Netcat listening should trigger on fixture"""
        # Load and parse fixture
        fixture_path = LINUX_FIXTURES / "netcat_listener.log"
        events = linux_collector.collect_events(str(fixture_path))

        assert len(events) == 1, "Should parse exactly one event"

        # Run detection
        alerts = detection_engine.match_event(events[0])

        assert len(alerts) > 0, "Should generate at least one alert"

        # Find the netcat listener alert
        nc_alert = next((a for a in alerts if a.rule_id == "LNX-006"), None)
        assert nc_alert is not None, "Should trigger LNX-006 rule"

        # Verify alert properties
        assert nc_alert.severity == "high", "Should have HIGH severity"
        assert 60 <= nc_alert.score <= 100, f"Score {nc_alert.score} should be in range 60-100 (v2 multiplicative)"
        assert "T1071" in nc_alert.mitre_attack, "Should include T1071 MITRE technique"


class TestWindowsNewRuleIntegration:
    """Integration tests for the WIN-007 to WIN-011 detection rules"""

    @pytest.fixture
    def windows_collector(self):
        """Create a Windows collector instance"""
        return WindowsCollector()

    @pytest.fixture
    def detection_engine(self):
        """Create a detection engine with all rules loaded"""
        rules = RuleLoader().load_rules_directory("rules")
        return DetectionEngine(rules)

    def _alert_for(self, collector, engine, fixture_name, rule_id):
        """Parse a fixture and return the alert for the given rule id, if any."""
        fixture_path = WINDOWS_FIXTURES / fixture_name
        events = collector.collect_events(str(fixture_path))
        assert len(events) == 1, f"{fixture_name} should parse exactly one event"
        assert events[0].platform == "windows", f"{fixture_name} should be Windows"
        alerts = engine.match_event(events[0])
        return next((a for a in alerts if a.rule_id == rule_id), None)

    def test_win007_powershell_cradle_triggers(self, windows_collector, detection_engine):
        """WIN-007: PowerShell WebClient download cradle should trigger"""
        alert = self._alert_for(
            windows_collector, detection_engine,
            "malicious_win007_powershell_cradle.xml", "WIN-007",
        )
        assert alert is not None, "Should trigger WIN-007 rule"
        assert alert.severity == "high", "Should have HIGH severity"
        assert 60 <= alert.score <= 120, f"Score {alert.score} out of expected range"
        assert "T1059.001" in alert.mitre_attack
        assert "T1105" in alert.mitre_attack

    def test_win007_no_alert_on_benign(self, windows_collector, detection_engine):
        """WIN-007: Benign PowerShell should NOT trigger"""
        alert = self._alert_for(
            windows_collector, detection_engine,
            "benign_win007_powershell.xml", "WIN-007",
        )
        assert alert is None, "Benign PowerShell should NOT trigger WIN-007"

    def test_win008_rundll32_js_triggers(self, windows_collector, detection_engine):
        """WIN-008: Rundll32 JavaScript proxy execution should trigger"""
        alert = self._alert_for(
            windows_collector, detection_engine,
            "malicious_win008_rundll32_js.xml", "WIN-008",
        )
        assert alert is not None, "Should trigger WIN-008 rule"
        assert alert.severity == "high", "Should have HIGH severity"
        assert 60 <= alert.score <= 120, f"Score {alert.score} out of expected range"
        assert "T1218.011" in alert.mitre_attack

    def test_win008_no_alert_on_benign(self, windows_collector, detection_engine):
        """WIN-008: Benign rundll32 should NOT trigger"""
        alert = self._alert_for(
            windows_collector, detection_engine,
            "benign_win008_rundll32.xml", "WIN-008",
        )
        assert alert is None, "Benign rundll32 should NOT trigger WIN-008"

    def test_win009_reg_sam_export_triggers(self, windows_collector, detection_engine):
        """WIN-009: Registry hive export for credential access should trigger"""
        alert = self._alert_for(
            windows_collector, detection_engine,
            "malicious_win009_reg_sam_export.xml", "WIN-009",
        )
        assert alert is not None, "Should trigger WIN-009 rule"
        assert alert.severity == "critical", "Should have CRITICAL severity"
        assert 90 <= alert.score <= 150, f"Score {alert.score} out of expected range"
        assert "T1003.002" in alert.mitre_attack

    def test_win009_no_alert_on_benign(self, windows_collector, detection_engine):
        """WIN-009: Benign reg query should NOT trigger"""
        alert = self._alert_for(
            windows_collector, detection_engine,
            "benign_win009_reg.xml", "WIN-009",
        )
        assert alert is None, "Benign reg query should NOT trigger WIN-009"

    def test_win010_msiexec_remote_triggers(self, windows_collector, detection_engine):
        """WIN-010: Msiexec remote package execution should trigger"""
        alert = self._alert_for(
            windows_collector, detection_engine,
            "malicious_win010_msiexec_remote.xml", "WIN-010",
        )
        assert alert is not None, "Should trigger WIN-010 rule"
        assert alert.severity == "high", "Should have HIGH severity"
        assert 60 <= alert.score <= 120, f"Score {alert.score} out of expected range"
        assert "T1218.007" in alert.mitre_attack
        assert "T1105" in alert.mitre_attack

    def test_win010_no_alert_on_benign(self, windows_collector, detection_engine):
        """WIN-010: Benign local msiexec install should NOT trigger"""
        alert = self._alert_for(
            windows_collector, detection_engine,
            "benign_win010_msiexec.xml", "WIN-010",
        )
        assert alert is None, "Benign local msiexec should NOT trigger WIN-010"

    def test_win011_cmstp_inf_triggers(self, windows_collector, detection_engine):
        """WIN-011: CMSTP suspicious INF execution should trigger"""
        alert = self._alert_for(
            windows_collector, detection_engine,
            "malicious_win011_cmstp_inf.xml", "WIN-011",
        )
        assert alert is not None, "Should trigger WIN-011 rule"
        assert alert.severity == "high", "Should have HIGH severity"
        assert 60 <= alert.score <= 120, f"Score {alert.score} out of expected range"
        assert "T1218.003" in alert.mitre_attack

    def test_win011_no_alert_on_benign(self, windows_collector, detection_engine):
        """WIN-011: Benign VPN profile INF should NOT trigger"""
        alert = self._alert_for(
            windows_collector, detection_engine,
            "benign_win011_cmstp.xml", "WIN-011",
        )
        assert alert is None, "Benign cmstp install should NOT trigger WIN-011"


class TestLinuxNewRuleIntegration:
    """Integration tests for the LNX-007 to LNX-011 detection rules"""

    @pytest.fixture
    def linux_collector(self):
        """Create a Linux collector instance"""
        return LinuxCollector()

    @pytest.fixture
    def detection_engine(self):
        """Create a detection engine with all rules loaded"""
        rules = RuleLoader().load_rules_directory("rules")
        return DetectionEngine(rules)

    def _alert_for(self, collector, engine, fixture_name, rule_id):
        """Parse a fixture and return the alert for the given rule id, if any."""
        fixture_path = LINUX_FIXTURES / fixture_name
        events = collector.collect_events(str(fixture_path))
        assert len(events) == 1, f"{fixture_name} should parse exactly one event"
        assert events[0].platform == "linux", f"{fixture_name} should be Linux"
        alerts = engine.match_event(events[0])
        return next((a for a in alerts if a.rule_id == rule_id), None)

    def test_lnx007_python_reverse_shell_triggers(self, linux_collector, detection_engine):
        """LNX-007: Python reverse shell one-liner should trigger"""
        alert = self._alert_for(
            linux_collector, detection_engine,
            "malicious_lnx007_python_reverse_shell.log", "LNX-007",
        )
        assert alert is not None, "Should trigger LNX-007 rule"
        assert alert.severity == "critical", "Should have CRITICAL severity"
        assert 90 <= alert.score <= 150, f"Score {alert.score} out of expected range"
        assert "T1059.006" in alert.mitre_attack

    def test_lnx007_no_alert_on_benign(self, linux_collector, detection_engine):
        """LNX-007: Benign python one-liner should NOT trigger"""
        alert = self._alert_for(
            linux_collector, detection_engine,
            "benign_lnx007_python.log", "LNX-007",
        )
        assert alert is None, "Benign python should NOT trigger LNX-007"

    def test_lnx008_systemd_persistence_triggers(self, linux_collector, detection_engine):
        """LNX-008: Systemd service persistence should trigger"""
        alert = self._alert_for(
            linux_collector, detection_engine,
            "malicious_lnx008_systemd_persistence.log", "LNX-008",
        )
        assert alert is not None, "Should trigger LNX-008 rule"
        assert alert.severity == "high", "Should have HIGH severity"
        assert 60 <= alert.score <= 120, f"Score {alert.score} out of expected range"
        assert "T1543.002" in alert.mitre_attack

    def test_lnx008_no_alert_on_benign(self, linux_collector, detection_engine):
        """LNX-008: Benign systemctl restart should NOT trigger"""
        alert = self._alert_for(
            linux_collector, detection_engine,
            "benign_lnx008_systemctl.log", "LNX-008",
        )
        assert alert is None, "Benign systemctl should NOT trigger LNX-008"

    def test_lnx009_ld_preload_triggers(self, linux_collector, detection_engine):
        """LNX-009: LD_PRELOAD from user-writable directory should trigger"""
        alert = self._alert_for(
            linux_collector, detection_engine,
            "malicious_lnx009_ld_preload.log", "LNX-009",
        )
        assert alert is not None, "Should trigger LNX-009 rule"
        assert alert.severity == "high", "Should have HIGH severity"
        assert 60 <= alert.score <= 120, f"Score {alert.score} out of expected range"
        assert "T1574.006" in alert.mitre_attack

    def test_lnx009_no_alert_on_benign(self, linux_collector, detection_engine):
        """LNX-009: Benign LD_PRELOAD from system path should NOT trigger"""
        alert = self._alert_for(
            linux_collector, detection_engine,
            "benign_lnx009_ld_preload.log", "LNX-009",
        )
        assert alert is None, "Benign LD_PRELOAD should NOT trigger LNX-009"

    def test_lnx010_authorized_keys_triggers(self, linux_collector, detection_engine):
        """LNX-010: SSH authorized_keys modification should trigger"""
        alert = self._alert_for(
            linux_collector, detection_engine,
            "malicious_lnx010_authorized_keys.log", "LNX-010",
        )
        assert alert is not None, "Should trigger LNX-010 rule"
        assert alert.severity == "high", "Should have HIGH severity"
        assert 60 <= alert.score <= 120, f"Score {alert.score} out of expected range"
        assert "T1098.004" in alert.mitre_attack

    def test_lnx010_no_alert_on_benign(self, linux_collector, detection_engine):
        """LNX-010: Benign chmod on authorized_keys should NOT trigger"""
        alert = self._alert_for(
            linux_collector, detection_engine,
            "benign_lnx010_authorized_keys.log", "LNX-010",
        )
        assert alert is None, "Benign chmod should NOT trigger LNX-010"

    def test_lnx011_wget_execute_triggers(self, linux_collector, detection_engine):
        """LNX-011: Wget download and immediate execution should trigger"""
        alert = self._alert_for(
            linux_collector, detection_engine,
            "malicious_lnx011_wget_execute.log", "LNX-011",
        )
        assert alert is not None, "Should trigger LNX-011 rule"
        assert alert.severity == "high", "Should have HIGH severity"
        assert 60 <= alert.score <= 120, f"Score {alert.score} out of expected range"
        assert "T1105" in alert.mitre_attack
        assert "T1059.004" in alert.mitre_attack

    def test_lnx011_no_alert_on_benign(self, linux_collector, detection_engine):
        """LNX-011: Benign wget file download should NOT trigger"""
        alert = self._alert_for(
            linux_collector, detection_engine,
            "benign_lnx011_wget.log", "LNX-011",
        )
        assert alert is None, "Benign wget should NOT trigger LNX-011"


class TestRuleLoadingIntegration:
    """Integration tests for rule loading and detection engine initialization"""

    def test_all_rules_load_successfully(self):
        """Verify all 12 rules load without errors"""
        loader = RuleLoader()
        rules = loader.load_rules_directory("rules")

        assert len(rules) == 22, "Should load exactly 22 rules"

        # Verify Windows rules
        windows_rules = [r for r in rules if r.platform == "windows"]
        assert len(windows_rules) == 11, "Should have 11 Windows rules"

        # Verify Linux rules
        linux_rules = [r for r in rules if r.platform == "linux"]
        assert len(linux_rules) == 11, "Should have 11 Linux rules"

        # Verify all expected rule IDs are present
        expected_rule_ids = [
            "WIN-001", "WIN-002", "WIN-003", "WIN-004", "WIN-005", "WIN-006",
            "WIN-007", "WIN-008", "WIN-009", "WIN-010", "WIN-011",
            "LNX-001", "LNX-002", "LNX-003", "LNX-004", "LNX-005", "LNX-006",
            "LNX-007", "LNX-008", "LNX-009", "LNX-010", "LNX-011"
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
        assert len(engine.rules) == 22, "Engine should have 12 rules"

        # Verify engine can filter by platform
        windows_rules = [r for r in engine.rules if r.platform == "windows"]
        linux_rules = [r for r in engine.rules if r.platform == "linux"]

        assert len(windows_rules) == 11, "Should have 11 Windows rules in engine"
        assert len(linux_rules) == 11, "Should have 11 Linux rules in engine"

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
            "mshta_execution.xml",
            "malicious_win007_powershell_cradle.xml",
            "benign_win007_powershell.xml",
            "malicious_win008_rundll32_js.xml",
            "benign_win008_rundll32.xml",
            "malicious_win009_reg_sam_export.xml",
            "benign_win009_reg.xml",
            "malicious_win010_msiexec_remote.xml",
            "benign_win010_msiexec.xml",
            "malicious_win011_cmstp_inf.xml",
            "benign_win011_cmstp.xml"
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
            "cron_persistence.log",
            "ssh_suspicious.log",
            "base64_decode.log",
            "netcat_listener.log",
            "malicious_lnx007_python_reverse_shell.log",
            "benign_lnx007_python.log",
            "malicious_lnx008_systemd_persistence.log",
            "benign_lnx008_systemctl.log",
            "malicious_lnx009_ld_preload.log",
            "benign_lnx009_ld_preload.log",
            "malicious_lnx010_authorized_keys.log",
            "benign_lnx010_authorized_keys.log",
            "malicious_lnx011_wget_execute.log",
            "benign_lnx011_wget.log"
        ]

        for fixture in fixtures:
            fixture_path = LINUX_FIXTURES / fixture
            events = collector.collect_events(str(fixture_path))
            assert len(events) == 1, f"{fixture} should parse exactly one event"
            assert events[0].platform == "linux", f"{fixture} event should be Linux platform"
