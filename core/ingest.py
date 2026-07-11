"""
Bounded incremental ingestion for line-oriented log sources.

The default pipeline is batch-oriented: collect_events and match_events
return complete lists, which loads whole files into memory and cannot
resume. This module (MoA finding 16) adds file tailing with durable
byte-offset checkpoints, bounded batches, log-rotation detection, and
idempotent database writes.

Scope: line-oriented sources, Linux auditd first. Windows Event Log
subscriptions are the follow-up (the finding sequences file tailing
first). Idempotency comes from the alert and incident fingerprint dedup,
so reprocessing a checkpoint boundary never creates duplicates.
"""
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional

from collectors.base import Event

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 500
INGEST_VERSION = 1


@dataclass
class Checkpoint:
    """
    Durable progress marker for one ingestion source.

    inode and size detect log rotation and truncation: if the file's
    inode changes or its size drops below the recorded offset, the
    source was rotated or truncated and reading restarts from zero.
    """
    source: str
    offset: int = 0
    inode: Optional[int] = None
    size: int = 0
    events_ingested: int = 0

    def rotated(self, current_inode: int, current_size: int) -> bool:
        """True when the file was rotated (new inode) or truncated."""
        if self.inode is not None and current_inode != self.inode:
            return True
        if current_size < self.offset:
            return True
        return False


def chunked(iterable: Iterable[Any], size: int) -> Iterator[List[Any]]:
    """
    Yield lists of at most `size` items from an iterable.

    Constant memory per batch regardless of total length.
    """
    if size < 1:
        raise ValueError("batch size must be >= 1")
    batch: List[Any] = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def read_new_text(path: str, checkpoint: Checkpoint) -> Dict[str, Any]:
    """
    Read new content from a file since the checkpoint offset.

    Reads only complete lines: a trailing partial line (no newline yet)
    is held back so a half-written record is never parsed, and the
    reported offset stops at the last newline. Detects rotation and
    truncation and restarts from zero in that case.

    Args:
        path: File to read
        checkpoint: Current progress marker

    Returns:
        Dict with: text (complete-line string), new_offset (int),
        inode (int), size (int), reset (bool)
    """
    stat = os.stat(path)
    inode = stat.st_ino
    size = stat.st_size

    reset = checkpoint.rotated(inode, size)
    start = 0 if reset else checkpoint.offset
    if reset and checkpoint.offset:
        logger.info(f"Source rotated or truncated, restarting: {path}")

    with open(path, "r", errors="replace") as f:
        f.seek(start)
        raw = f.read()

    # Hold back a trailing partial line (no terminating newline).
    if raw and not raw.endswith("\n"):
        last_nl = raw.rfind("\n")
        if last_nl == -1:
            # No complete line available yet.
            return {
                "text": "", "start": start, "new_offset": start,
                "inode": inode, "size": size, "reset": reset,
            }
        complete = raw[: last_nl + 1]
    else:
        complete = raw

    new_offset = start + len(complete.encode("utf-8"))
    return {
        "text": complete, "start": start, "new_offset": new_offset,
        "inode": inode, "size": size, "reset": reset,
    }


class CheckpointStore:
    """
    Persists ingestion checkpoints in the alert database.

    Creates its own table so the store can be dropped into an existing
    AlertDatabase without touching the alert schema.
    """

    def __init__(self, db):
        self.db = db
        self._ensure_table()

    def _ensure_table(self) -> None:
        cursor = self.db.connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ingest_checkpoints (
                source TEXT PRIMARY KEY,
                offset INTEGER NOT NULL DEFAULT 0,
                inode INTEGER,
                size INTEGER NOT NULL DEFAULT 0,
                events_ingested INTEGER NOT NULL DEFAULT 0,
                ingest_version INTEGER NOT NULL DEFAULT 1,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.db.connection.commit()

    def load(self, source: str) -> Checkpoint:
        """Load the checkpoint for a source, or a fresh zero checkpoint."""
        cursor = self.db.connection.cursor()
        cursor.execute(
            "SELECT source, offset, inode, size, events_ingested "
            "FROM ingest_checkpoints WHERE source = ?",
            (source,),
        )
        row = cursor.fetchone()
        if row is None:
            return Checkpoint(source=source)
        return Checkpoint(
            source=row[0], offset=row[1], inode=row[2],
            size=row[3], events_ingested=row[4],
        )

    def save(self, checkpoint: Checkpoint) -> None:
        """Upsert a checkpoint durably."""
        cursor = self.db.connection.cursor()
        cursor.execute("""
            INSERT INTO ingest_checkpoints
                (source, offset, inode, size, events_ingested, ingest_version, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(source) DO UPDATE SET
                offset = excluded.offset,
                inode = excluded.inode,
                size = excluded.size,
                events_ingested = excluded.events_ingested,
                updated_at = CURRENT_TIMESTAMP
        """, (
            checkpoint.source, checkpoint.offset, checkpoint.inode,
            checkpoint.size, checkpoint.events_ingested, INGEST_VERSION,
        ))
        self.db.connection.commit()


# A parser turns a text block into events. It may return either a plain
# list of events (the whole text is consumed) or a (events, consumed_chars)
# tuple, where consumed_chars marks how much of the text formed complete
# records. Anything past consumed_chars is re-read on the next run, so
# records that span a read boundary (multi-line XML elements) are never
# split. See normalize_parse_result.
EventParser = Callable[[str], Any]


def normalize_parse_result(result, text: str):
    """
    Normalize a parser's return into (events, consumed_chars).

    A bare list means the whole text was consumed. A tuple is returned
    as-is. consumed_chars is clamped to len(text).
    """
    if isinstance(result, tuple):
        events, consumed = result
        return events, min(consumed, len(text))
    return result, len(text)


def linux_auditd_parser(collector) -> EventParser:
    """
    Build an auditd text parser backed by a LinuxCollector.

    auditd records for one event are line-contiguous and written
    atomically, and read_new_text already trims to complete lines, so the
    whole complete-line buffer is consumed each run.
    """
    def parse(text: str):
        return collector.events_from_lines(text.splitlines()), len(text)
    return parse


def windows_sysmon_parser(collector) -> EventParser:
    """
    Build a Sysmon XML text parser backed by a WindowsCollector.

    Consumes only complete <Event>...</Event> elements; a trailing
    partial element is left for the next run.
    """
    def parse(text: str):
        return collector.events_from_text(text)
    return parse


class IngestionService:
    """
    Drives bounded, restart-safe ingestion of a log source.

    Each run reads new content since the checkpoint, parses it into events,
    processes them in bounded batches through the engine and correlator,
    saves results with dedup, and advances the checkpoint once to the
    parser's consumed offset. A crash mid-run leaves the checkpoint
    unadvanced, so the run is reprocessed and idempotent dedup absorbs the
    overlap. The parser controls the consumed offset, so multi-line records
    (XML elements) that span a read boundary are never split.
    """

    def __init__(
        self,
        db,
        engine,
        parser: EventParser,
        correlator=None,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ):
        self.db = db
        self.engine = engine
        self.parser = parser
        self.correlator = correlator
        self.batch_size = batch_size
        self.checkpoints = CheckpointStore(db)

    def ingest_file(self, source: str) -> Dict[str, Any]:
        """
        Ingest new content from a single file source.

        Returns a summary dict with events processed, new alerts,
        duplicates, suppressions, new incidents, batch count, and the
        start and end offsets. Correlation runs per batch: chains split
        across batch boundaries are not matched, which is the documented
        bound of batched correlation.
        """
        source = str(Path(source))
        checkpoint = self.checkpoints.load(source)
        read = read_new_text(source, checkpoint)

        if read["reset"]:
            checkpoint = Checkpoint(source=source)

        summary = {
            "source": source,
            "events_processed": 0,
            "alerts_new": 0,
            "alerts_duplicate": 0,
            "alerts_suppressed": 0,
            "incidents_new": 0,
            "batches": 0,
            "reset": read["reset"],
            "start_offset": checkpoint.offset,
        }

        text = read["text"]
        if not text:
            # Nothing new; still record inode/size so rotation is tracked.
            checkpoint.inode = read["inode"]
            checkpoint.size = read["size"]
            checkpoint.offset = read["new_offset"]
            self.checkpoints.save(checkpoint)
            summary["end_offset"] = checkpoint.offset
            return summary

        events, consumed = normalize_parse_result(self.parser(text), text)
        # The offset advances only past the consumed prefix, so a trailing
        # partial record (a multi-line XML element still being written) is
        # re-read on the next run instead of being split or dropped.
        consumed_offset = read["start"] + len(text[:consumed].encode("utf-8"))
        summary["events_processed"] = len(events)

        for batch in chunked(events, self.batch_size):
            self._process_batch(batch, summary)
            summary["batches"] += 1
            checkpoint.events_ingested += len(batch)

        # Persist the checkpoint once, advanced to the consumed offset.
        # Idempotent dedup makes a boundary reprocess after a crash safe.
        checkpoint.inode = read["inode"]
        checkpoint.size = read["size"]
        checkpoint.offset = consumed_offset
        self.checkpoints.save(checkpoint)

        summary["end_offset"] = checkpoint.offset
        logger.info(
            f"Ingested {summary['events_processed']} events from {source}: "
            f"{summary['alerts_new']} new alerts, "
            f"{summary['incidents_new']} new incidents "
            f"across {summary['batches']} batch(es)"
        )
        return summary

    def _process_batch(self, batch: List[Event], summary: Dict[str, Any]) -> None:
        """Detect, correlate, and persist one bounded batch idempotently."""
        for alert in self.engine.match_events(batch):
            result = self.db.save_alert_dedup(alert)
            if result.get("is_suppressed"):
                summary["alerts_suppressed"] += 1
            elif result.get("is_duplicate"):
                summary["alerts_duplicate"] += 1
            else:
                summary["alerts_new"] += 1

        if self.correlator is not None:
            for incident in self.correlator.correlate(batch):
                saved = self.db.save_incident(incident)
                if not saved.get("is_duplicate"):
                    summary["incidents_new"] += 1
