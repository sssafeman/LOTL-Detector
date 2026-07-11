# Bounded Incremental Ingestion

The default pipeline is batch-oriented: `collect_events` and
`match_events` return complete lists. Large log files load fully into
memory, latency scales with file size, and a restart reprocesses
everything. This layer (MoA finding 16) adds restart-safe file tailing
with durable checkpoints, bounded batches, and idempotent writes.

Scope is line-oriented sources, Linux auditd first. The finding
sequences file tailing before Windows Event Log subscriptions, which
remain follow-up work. Batch import stays available unchanged as a
separate path (`/api/scan`).

## Components (`core/ingest.py`)

| Piece | Responsibility |
|-------|----------------|
| `Checkpoint` | Byte offset, inode, size, and event count for one source |
| `read_new_text` | Reads only complete new lines; detects rotation/truncation |
| `chunked` | Splits an event iterator into bounded, constant-memory batches |
| `CheckpointStore` | Persists checkpoints in the `ingest_checkpoints` table |
| `IngestionService` | Orchestrates read, parse, batch, detect, correlate, save, checkpoint |
| `linux_auditd_parser` | Adapts a `LinuxCollector` to parse incremental line buffers |

## How a run works

1. Load the source's checkpoint (or a fresh zero checkpoint).
2. `read_new_text` seeks to the stored offset and reads to EOF, holding
   back any trailing partial line so a half-written record is never
   parsed. The reported offset advances only past complete lines.
3. If the file's inode changed or its size dropped below the stored
   offset, the source was rotated or truncated: reading restarts from
   zero and the run is flagged `reset`.
4. New text is parsed into events, then processed in bounded batches.
5. For each batch: run the detection engine, save alerts with dedup, run
   the correlator, save incidents. Then advance and persist the
   checkpoint. A crash resumes at the last committed batch.

## Idempotency

Writes are idempotent through the existing fingerprint dedup. If a
checkpoint is lost and content is reprocessed from offset zero, alerts
and incidents dedupe against their prior rows instead of duplicating.
This is why the checkpoint can be advanced eagerly after each batch
without risking data loss on a mid-run crash: at worst a boundary batch
is reprocessed and deduped.

## Bounds and limitations

- **Per-batch correlation.** Chains are correlated within a batch. A
  chain whose stages straddle a batch boundary is not matched. Raise
  `batch_size` above the expected events-per-window to avoid splitting
  real chains, at the cost of more memory per batch.
- **Line-oriented only.** auditd and generic newline-delimited logs.
  Windows Event Log uses the subscription API, not file tailing, and is
  not yet wired in.
- **Single-process checkpoints.** The checkpoint table assumes one
  ingester per source. Concurrent ingesters on the same source are not
  coordinated.

## Usage

API:

```bash
POST /api/ingest
{"platform": "linux", "log_path": "/var/log/audit/audit.log", "batch_size": 500}
```

Returns a summary: `events_processed`, `alerts_new`, `alerts_duplicate`,
`alerts_suppressed`, `incidents_new`, `batches`, `reset`, and the
`start_offset` / `end_offset`. Call it on a schedule (cron, timer) to
tail a growing audit log; each call processes only what arrived since the
last.

Library:

```python
from core.ingest import IngestionService, linux_auditd_parser
from collectors.linux.collector import LinuxCollector

parser = linux_auditd_parser(LinuxCollector())
service = IngestionService(db, engine, parser, correlator=correlator, batch_size=500)
summary = service.ingest_file("/var/log/audit/audit.log")
```
