# macOS Collector

The macOS collector consumes **Endpoint Security exec events** in
newline-delimited JSON, as produced by `eslogger exec` (macOS 11+).
Endpoint Security is Apple's supported framework for process execution
telemetry, so this is the realistic collection path rather than scraping
the unified log, which does not carry process command lines.

This replaces the previous empty stub and makes the framework genuinely
cross-platform (Windows, Linux, macOS).

## Collection

Point `eslogger` at exec events and capture NDJSON:

```bash
sudo eslogger exec > /var/log/lotl/exec.ndjson
```

Each line is one `ES_EVENT_TYPE_NOTIFY_EXEC` message. The collector reads
a file or a directory of `.ndjson` / `.json` / `.log` files.

## Field mapping

In an ES exec event, the acting process image
(`process.executable.path`) is the pre-exec image, which for a freshly
forked child is the parent program (typically a shell), and
`event.exec.target` is the program that was executed. The collector maps:

| Event field | ES source |
|-------------|-----------|
| `process_name` | basename of `event.exec.target.executable.path` |
| `command_line` | `event.exec.args` joined with spaces |
| `parent_process_name` | basename of `process.executable.path` |
| `process_id` | `process.audit_token.pid` |
| `parent_process_id` | `process.ppid` |
| `user` | `process.audit_token.euid` (`0` becomes `root`, else `uid:<n>`) |
| `timestamp` | `time` (ISO 8601 or epoch seconds) |

Records that are not exec events, or are malformed JSON, are skipped
rather than raising, so a mixed or partial log still yields its valid
events.

## Incremental ingestion

The collector exposes `events_from_lines` and `events_from_text`, so the
bounded ingestion layer (`docs/ingestion.md`) tails a growing NDJSON file
the same way it tails auditd and Sysmon: byte-offset checkpoints,
rotation detection, bounded batches, idempotent writes. NDJSON records
are single lines, so the whole complete-line buffer is consumed each run.

Use it via `POST /api/ingest` with `"platform": "macos"`, or the library
`macos_eslogger_parser`.

## Rules

Five macOS detection rules ship with the collector (see
`docs/coverage-matrix.md`): osascript shell execution, curl/wget download
to shell, LaunchAgent/Daemon persistence via launchctl, Gatekeeper
disable via spctl, and local account creation via dscl. Each has malicious
and benign fixtures and integration tests.

## Limitations

- Consumes captured NDJSON, not a live Endpoint Security client stream.
  Live streaming is future work.
- `eslogger` requires Full Disk Access and root, per Apple's Endpoint
  Security entitlement model.
- User identity is the numeric euid; resolving it to a username needs a
  directory lookup not available offline.
