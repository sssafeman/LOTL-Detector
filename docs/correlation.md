# Process Tree Correlation

## Overview

Single-event matching misses behavior chains. An Office application
launching PowerShell looks ambiguous on its own, and an encoded PowerShell
command from an unknown parent is only a medium-confidence signal. The same
two observations linked through process lineage inside a short time window
are a high-confidence intrusion indicator.

The correlation layer sits above atomic rules and never replaces them.
Atomic alerts are generated exactly as before. Correlation additionally
emits incidents: full chain matches that preserve every supporting event.

This implements finding 17 from the MoA review: bounded time-window
sequences keyed by host and process lineage, correlated incidents with
supporting events, and deterministic replay.

## Components

| Component | File | Responsibility |
|-----------|------|----------------|
| Process tree | `core/process_tree.py` | Per-host lineage from event batches |
| Correlator | `core/correlator.py` | Chain rule loading, sequence matching, incident scoring |
| Chain schema | `rules/chain-schema.json` | Strict validation for chain rules |
| Chain rules | `rules/correlation/*.yml` | Bundled behavior chains |
| Persistence | `core/database.py` | `incidents` table, `save_incident`, `get_incidents` |
| API | `api/server.py` | Correlation in `/api/scan`, `GET /api/incidents` |

## Process Tree Construction

Events are grouped by host identity (from `raw_data` host fields, empty
string when unavailable) so pid collisions across hosts never produce false
lineage. Within a host:

1. Every event becomes a concrete node.
2. A child links to the latest event whose pid equals the child's
   `parent_process_id` at or before the child's timestamp.
3. When the child also declares a `parent_process_name` and that name
   disagrees with the candidate's basename, the link is refused. This is
   the pid reuse guard.
4. When no concrete parent exists, a phantom node is synthesized from the
   child's parent fields. Phantom nodes carry a process name and pid but
   no command line, user, or timestamp. Phantoms merge by (pid, name) when
   the pid is known; without a pid every child gets its own phantom so
   unrelated processes are never linked through a shared parent name.

Phantom nodes matter in practice: the parent process (an Office
application, a web server) usually started before log collection began,
so it has no process creation event of its own. Chains anchored on a
name-only first stage still match through the phantom, at reduced
confidence.

Ancestry and subtree walks are capped at depth 64 with cycle guards.

## Chain Rule Format

Chain rules live in `rules/correlation/` and validate against
`rules/chain-schema.json` (additionalProperties: false throughout).

```yaml
name: "Office Application Spawning Obfuscated PowerShell"
id: "CHAIN-WIN-001"
platform: windows
severity: critical
mitre_attack:
  - T1566.001
  - T1059.001
window_seconds: 300
stages:
  - name: "office_parent"
    match:
      process_name_any:
        - "winword.exe"
        - "excel.exe"
  - name: "obfuscated_shell_child"
    relation: descendant
    match:
      process_name_any:
        - "powershell.exe"
      command_contains_any:
        - "-encodedcommand"
response:
  - "Isolate the host and acquire the originating document."
```

Fields:

- `id`: `CHAIN-(WIN|LNX|MAC)-NNN`. Duplicate IDs are rejected at load time.
- `window_seconds`: maximum seconds between the earliest and latest
  observed events in a match (1 to 86400).
- `stages`: ordered list, minimum 2. Each stage has:
  - `name`: label used in incident output.
  - `relation`: `child` (direct child of the previous stage's process,
    default) or `descendant` (anywhere in its subtree). Ignored on the
    first stage, which anchors the chain.
  - `match`: one or more of `process_name`, `process_name_any`,
    `command_contains` (AND), `command_contains_any` (OR),
    `command_regex`, `user_pattern`. Same semantics and platform-aware
    basename normalization as atomic rules. Regexes are precompiled at
    load time with early validation.

A stage that constrains the command line or user can never match a
phantom node, since phantoms have no command telemetry.

## Matching Semantics

For each host tree and each chain:

1. Anchor candidates are all nodes matching stage 0, examined in
   (timestamp, pid, key) order.
2. From each anchor, a depth-first search matches the remaining stages
   against children or descendants of the previously matched node,
   also in sorted order, taking the earliest valid completion.
3. Observed timestamps must be non-decreasing along the chain, and the
   span between the earliest and latest observed events must fit inside
   `window_seconds`. Phantom nodes are exempt from time checks.
4. Completed paths deduplicate on their node set, and incidents sort by
   first timestamp then chain ID.

The ordering rules make correlation replay-safe: the same event batch
always yields byte-identical incidents, which the test suite asserts.

## Incident Scoring

Scoring reuses the v2 multiplicative model so incidents and alerts stay
comparable:

```
score = clamp(round(severity * (0.25 + 0.75 * confidence / 100) * 1.5), 0, 150)
```

Severity comes from the chain rule (same subscores as atomic rules).
Confidence is evidence-based:

- 70 base for any complete lineage match
- +10 when every stage matched an observed event (no phantom parents)
- +5 per stage beyond the second
- capped at 100

Examples: a critical two-stage chain with full telemetry scores 128
(critical band); the same chain through a phantom parent scores 116
(high band); a critical three-stage chain with full telemetry scores 133.
Risk bands use the same thresholds as the alert scorer.

## Persistence and API

Incidents are stored in the `incidents` table with a stable SHA-256
fingerprint computed from the chain ID, platform, host, and each stage's
normalized process name, pid, and timestamp. Rescanning the same log
deduplicates instead of inserting.

- `POST /api/scan` now returns `incidents_generated` and
  `incident_results` alongside the existing alert fields.
- `GET /api/incidents` supports `chain_id`, `severity`, `platform`,
  `min_score`, and `limit` filters. Requires authentication like all
  non-health endpoints.

The CLI (`demo_detector.py`) prints a CORRELATED INCIDENTS section in
both demo and scan modes, marking each stage as an observed event or an
inferred (phantom) parent.

## Bundled Chains

| ID | Chain | Severity |
|----|-------|----------|
| CHAIN-WIN-001 | Office application to obfuscated PowerShell | critical |
| CHAIN-WIN-002 | Script host to LOLBin downloader | high |
| CHAIN-LNX-001 | Web server to shell to payload retrieval | critical |
| CHAIN-LNX-002 | Cron to shell to remote download | high |
| CHAIN-MAC-001 | Osascript to shell to network download | critical |

## Limitations

- Correlation runs per scan batch. Chains split across separate scan
  invocations do not match; streaming correlation depends on the
  bounded incremental ingestion work (finding 16).
- Lineage relies on collector-provided parent pid and name. Sources
  without parent telemetry degrade to phantom-based matching.
- Incident suppression and lifecycle states are not yet implemented;
  incidents currently support fingerprint deduplication only.
