# Threat Model

Scope: the LOTL Detector framework itself, not the environments it
monitors. Covers the ingestion pipeline, detection engine, correlation
layer, SQLite store, and Flask API. Uses a STRIDE decomposition over the
trust boundaries. This document supports the portfolio and guides
hardening priorities.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Log sources (Sysmon XML, auditd logs) | Attacker-influenced input; parsing runs on it |
| Detection and chain rules (YAML) | Define what is caught; tampering blinds the sensor |
| Alert and incident database (SQLite) | Investigation record of truth; integrity is evidentiary |
| API bearer key | Grants read and scan access to all detections |
| Suppression and lifecycle state | Silencing rules can hide active intrusions |

## Trust Boundaries

1. Log source to collector. Log content is untrusted: an attacker who
   reaches a monitored host controls the command lines, process names,
   and audit fields the parser reads.
2. Client to API. Callers are untrusted until they present a valid
   bearer key. Everything except `/api/health` requires authentication.
3. Filesystem to scanner. The `/api/scan` endpoint takes a caller
   supplied path; without constraint this is arbitrary file read.
4. Rule author to loader. Rules are code-adjacent: a malicious or broken
   rule can crash loading or create blind spots.

## STRIDE Analysis

### Spoofing

- API request spoofing. Mitigated by bearer key auth with constant-time
  comparison (`api/auth.py`) on every non-health endpoint. Keys carry
  scopes (read, scan, admin), so a leaked read key cannot trigger scans or
  change state, and multiple keys can be valid at once for zero-downtime
  rotation (`docs/api-auth.md`). Residual: no per-user identity or key
  expiry; possession of a key still grants its scope.
- Host identity spoofing in events. Correlation keys on host fields from
  `raw_data`. A host that forges its hostname could split or merge its
  own lineage. Impact is limited to that host's own events because
  per-host trees never cross-link.

### Tampering

- Log injection. A crafted command line could try to inject fields or
  break the parser. Mitigated by structured parsing (Sysmon XML via
  ElementTree, auditd field regexes) rather than string concatenation.
  Detection matching is exact-basename and precompiled-regex, so
  substring spoofing like `notpowershell.exe` no longer evades or
  false-triggers (matching hardening, MoA finding 8).
- Path traversal on scan. Mitigated by `core/source_validator.py`:
  containment checks against allowed roots, symlink resolution,
  extension allowlist, and size limits.
- Rule tampering. Rules validate against a strict JSON schema
  (`additionalProperties: false`, `minProperties: 1`) and the
  rule-contract test suite fails CI if any operator is unenforced or any
  bundled rule silently fails to load.
- Database tampering. SQLite file has OS-level permissions only. An
  attacker with local write access can alter alerts. Out of scope for
  application controls; deploy with restricted file permissions.

### Repudiation

- Alert lifecycle changes (acknowledge, resolve, suppress) are recorded
  in the `alert_audit` table with author, reason, and timestamp. Residual:
  the author field is caller-asserted, not cryptographically bound.

### Information Disclosure

- Command lines contain sensitive data (credentials passed as
  arguments, internal hostnames). The API returns them to any caller with
  the read scope. Request logging deliberately omits command lines and
  request bodies (`api/server.py`). Residual: no field-level redaction;
  scopes gate actions but any read key still sees full command lines.
- Default binding is `127.0.0.1`. Debug mode is refused on non-loopback
  interfaces. CORS is closed by default and only opens to explicitly
  configured origins.

### Denial of Service

- Large log files. Batch parsing (`/api/scan`) loads full event lists
  into memory, bounded by scan size limits. The incremental ingestion
  path (`/api/ingest`, finding 16) processes new content in bounded
  batches with constant memory (benchmarked near 8 MB regardless of file
  size), so it is the memory-safe path for large or growing sources.
- Regex catastrophic backtracking. Rule regexes are attacker-adjacent
  (they run against attacker-influenced command lines). Patterns are
  precompiled at load time, which surfaces invalid patterns early but
  does not by itself prevent pathological backtracking. Rule authors
  must avoid nested quantifiers; a future guard could enforce timeouts.
- Correlation blowup. Tree walks are depth-capped (64) with cycle
  guards, and descendant iteration is bounded, so a corrupted or
  adversarial lineage cannot cause unbounded recursion.

### Elevation of Privilege

- The detector reads logs; it does not execute the commands it inspects.
  Response actions are advisory text, never executed. The main EoP risk
  is a parser or YAML deserialization flaw. Mitigated by `yaml.safe_load`
  and structured, non-eval parsing throughout.

## Residual Risks and Priorities

| Risk | Severity | Mitigation status |
|------|----------|-------------------|
| Leaked API key grants its scope | Medium | Scoped keys + rotation done; no expiry, no per-user identity |
| Memory DoS on huge logs | Low | Bounded incremental ingestion done (finding 16); batch path still loads fully |
| Regex backtracking on hostile command lines | Medium | Precompiled; needs match timeout guard |
| Command lines exposed to a read-scoped caller | Medium | Log redaction done; API redaction open |
| Database integrity relies on OS permissions | Medium | Document deployment hardening |
| Tampered rule distribution | Low | Signed rule packs done (finding 18); HMAC is symmetric, asymmetric is future work |
| Author fields are self-asserted | Low | Acceptable for single-tenant portfolio scope |

## Assumptions

- Single-tenant deployment behind a trusted network boundary or reverse
  proxy with TLS. The framework does not terminate TLS itself.
- Rules are authored by trusted operators and validated in CI before
  deployment. Rule packs are signed and verified before loading
  (`docs/rule-packs.md`); the HMAC scheme assumes a trusted shared key,
  and asymmetric signing for untrusted distribution is future work.
- The host running the detector is trusted; local attackers with write
  access to the database or rules are out of scope.
