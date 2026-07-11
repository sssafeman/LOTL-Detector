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
  comparison (`api/auth.py`) on every non-health endpoint. Residual: no
  per-user identity or key rotation; a leaked key is fully privileged.
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
  arguments, internal hostnames). The API returns them to any
  authenticated caller. Request logging deliberately omits command lines
  and request bodies (`api/server.py`). Residual: no field-level redaction
  or role-based access.
- Default binding is `127.0.0.1`. Debug mode is refused on non-loopback
  interfaces. CORS is closed by default and only opens to explicitly
  configured origins.

### Denial of Service

- Large log files. Batch parsing loads full event lists into memory.
  Mitigated partially by scan size limits; fully addressing this is the
  bounded incremental ingestion work (MoA finding 16).
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
| Leaked API key is fully privileged | High | Single shared key; add rotation and scopes |
| No streaming ingestion, memory DoS on huge logs | Medium | Partial (size limits); finding 16 open |
| Regex backtracking on hostile command lines | Medium | Precompiled; needs match timeout guard |
| Command lines exposed to any authenticated caller | Medium | Log redaction done; API redaction open |
| Database integrity relies on OS permissions | Medium | Document deployment hardening |
| Author fields are self-asserted | Low | Acceptable for single-tenant portfolio scope |

## Assumptions

- Single-tenant deployment behind a trusted network boundary or reverse
  proxy with TLS. The framework does not terminate TLS itself.
- Rules are authored by trusted operators, validated in CI before
  deployment. Untrusted rule distribution (signing, manifests) is future
  work (MoA finding 18).
- The host running the detector is trusted; local attackers with write
  access to the database or rules are out of scope.
