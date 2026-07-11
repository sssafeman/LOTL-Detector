# Rule Pack Signing and Distribution

Manual YAML deployment does not scale, and unsigned automatic updates are
a supply-chain risk: an attacker who can write to the rules directory can
silence detections or inject malicious logic. This is the distribution
half of MoA finding 18 (the SIEM export half is in `docs/` via
`core/export.py`).

A **rule pack** is a directory of rule files plus a signed manifest that
pins every file's SHA-256 hash, the pack version, and the engine contract
version the pack targets. Nothing is trusted until the manifest signature
and every file hash verify.

## Components (`core/rulepack.py`)

| Piece | Responsibility |
|-------|----------------|
| `build_manifest` | Hash every rule file, record versions |
| `build_pack` | Copy rules, write signed `manifest.json` + `manifest.sig` |
| `verify_pack` | Recompute hashes, check signature and compatibility |
| `load_verified_rules` | Verify, then load with the standard RuleLoader |
| `PackRegistry` | Staged activation, rollback, audit trail |

## Manifest

```json
{
  "pack_format_version": 1,
  "pack_version": "2026.07.11",
  "engine_min_version": 2,
  "created_at": "2026-07-11T12:00:00",
  "rule_count": 28,
  "rules": [
    {"path": "schema.json", "sha256": "..."},
    {"path": "windows/certutil_download.yml", "sha256": "..."}
  ]
}
```

The manifest is serialized canonically (sorted keys, no whitespace) and
signed with HMAC-SHA256. `manifest.sig` holds the hex signature.

## Verification

`verify_pack` checks, in order:

1. `manifest.json` and `manifest.sig` are present.
2. The signature matches the manifest bytes (constant-time compare).
3. `pack_format_version` is supported by this build.
4. `engine_min_version` is not newer than the engine contract this build
   implements.
5. Every listed file exists and its SHA-256 matches.
6. No unlisted rule file is present (blocks smuggled-in rules).

Any failure marks the pack invalid with a specific reason.
`load_verified_rules` raises before loading, so unverified rules never
reach the engine.

## Signing key

Signing uses a shared HMAC secret, supplied via the `LOTL_RULEPACK_KEY`
environment variable for the CLI or passed as bytes to the API. The key
is never logged and never written into a pack. This defends against
tampering by anyone without the key, which suits a single-tenant
deployment.

The natural upgrade is asymmetric signing: the publisher signs with a
private key and every client verifies with the public key, so clients
cannot forge packs even if compromised. The manifest and verification
flow are unchanged by that swap; only `_sign` and the key handling move
from HMAC to a public-key signature.

## Staged activation and rollback

`PackRegistry` manages verified packs under a root directory:

- `stage(pack_dir, key)`: verify, then copy into `versions/<version>/`.
- `activate(version, key)`: re-verify the staged version and make it
  active, pushing the previous active version onto a history stack.
- `rollback(key)`: re-verify and restore the previous version.
- Every action appends to `audit.log` with a timestamp.

Exactly one version is active at a time (`active.json`). The registry
never activates a version that fails verification, so a rollback target
is always a known-good pack.

## CLI

```bash
export LOTL_RULEPACK_KEY='your-secret'
python -m core.rulepack build rules dist/pack-2026.07.11 --version 2026.07.11
python -m core.rulepack verify dist/pack-2026.07.11
```

## Limitations

- HMAC is symmetric: any party that can verify can also sign. Move to
  asymmetric signatures for untrusted distribution.
- The registry assumes a single writer; it does not lock against
  concurrent activation.
- Compatibility is a single integer contract version. Finer-grained
  capability negotiation (per-operator support) is future work.
