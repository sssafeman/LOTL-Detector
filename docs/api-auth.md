# API Authentication: Scopes and Rotation

All endpoints except `/api/health` require a bearer API key. Keys now
carry scopes, and multiple keys can be valid at once to support rotation.
This extends the earlier single-key authentication work.

## Scopes

| Scope | Grants | Endpoints |
|-------|--------|-----------|
| `read` | Query detections | GET alerts, incidents, stats, rules, export |
| `scan` | read + trigger analysis | POST scan, ingest |
| `admin` | scan + change state | POST alert state, suppressions |

Scopes are hierarchical: `admin` implies `scan` implies `read`. A key
granted `scan` can also read; a key granted only `read` that calls a scan
endpoint gets `403 forbidden` (distinct from `401 unauthorized` for a
missing or unknown key).

## Configuring keys

Two ways, in precedence order.

**Multiple scoped keys (recommended)** via `LOTL_API_KEYS_FILE`, a JSON
list of records:

```json
[
  {"key": "…32+ chars…", "label": "dashboard", "scopes": ["read"]},
  {"key": "…32+ chars…", "label": "collector", "scopes": ["scan"]},
  {"key": "…32+ chars…", "label": "soc-admin", "scopes": ["admin"]}
]
```

Generate a record (the raw key is printed once, never logged):

```bash
python -m api.auth record --label collector --scopes read scan
```

**Single key** via `LOTL_API_KEY` (or `python -m api.auth generate`).
A single key is granted all scopes, matching the prior behavior.

Keys shorter than 32 characters are rejected. In tests the app can be
built with `API_KEYS` (list) or `API_KEY` (single) in the config, or an
injected `API_KEY_STORE`.

## Startup behavior

Startup fails closed. Without usable credentials (`LOTL_API_KEYS_FILE`,
`LOTL_API_KEY`, `LOTL_API_KEY_FILE`, or the default key file), `run.py`
and `api/server.py` refuse to start instead of serving unprotected
endpoints. A configured credential source that cannot be read is a
startup error, not a warning.

For a local demo only, `LOTL_ALLOW_UNAUTHENTICATED=1` runs the API
without authentication. Entry points refuse that bypass unless the
server binds to a loopback address, and debug mode is refused on
non-loopback bindings in every entry point.

## Rotation

Because the key store holds several keys at once, rotation is
zero-downtime:

1. Add a new record to the keys file with the same scopes as the old one.
2. Reload the server so both keys are valid.
3. Migrate callers to the new key.
4. Remove the old record and reload.

No request is ever rejected mid-rotation, since both keys authenticate
during the overlap window.

## Verification details

- The presented token is compared against every configured key in
  constant time (no early return), so timing cannot reveal a near match.
- The authenticated key's label and scopes are attached to Flask's `g`
  for downstream audit use.
- If no key store is configured on a non-test start, the server logs that
  it is running unprotected rather than silently allowing access.

## Limitations

- HMAC-style shared secrets: possession of a key grants its scopes. There
  is no per-request signing or short-lived tokens.
- No built-in expiry on keys; rotation is operator-driven.
- Scopes are coarse (three levels). Per-endpoint or per-rule
  authorization is future work.
