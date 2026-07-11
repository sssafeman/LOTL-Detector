"""
API authentication module for LOTL-Detector.

Static bearer API key authentication. The key is loaded from:
  1. LOTL_API_KEY environment variable
  2. LOTL_API_KEY_FILE file path
  3. Default file: ~/.config/lotl-detector/api.key

Key generation: python -m api.auth generate
"""
import os
import hmac
import json
import secrets
import logging
from dataclasses import dataclass
from pathlib import Path
from functools import wraps
from typing import Dict, FrozenSet, List, Optional
from flask import request, jsonify, g

logger = logging.getLogger(__name__)

DEFAULT_KEY_DIR = Path.home() / ".config" / "lotl-detector"
DEFAULT_KEY_FILE = DEFAULT_KEY_DIR / "api.key"
MIN_KEY_LENGTH = 32

# Access scopes, from least to most privileged. admin implies scan
# implies read, so a key granted a scope also holds the ones below it.
SCOPES = ("read", "scan", "admin")


def expand_scopes(scopes) -> FrozenSet[str]:
    """
    Expand a set of granted scopes to include implied lower scopes.

    admin grants everything; scan additionally grants read.
    Unknown scope names are ignored.
    """
    granted = {s for s in scopes if s in SCOPES}
    if "admin" in granted:
        return frozenset(SCOPES)
    if "scan" in granted:
        granted.add("read")
    return frozenset(granted)


@dataclass(frozen=True)
class KeyRecord:
    """One API key with a label and its expanded scope set."""
    token: str
    label: str
    scopes: FrozenSet[str]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


class KeyStore:
    """
    Holds one or more API keys, each with scopes, for auth and rotation.

    Multiple simultaneously valid keys are how rotation works: add the new
    key alongside the old, migrate callers, then remove the old key. Lookup
    compares a presented token against every key in constant time so a near
    match cannot be found by timing.
    """

    def __init__(self, records: List[KeyRecord]):
        self._records = list(records)

    def __len__(self) -> int:
        return len(self._records)

    @property
    def labels(self) -> List[str]:
        return [r.label for r in self._records]

    def authenticate(self, token: str) -> Optional[KeyRecord]:
        """
        Return the KeyRecord matching a token, or None.

        Every record is compared (no early return) so total work does not
        depend on which key, if any, matched.
        """
        token_bytes = token.encode()
        matched: Optional[KeyRecord] = None
        for record in self._records:
            if hmac.compare_digest(token_bytes, record.token.encode()):
                matched = record
        return matched

    @classmethod
    def from_single(cls, key: str, scopes=SCOPES) -> "KeyStore":
        """Build a store from one key (all scopes by default)."""
        return cls([KeyRecord(key, "default", expand_scopes(scopes))])

    @classmethod
    def from_records(cls, records: List[Dict]) -> "KeyStore":
        """
        Build a store from a list of dicts:
        [{"key": "...", "label": "...", "scopes": ["read", "scan"]}, ...]
        """
        parsed = []
        for i, rec in enumerate(records):
            key = (rec.get("key") or "").strip()
            if not key or len(key) < MIN_KEY_LENGTH:
                logger.warning(
                    f"Skipping key #{i} ({rec.get('label', '?')}): "
                    f"missing or shorter than {MIN_KEY_LENGTH} chars"
                )
                continue
            label = rec.get("label", f"key-{i}")
            scopes = expand_scopes(rec.get("scopes", ["read"]))
            parsed.append(KeyRecord(key, label, scopes))
        return cls(parsed)

    @classmethod
    def load(cls) -> Optional["KeyStore"]:
        """
        Load a KeyStore from the environment.

        Precedence: LOTL_API_KEYS_FILE (JSON list of key records), then
        LOTL_API_KEY (single key, all scopes). Returns None if neither is
        set, matching the unauthenticated fallback.
        """
        keys_file = os.environ.get("LOTL_API_KEYS_FILE")
        if keys_file:
            try:
                records = json.loads(Path(keys_file).read_text())
                store = cls.from_records(records)
                if len(store):
                    return store
                logger.error(f"No valid keys in {keys_file}")
            except Exception as e:
                logger.error(f"Failed to load keys file {keys_file}: {e}")

        single = load_api_key()
        if single:
            return cls.from_single(single)
        return None


def load_api_key() -> str | None:
    """
    Load the API key from env var, file path, or default file.

    Returns:
        The API key string, or None if no key is configured.
    """
    # 1. Environment variable
    key = os.environ.get("LOTL_API_KEY")
    if key:
        key = key.strip()
        if len(key) >= MIN_KEY_LENGTH:
            return key
        logger.warning(f"LOTL_API_KEY is shorter than {MIN_KEY_LENGTH} chars, ignoring")

    # 2. File path from env var
    key_file_path = os.environ.get("LOTL_API_KEY_FILE")
    if key_file_path:
        key = _read_key_file(Path(key_file_path))
        if key:
            return key

    # 3. Default file
    if DEFAULT_KEY_FILE.exists():
        key = _read_key_file(DEFAULT_KEY_FILE)
        if key:
            return key

    return None


def _read_key_file(path: Path) -> str | None:
    """Read an API key from a file, stripping whitespace."""
    try:
        content = path.read_text().strip()
        if content and len(content) >= MIN_KEY_LENGTH:
            return content
        if content:
            logger.warning(f"API key in {path} is shorter than {MIN_KEY_LENGTH} chars")
        return None
    except Exception as e:
        logger.error(f"Failed to read API key file {path}: {e}")
        return None


def generate_api_key(output_file: Path | None = None) -> str:
    """
    Generate a new cryptographically random API key.

    Args:
        output_file: Where to write the key. Defaults to ~/.config/lotl-detector/api.key

    Returns:
        The generated key string.
    """
    key = secrets.token_urlsafe(32)

    if output_file is None:
        output_file = DEFAULT_KEY_FILE

    output_file.parent.mkdir(parents=True, exist_ok=True)
    # Create directory with 0700
    output_file.parent.chmod(0o700)
    # Write key with trailing newline
    output_file.write_text(key + "\n")
    # Set file permissions to 0600
    output_file.chmod(0o600)

    logger.info(f"API key generated and saved to {output_file}")
    return key


def require_auth(api_key: str):
    """
    Flask decorator that requires a valid Bearer API key.

    Args:
        api_key: The expected API key string.

    Returns:
        Decorator function.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for Authorization header
            auth_header = request.headers.get("Authorization", "")

            if not auth_header:
                return _unauthorized_response()

            # Must be "Bearer <token>"
            parts = auth_header.split(" ", 1)
            if len(parts) != 2 or parts[0] != "Bearer":
                return _unauthorized_response()

            provided_token = parts[1].strip()
            if not provided_token:
                return _unauthorized_response()

            # Constant-time comparison to prevent timing attacks
            if not hmac.compare_digest(provided_token.encode(), api_key.encode()):
                return _unauthorized_response()

            g.authenticated = True
            return f(*args, **kwargs)

        return decorated_function
    return decorator


def _extract_bearer_token() -> Optional[str]:
    """Return the bearer token from the Authorization header, or None."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0] != "Bearer":
        return None
    token = parts[1].strip()
    return token or None


def require_scope(store: "KeyStore", scope: str):
    """
    Flask decorator requiring a valid key that holds the given scope.

    A missing or unknown key returns 401. A valid key that lacks the scope
    returns 403, so operators can tell "not authenticated" from "not
    authorized". The authenticated key's label and scopes are placed on
    Flask's g for downstream audit use.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = _extract_bearer_token()
            if not token:
                return _unauthorized_response()
            record = store.authenticate(token)
            if record is None:
                return _unauthorized_response()
            if not record.has_scope(scope):
                return _forbidden_response(scope)
            g.authenticated = True
            g.auth_label = record.label
            g.auth_scopes = sorted(record.scopes)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def _unauthorized_response():
    """Return a standard 401 response without revealing the failure reason."""
    response = jsonify({"error": "unauthorized"})
    response.status_code = 401
    response.headers["WWW-Authenticate"] = "Bearer"
    return response


def _forbidden_response(scope: str):
    """Return a 403 response naming the scope the key is missing."""
    response = jsonify({
        "error": "forbidden",
        "message": f"this key lacks the required scope: {scope}",
    })
    response.status_code = 403
    return response


def generate_key_record(label: str, scopes: List[str]) -> Dict:
    """
    Generate a new key record dict for a keys file, without writing it.

    Returns {"key", "label", "scopes"}. The caller decides where to store
    it; the raw key is only returned, never logged.
    """
    return {
        "key": secrets.token_urlsafe(32),
        "label": label,
        "scopes": [s for s in scopes if s in SCOPES] or ["read"],
    }


def main():
    """
    CLI for key management.

      python -m api.auth generate
          Write a single all-scope key to the default key file.

      python -m api.auth record --label reader --scopes read scan
          Print a JSON key record for a keys file (LOTL_API_KEYS_FILE).
    """
    import sys
    argv = sys.argv[1:]
    if argv and argv[0] == "generate":
        key = generate_api_key()
        print(f"API key generated and saved to {DEFAULT_KEY_FILE}")
        print(f"Key length: {len(key)} characters")
        print("Store this key securely. Use it in the Authorization header:")
        print("  Authorization: Bearer <your-key>")
        print()
        print("Or set the LOTL_API_KEY environment variable.")
    elif argv and argv[0] == "record":
        import argparse
        parser = argparse.ArgumentParser(prog="api.auth record")
        parser.add_argument("--label", required=True)
        parser.add_argument(
            "--scopes", nargs="+", default=["read"], choices=list(SCOPES)
        )
        args = parser.parse_args(argv[1:])
        record = generate_key_record(args.label, args.scopes)
        print(json.dumps([record], indent=2))
        print()
        print("Append this to your LOTL_API_KEYS_FILE (a JSON list of records).")
        print("Rotate by adding a new record, migrating callers, then removing the old.")
    else:
        print("Usage: python -m api.auth generate | record --label L --scopes ...")


if __name__ == "__main__":
    main()
