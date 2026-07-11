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
import secrets
import logging
from pathlib import Path
from functools import wraps
from flask import request, jsonify, g

logger = logging.getLogger(__name__)

DEFAULT_KEY_DIR = Path.home() / ".config" / "lotl-detector"
DEFAULT_KEY_FILE = DEFAULT_KEY_DIR / "api.key"
MIN_KEY_LENGTH = 32


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


def _unauthorized_response():
    """Return a standard 401 response without revealing the failure reason."""
    response = jsonify({"error": "unauthorized"})
    response.status_code = 401
    response.headers["WWW-Authenticate"] = "Bearer"
    return response


def main():
    """CLI entry point for key generation: python -m api.auth generate"""
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "generate":
        key = generate_api_key()
        print(f"API key generated and saved to {DEFAULT_KEY_FILE}")
        print(f"Key length: {len(key)} characters")
        print("Store this key securely. Use it in the Authorization header:")
        print(f"  Authorization: Bearer <your-key>")
        print()
        print("Or set the LOTL_API_KEY environment variable.")
    else:
        print("Usage: python -m api.auth generate")


if __name__ == "__main__":
    main()