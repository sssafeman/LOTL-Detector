"""
Log source validation for LOTL-Detector.

Provides containment-based path validation to prevent path traversal
and unauthorized file access through the scan API.
"""
import os
from pathlib import Path
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

# Default allowed extensions per platform
ALLOWED_EXTENSIONS = {
    "windows": {".log", ".xml", ".evtx", ".json"},
    "linux": {".log", ".json", ".txt"},
}

# Default max file size: 100 MB
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024

# Max directory recursion depth
MAX_RECURSION_DEPTH = 10


class SourceValidationError(ValueError):
    """Raised when a log source fails validation."""
    pass


def validate_log_source(
    source: str,
    platform: str,
    allowed_roots: Optional[List[str]] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> str:
    """
    Validate a log source path for safe access.

    Checks:
    1. Path is not empty
    2. Path exists
    3. Path is a regular file or directory (not device, pipe, socket)
    4. If allowed_roots is configured, path is contained within a root
    5. Symlinks are resolved and the real path is checked for containment
    6. File extension is in the allowed set (for files)
    7. File size is within limits (for files)

    Args:
        source: Path to log file or directory
        platform: 'windows' or 'linux' (determines allowed extensions)
        allowed_roots: List of allowed root directories. If None or empty,
                       any path is allowed (backward compatible, but less secure).
        max_file_size: Maximum file size in bytes for individual files.

    Returns:
        The resolved real path string if validation passes.

    Raises:
        SourceValidationError: If validation fails with a specific reason.
    """
    if not source or not source.strip():
        raise SourceValidationError("Log source path is empty")

    source = source.strip()

    # Resolve symlinks and get real path
    try:
        real_path = Path(source).resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise SourceValidationError(f"Cannot resolve path: {e}")

    # Check existence
    if not real_path.exists():
        raise SourceValidationError(f"Log source does not exist: {source}")

    # Reject special files (devices, pipes, sockets)
    if not real_path.is_file() and not real_path.is_dir():
        raise SourceValidationError(
            f"Log source is not a regular file or directory: {source}"
        )

    # Containment check if allowed roots are configured
    if allowed_roots:
        contained = False
        real_str = str(real_path)
        for root in allowed_roots:
            root_resolved = str(Path(root).resolve(strict=False))
            if real_str == root_resolved or real_str.startswith(
                root_resolved + os.sep
            ):
                contained = True
                break
        if not contained:
            raise SourceValidationError(
                f"Log source is outside allowed roots: {source}. "
                f"Allowed roots: {allowed_roots}"
            )

    # File-specific checks
    if real_path.is_file():
        # Extension check
        ext = real_path.suffix.lower()
        allowed_exts = ALLOWED_EXTENSIONS.get(platform, set())
        if allowed_exts and ext not in allowed_exts:
            raise SourceValidationError(
                f"File extension '{ext}' not allowed for platform '{platform}'. "
                f"Allowed: {sorted(allowed_exts)}"
            )

        # Size check
        try:
            file_size = real_path.stat().st_size
            if file_size > max_file_size:
                raise SourceValidationError(
                    f"File size {file_size} bytes exceeds limit {max_file_size} bytes"
                )
        except OSError as e:
            raise SourceValidationError(f"Cannot stat file: {e}")

    # Directory checks
    if real_path.is_dir():
        # Check for excessive depth (potential path traversal via nested dirs)
        depth = len(real_path.parts)
        if depth > 20:
            raise SourceValidationError(
                f"Directory path depth {depth} exceeds safe limit"
            )

    logger.debug(f"Log source validated: {source} -> {real_path}")
    return str(real_path)
