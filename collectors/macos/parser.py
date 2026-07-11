"""
Helpers for parsing macOS Endpoint Security exec events.

The source format is newline-delimited JSON as emitted by `eslogger exec`
(macOS 11+), the Apple-supported way to capture process execution. Each
line is one ES_EVENT_TYPE_NOTIFY_EXEC message. In an exec event the acting
process image (`process.executable.path`) is the pre-exec image, which for
a freshly forked child is the parent program (a shell), and
`event.exec.target` is the program that was executed. We map the target to
the process fields and the acting image to the parent, which matches how
living-off-the-land chains appear (bash then curl, zsh then osascript).
"""
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


def basename(path: str) -> str:
    """Return the trailing component of a POSIX path."""
    if not path:
        return ""
    return os.path.basename(path.rstrip("/")) or path


def parse_es_timestamp(value: Any) -> datetime:
    """
    Parse an ES event timestamp.

    Accepts ISO 8601 strings (with Z or offset) and numeric epoch seconds.
    Falls back to a fixed epoch-derived time on failure so a malformed
    timestamp does not drop an otherwise valid event.
    """
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str) and value:
        text = value.strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            pass
    logger.debug(f"Unparseable ES timestamp: {value!r}")
    return datetime.fromtimestamp(0, tz=timezone.utc)


def _uid_to_user(token: Dict[str, Any]) -> str:
    """
    Derive a user string from an ES audit_token.

    Prefers euid, then ruid. 0 maps to root; other ids become "uid:<n>".
    Returns empty string when no id is present.
    """
    for field in ("euid", "ruid", "uid"):
        if field in token and token[field] is not None:
            uid = token[field]
            return "root" if uid == 0 else f"uid:{uid}"
    return ""


def parse_exec_event(raw: Any) -> Optional[Dict[str, Any]]:
    """
    Parse one ES exec event into a normalized field dict.

    Args:
        raw: A JSON string or already-decoded dict for one ES exec event

    Returns:
        Dict with process_name, command_line, user, process_id,
        parent_process_name, parent_process_id, working_directory, and the
        original record, or None when the record is not a usable exec event.
    """
    if isinstance(raw, str):
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.debug(f"Skipping non-JSON line: {e}")
            return None
    elif isinstance(raw, dict):
        record = raw
    else:
        return None

    event = record.get("event", {})
    exec_event = event.get("exec")
    if not exec_event:
        # Not an exec event (eslogger can be pointed at other event types).
        return None

    target = exec_event.get("target", {})
    target_path = (target.get("executable") or {}).get("path", "")
    args = exec_event.get("args") or target.get("args") or []
    if not target_path and not args:
        return None

    process = record.get("process", {})
    acting_path = (process.get("executable") or {}).get("path", "")
    audit_token = process.get("audit_token") or {}

    command_line = " ".join(str(a) for a in args) if args else basename(target_path)
    pid = audit_token.get("pid", process.get("pid", 0)) or 0
    ppid = process.get("ppid")
    cwd = exec_event.get("cwd") or (exec_event.get("script") or {}).get("cwd")
    user = record.get("user") or _uid_to_user(audit_token)

    return {
        "process_name": basename(target_path) or (args[0] if args else ""),
        "command_line": command_line,
        "user": user,
        "process_id": int(pid) if isinstance(pid, (int, str)) and str(pid).isdigit() else 0,
        "parent_process_name": basename(acting_path) if acting_path else None,
        "parent_process_id": ppid,
        "working_directory": cwd,
        "timestamp": record.get("time") or record.get("timestamp"),
        "raw": record,
    }


def split_ndjson(text: str) -> List[str]:
    """Split a text buffer into non-empty NDJSON lines."""
    return [line for line in text.splitlines() if line.strip()]
