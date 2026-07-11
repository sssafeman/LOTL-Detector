"""
Alert fingerprinting for deduplication.

Computes a stable SHA-256 fingerprint from normalized alert fields.
Two alerts with the same fingerprint represent the same detection episode.
"""
import hashlib
import json
import unicodedata
import re
from typing import Dict, Any
from collectors.base import Event
from core.engine import Alert, normalize_process_name

FINGERPRINT_VERSION = 1


def normalize_text(value: Any) -> str:
    """Normalize a value to a stripped NFC Unicode string."""
    if value is None:
        return ""
    text = unicodedata.normalize("NFC", str(value))
    return text.strip()


def normalize_platform(platform: str) -> str:
    """Normalize platform string."""
    return normalize_text(platform).casefold()


def normalize_command_line(cmd: str, platform: str) -> str:
    """
    Normalize command line for fingerprinting.

    NFC normalize, trim, collapse whitespace outside quotes.
    Windows: casefold. Linux/macOS: preserve case.
    """
    text = normalize_text(cmd)
    # Collapse runs of whitespace to single space, preserve quoted content
    # Simple approach: collapse whitespace outside quotes
    result = []
    in_quote = False
    quote_char = ""
    i = 0
    while i < len(text):
        char = text[i]
        if char in ('"', "'") and not in_quote:
            in_quote = True
            quote_char = char
            result.append(char)
        elif char == quote_char and in_quote:
            in_quote = False
            quote_char = ""
            result.append(char)
        elif char.isspace() and not in_quote:
            # Collapse whitespace to single space
            if result and not result[-1].isspace():
                result.append(" ")
        else:
            result.append(char)
        i += 1

    normalized = "".join(result).strip()
    if platform == "windows":
        normalized = normalized.casefold()
    return normalized


def normalize_user(user: str, platform: str) -> str:
    """Normalize user string. Windows: casefold. Linux/macOS: preserve case."""
    text = normalize_text(user)
    # Collapse internal whitespace
    text = re.sub(r"\s+", " ", text)
    if platform == "windows":
        text = text.casefold()
    return text


def extract_host(event: Event) -> str:
    """
    Extract host identity from event raw_data.

    Precedence: hostname, host, computer_name, Computer.
    Returns empty string if unavailable.
    """
    raw = event.raw_data or {}
    for key in ("hostname", "host", "computer_name", "Computer"):
        if key in raw and raw[key]:
            host = normalize_text(raw[key])
            return host.rstrip(".").casefold()
    return ""


def compute_fingerprint(alert: Alert) -> Dict[str, str]:
    """
    Compute fingerprints for an alert.

    Returns a dict with:
      - fingerprint: full fingerprint including host (for grouping + host suppression)
      - activity_fingerprint: fingerprint excluding host (for global suppression)
      - host: normalized host string

    Args:
        alert: The Alert object to fingerprint

    Returns:
        Dict with fingerprint, activity_fingerprint, and host
    """
    event = alert.event
    platform = normalize_platform(event.platform)

    host = extract_host(event)
    process = normalize_process_name(event.process_name, event.platform)
    parent = normalize_process_name(
        event.parent_process_name or "", event.platform
    )
    command = normalize_command_line(event.command_line, event.platform)
    user = normalize_user(event.user, event.platform)

    # Full fingerprint (includes host)
    full_payload = {
        "v": FINGERPRINT_VERSION,
        "rule_id": alert.rule_id,
        "platform": platform,
        "host": host,
        "process_name": process,
        "command_line": command,
        "user": user,
        "parent_process_name": parent,
    }

    full_json = json.dumps(
        full_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    full_hash = hashlib.sha256(full_json.encode("utf-8")).hexdigest()

    # Activity fingerprint (excludes host, for global suppression)
    activity_payload = {
        "v": FINGERPRINT_VERSION,
        "rule_id": alert.rule_id,
        "platform": platform,
        "process_name": process,
        "command_line": command,
        "user": user,
        "parent_process_name": parent,
    }

    activity_json = json.dumps(
        activity_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    activity_hash = hashlib.sha256(activity_json.encode("utf-8")).hexdigest()

    return {
        "fingerprint": full_hash,
        "activity_fingerprint": activity_hash,
        "host": host,
    }


def compute_incident_fingerprint(incident: Any) -> str:
    """
    Compute a stable SHA-256 fingerprint for a correlated incident.

    Built from the chain ID, platform, host, and each matched stage's
    normalized process name, pid, and timestamp. Rescanning the same log
    yields the same fingerprint, so incidents deduplicate on rescan.

    Args:
        incident: An Incident object from core.correlator

    Returns:
        Hex-encoded SHA-256 fingerprint
    """
    stage_payload = []
    for stage in incident.stages:
        stage_payload.append({
            "stage": stage.get("stage", ""),
            "process_name": normalize_process_name(
                stage.get("process_name", ""), incident.platform
            ),
            "pid": stage.get("pid"),
            "timestamp": stage.get("timestamp"),
        })

    payload = {
        "v": FINGERPRINT_VERSION,
        "chain_id": incident.chain_id,
        "platform": normalize_platform(incident.platform),
        "host": normalize_text(incident.host).casefold(),
        "stages": stage_payload,
    }
    payload_json = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
