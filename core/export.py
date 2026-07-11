"""
SIEM export: structured formatters and output sinks for alerts and incidents.

Formatters produce two wire formats:
  - CEF (ArcSight Common Event Format), the classic syslog-friendly line.
  - ECS-aligned JSON (Elastic Common Schema field names), for JSON pipelines.

Sinks deliver formatted records: file, stdout, UDP syslog, and HTTP webhook
with a bounded retry queue. Network sinks accept an injectable transport so
they can be exercised without real sockets.

This implements the export half of MoA finding 18. Rule pack signing and
distribution remain future work.
"""
import json
import logging
import socket
import time
from typing import Any, Callable, Dict, List, Optional
from urllib import request as urllib_request
from urllib.error import URLError

logger = logging.getLogger(__name__)

EXPORT_VERSION = 1
VENDOR = "LOTL Detector"
PRODUCT = "lotl-detector"

# CEF severity is 0 to 10. Map our risk bands onto it.
_CEF_SEVERITY = {"low": 3, "medium": 5, "high": 8, "critical": 10}

# Characters that must be escaped in CEF extension values and the header.
_CEF_HEADER_ESCAPE = str.maketrans({"\\": "\\\\", "|": "\\|", "\n": " "})


def _cef_escape_header(value: str) -> str:
    """Escape a CEF header field (pipe, backslash, newline)."""
    return str(value).translate(_CEF_HEADER_ESCAPE)


def _cef_escape_extension(value: str) -> str:
    """Escape a CEF extension value (backslash, equals, newline)."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def _alert_fields(alert: Any) -> Dict[str, Any]:
    """
    Normalize an alert into a flat field dict.

    Accepts either a database row dict (from get_alerts) or the output of
    Alert.to_dict (which nests event fields under 'event'). Missing fields
    default to empty rather than raising, so partial records still export.
    """
    if hasattr(alert, "to_dict"):
        alert = alert.to_dict()

    event = alert.get("event") or alert.get("event_data") or {}
    return {
        "kind": "alert",
        "signature_id": alert.get("rule_id", ""),
        "name": alert.get("rule_name", ""),
        "severity": alert.get("severity", ""),
        "score": alert.get("score", 0),
        "risk_band": alert.get("risk_band", "low"),
        "platform": alert.get("platform") or event.get("platform", ""),
        "timestamp": alert.get("timestamp", ""),
        "process_name": alert.get("process_name") or event.get("process_name", ""),
        "command_line": alert.get("command_line") or event.get("command_line", ""),
        "user": alert.get("user") or event.get("user", ""),
        "parent_process_name": (
            alert.get("parent_process_name") or event.get("parent_process_name") or ""
        ),
        "host": event.get("raw_data", {}).get("hostname", "") if event else "",
        "mitre_attack": alert.get("mitre_attack") or [],
        "description": alert.get("description", ""),
    }


def _incident_fields(incident: Any) -> Dict[str, Any]:
    """Normalize an incident into a flat field dict (dict or Incident)."""
    if hasattr(incident, "to_dict"):
        incident = incident.to_dict()

    stages = incident.get("stages") or []
    chain = " -> ".join(s.get("process_name", "?") for s in stages)
    return {
        "kind": "incident",
        "signature_id": incident.get("chain_id", ""),
        "name": incident.get("chain_name", ""),
        "severity": incident.get("severity", ""),
        "score": incident.get("score", 0),
        "risk_band": incident.get("risk_band", "low"),
        "confidence": incident.get("confidence", 0),
        "platform": incident.get("platform", ""),
        "host": incident.get("host", ""),
        "timestamp": incident.get("first_timestamp") or "",
        "last_timestamp": incident.get("last_timestamp") or "",
        "chain": chain,
        "stage_count": len(stages),
        "mitre_attack": incident.get("mitre_attack") or [],
        "description": incident.get("description", ""),
    }


def to_cef(record: Any) -> str:
    """
    Format an alert or incident as a CEF line.

    Detects incidents by the presence of a chain_id / chain_name; everything
    else is treated as an alert.
    """
    if _is_incident(record):
        fields = _incident_fields(record)
        extra = {
            "cs2": fields["chain"],
            "cs2Label": "processChain",
            "cn1": fields["confidence"],
            "cn1Label": "confidence",
        }
    else:
        fields = _alert_fields(record)
        extra = {
            "sproc": fields["process_name"],
            "sourceProcessName": fields["parent_process_name"],
        }

    severity = _CEF_SEVERITY.get(fields["risk_band"], 5)
    header = "CEF:0|{vendor}|{product}|{version}|{sig}|{name}|{sev}|".format(
        vendor=_cef_escape_header(VENDOR),
        product=_cef_escape_header(PRODUCT),
        version=EXPORT_VERSION,
        sig=_cef_escape_header(fields["signature_id"]),
        name=_cef_escape_header(fields["name"]),
        sev=severity,
    )

    extensions = {
        "rt": fields.get("timestamp", ""),
        "dvchost": fields.get("host", ""),
        "suser": fields.get("user", ""),
        "cs1": fields.get("command_line", ""),
        "cs1Label": "commandLine" if fields.get("command_line") else "",
        "cat": fields["kind"],
        "externalId": fields["signature_id"],
        "cn2": fields["score"],
        "cn2Label": "riskScore",
        "reason": ",".join(fields.get("mitre_attack", [])),
    }
    extensions.update(extra)

    parts = [
        "{}={}".format(key, _cef_escape_extension(value))
        for key, value in extensions.items()
        if value not in ("", None, [])
    ]
    return header + " ".join(parts)


def to_ecs(record: Any) -> Dict[str, Any]:
    """
    Format an alert or incident as an ECS-aligned JSON dictionary.
    """
    if _is_incident(record):
        fields = _incident_fields(record)
        doc: Dict[str, Any] = {
            "@timestamp": fields["timestamp"],
            "event": {
                "kind": "alert",
                "category": ["process"],
                "type": ["info"],
                "risk_score": fields["score"],
                "severity": fields["score"],
                "dataset": "lotl.incident",
                "end": fields["last_timestamp"],
            },
            "rule": {
                "id": fields["signature_id"],
                "name": fields["name"],
                "description": fields["description"],
            },
            "host": {"name": fields["host"]},
            "lotl": {
                "kind": "incident",
                "confidence": fields["confidence"],
                "risk_band": fields["risk_band"],
                "process_chain": fields["chain"],
                "stage_count": fields["stage_count"],
            },
        }
    else:
        fields = _alert_fields(record)
        doc = {
            "@timestamp": fields["timestamp"],
            "event": {
                "kind": "alert",
                "category": ["process"],
                "type": ["info"],
                "risk_score": fields["score"],
                "severity": fields["score"],
                "dataset": "lotl.alert",
            },
            "rule": {
                "id": fields["signature_id"],
                "name": fields["name"],
                "description": fields["description"],
            },
            "process": {
                "name": fields["process_name"],
                "command_line": fields["command_line"],
                "parent": {"name": fields["parent_process_name"]},
            },
            "user": {"name": fields["user"]},
            "host": {"name": fields["host"]},
            "lotl": {
                "kind": "alert",
                "severity": fields["severity"],
                "risk_band": fields["risk_band"],
            },
        }

    if fields["mitre_attack"]:
        doc["threat"] = {"technique": {"id": fields["mitre_attack"]}}
    doc["observer"] = {"vendor": VENDOR, "product": PRODUCT}
    return doc


def _is_incident(record: Any) -> bool:
    """True when the record is an incident (has a chain identity)."""
    if hasattr(record, "chain_id"):
        return True
    if isinstance(record, dict):
        return "chain_id" in record or "chain_name" in record
    return False


def format_record(record: Any, fmt: str) -> str:
    """
    Format one record as a single line in the requested format.

    Args:
        record: Alert or incident (object or dict)
        fmt: 'cef' or 'json'

    Returns:
        A single-line string (JSON is compact, no embedded newlines)
    """
    fmt = fmt.lower()
    if fmt == "cef":
        return to_cef(record)
    if fmt == "json":
        return json.dumps(to_ecs(record), separators=(",", ":"), default=str)
    raise ValueError(f"Unknown export format: {fmt} (use 'cef' or 'json')")


def format_records(records: List[Any], fmt: str) -> List[str]:
    """Format a list of records, returning one line per record."""
    return [format_record(r, fmt) for r in records]


class ExportSink:
    """Base sink interface. Subclasses implement emit(line)."""

    def emit(self, line: str) -> bool:
        """Deliver one formatted line. Returns True on success."""
        raise NotImplementedError

    def export(self, records: List[Any], fmt: str) -> int:
        """Format and emit all records. Returns the number delivered."""
        delivered = 0
        for line in format_records(records, fmt):
            if self.emit(line):
                delivered += 1
        return delivered


class FileSink(ExportSink):
    """Append formatted records to a file, one per line."""

    def __init__(self, path: str):
        self.path = path

    def emit(self, line: str) -> bool:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        return True


class StdoutSink(ExportSink):
    """Write formatted records to stdout."""

    def emit(self, line: str) -> bool:
        print(line)
        return True


class SyslogSink(ExportSink):
    """
    Send formatted records over UDP syslog with an RFC 3164 style priority.

    A transport callable (bytes, address) can be injected for testing;
    otherwise a UDP socket is used.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 514,
        facility: int = 13,
        severity: int = 5,
        transport: Optional[Callable[[bytes, tuple], None]] = None,
    ):
        self.host = host
        self.port = port
        self.priority = facility * 8 + severity
        self._transport = transport
        self._socket = None

    def _send(self, payload: bytes) -> None:
        if self._transport is not None:
            self._transport(payload, (self.host, self.port))
            return
        if self._socket is None:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.sendto(payload, (self.host, self.port))

    def emit(self, line: str) -> bool:
        message = f"<{self.priority}>{line}"
        try:
            self._send(message.encode("utf-8"))
            return True
        except OSError as e:
            logger.error(f"Syslog send failed: {e}")
            return False

    def close(self) -> None:
        """Close the underlying socket if one was opened."""
        if self._socket is not None:
            self._socket.close()
            self._socket = None


class WebhookSink(ExportSink):
    """
    POST formatted records to an HTTP webhook with bounded retries.

    A transport callable (url, data_bytes, headers) can be injected for
    testing; otherwise urllib performs the POST. Failed sends are retried
    up to max_retries with a fixed backoff, then dropped and logged.
    """

    def __init__(
        self,
        url: str,
        max_retries: int = 3,
        backoff_seconds: float = 0.5,
        timeout: float = 5.0,
        transport: Optional[Callable[[str, bytes, Dict[str, str]], int]] = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.url = url
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.timeout = timeout
        self._transport = transport
        self._sleep = sleep

    def _post(self, data: bytes, headers: Dict[str, str]) -> int:
        if self._transport is not None:
            return self._transport(self.url, data, headers)
        req = urllib_request.Request(
            self.url, data=data, headers=headers, method="POST"
        )
        with urllib_request.urlopen(req, timeout=self.timeout) as resp:
            return resp.getcode()

    def emit(self, line: str) -> bool:
        data = line.encode("utf-8")
        headers = {"Content-Type": "application/json"}
        attempt = 0
        while attempt <= self.max_retries:
            try:
                status = self._post(data, headers)
                if 200 <= status < 300:
                    return True
                logger.warning(f"Webhook returned {status}, attempt {attempt + 1}")
            except (URLError, OSError) as e:
                logger.warning(f"Webhook send error: {e}, attempt {attempt + 1}")
            attempt += 1
            if attempt <= self.max_retries:
                self._sleep(self.backoff_seconds)
        logger.error(f"Webhook delivery failed after {self.max_retries} retries")
        return False


def build_sink(spec: Dict[str, Any]) -> ExportSink:
    """
    Build a sink from a config dict.

    Args:
        spec: {"type": "file"|"stdout"|"syslog"|"webhook", ...type-specific}

    Returns:
        An ExportSink instance
    """
    sink_type = spec.get("type", "stdout").lower()
    if sink_type == "file":
        return FileSink(spec["path"])
    if sink_type == "stdout":
        return StdoutSink()
    if sink_type == "syslog":
        return SyslogSink(
            host=spec.get("host", "127.0.0.1"),
            port=spec.get("port", 514),
            facility=spec.get("facility", 13),
            severity=spec.get("severity", 5),
        )
    if sink_type == "webhook":
        return WebhookSink(
            url=spec["url"],
            max_retries=spec.get("max_retries", 3),
            backoff_seconds=spec.get("backoff_seconds", 0.5),
        )
    raise ValueError(f"Unknown sink type: {sink_type}")
