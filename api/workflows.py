"""Application workflows used by the REST API routes."""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from flask import Flask, g, has_request_context

from collectors.base import BaseCollector, Event
from core.correlator import Correlator
from core.database import AlertDatabase
from core.engine import Alert, DetectionEngine
from core.ingest import (
    EventParser,
    IngestionService,
    linux_auditd_parser,
    macos_eslogger_parser,
    windows_sysmon_parser,
)
from core.source_validator import SourceValidationError, validate_log_source

SUPPORTED_PLATFORMS = ('windows', 'linux', 'macos')
VALID_SEVERITIES = ('critical', 'high', 'medium', 'low')
MAX_QUERY_LIMIT = 10000
DEFAULT_ALERT_LIMIT = 100
DEFAULT_EXPORT_LIMIT = 1000
DEFAULT_INCIDENT_LIMIT = 100


class RequestValidationError(ValueError):
    """Represent a client input error with an API-safe message."""


def _parse_int_parameter(
    args: Any,
    name: str,
    *,
    default: Optional[int] = None,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> Optional[int]:
    """Parse an integer query parameter, rejecting unusable values.

    Werkzeug's args.get(type=int) silently returns None on bad input,
    which dropped the filter instead of telling the client (E13).
    """
    raw = args.get(name)
    if raw is None or raw == '':
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise RequestValidationError(f'{name} must be an integer')
    if minimum is not None and value < minimum:
        raise RequestValidationError(f'{name} must be at least {minimum}')
    if maximum is not None and value > maximum:
        raise RequestValidationError(f'{name} must be at most {maximum}')
    return value


def _parse_limit_parameter(args: Any, default: int) -> int:
    """Parse and cap a result-limit parameter."""
    value = _parse_int_parameter(
        args, 'limit', default=default, minimum=1, maximum=MAX_QUERY_LIMIT
    )
    assert value is not None  # a default is always provided
    return value


def _parse_timestamp_parameter(args: Any, name: str) -> Optional[datetime]:
    """Parse an ISO 8601 time bound, rejecting unparseable values."""
    raw = args.get(name)
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        raise RequestValidationError(f'{name} must be an ISO 8601 timestamp')


def _validate_alert_filters(args: Any) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Validate the filters shared by the alerts and export endpoints."""
    severity = args.get('severity')
    platform = args.get('platform')
    if severity and severity not in VALID_SEVERITIES:
        raise RequestValidationError(
            "severity must be one of " + ", ".join(VALID_SEVERITIES)
        )
    if platform and platform not in SUPPORTED_PLATFORMS:
        raise RequestValidationError(
            "platform must be one of " + ", ".join(SUPPORTED_PLATFORMS)
        )
    min_score = _parse_int_parameter(args, 'min_score', minimum=0)
    return severity, platform, min_score


@dataclass(frozen=True)
class ApiComponents:
    """Runtime components resolved for an API workflow invocation."""

    database: AlertDatabase
    engine: DetectionEngine
    correlator: Optional[Correlator]
    collectors: Dict[str, BaseCollector]


@dataclass
class ApiWorkflows:
    """Coordinate API queries, scans, ingestion, and state changes."""

    app: Flask
    components_provider: Callable[[], ApiComponents]
    logger: logging.Logger

    def query_alerts(self, args: Any) -> list[Dict[str, Any]]:
        """Apply every supplied filter as an intersection (finding E13).

        Time bounds, severity, platform, min_score, and limit all apply
        together, with the same semantics as the export endpoint. The
        old code returned early on the first filter it saw and dropped
        the rest.
        """
        database = self.components_provider().database
        severity, platform, min_score = _validate_alert_filters(args)
        return database.get_alerts(
            start_time=_parse_timestamp_parameter(args, 'start_time'),
            end_time=_parse_timestamp_parameter(args, 'end_time'),
            severity=severity,
            platform=platform,
            min_score=min_score,
            limit=_parse_limit_parameter(args, DEFAULT_ALERT_LIMIT),
        )

    def query_export_records(
        self, args: Any
    ) -> Tuple[list[Dict[str, Any]], str]:
        """Load records for the export endpoint with one query semantics.

        Filters run in the database query and the limit applies after
        filtering (E13). The old code loaded the newest N records first
        and filtered them in Python, so matching older records were
        silently dropped from exports.
        """
        database = self.components_provider().database
        kind = args.get('kind', 'alerts')
        output_format = (args.get('format') or 'json').lower()
        if output_format not in ('cef', 'json'):
            raise RequestValidationError("format must be 'cef' or 'json'")
        if kind not in ('alerts', 'incidents'):
            raise RequestValidationError("kind must be 'alerts' or 'incidents'")

        severity, platform, min_score = _validate_alert_filters(args)
        limit = _parse_limit_parameter(args, DEFAULT_EXPORT_LIMIT)

        if kind == 'incidents':
            records = database.get_incidents(
                severity=severity,
                platform=platform,
                min_score=min_score,
                limit=limit,
            )
        else:
            records = database.get_alerts(
                severity=severity,
                platform=platform,
                min_score=min_score,
                limit=limit,
            )
        return records, output_format

    def find_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Fetch one alert directly by primary key (finding E13).

        The old lookup scanned only the latest 10000 alerts, so any
        older ID read as not found.
        """
        database = self.components_provider().database
        return database.get_alert_by_id(alert_id)

    def stats_payload(self) -> Dict[str, Any]:
        """Build the combined database and rule statistics payload."""
        components = self.components_provider()
        return {
            'alerts': components.database.get_stats(),
            'rules': components.engine.get_stats(),
        }

    def rules_payload(self) -> Dict[str, Any]:
        """Serialize loaded rules and calculate their summary counts."""
        engine = self.components_provider().engine
        rules_data = [rule.to_dict() for rule in engine.rules]
        stats = {
            'total': len(rules_data),
            'by_platform': {},
            'by_severity': {},
        }
        for rule in engine.rules:
            platform_counts = stats['by_platform']
            severity_counts = stats['by_severity']
            platform_counts[rule.platform] = (
                platform_counts.get(rule.platform, 0) + 1
            )
            severity_counts[rule.severity] = (
                severity_counts.get(rule.severity, 0) + 1
            )
        return {
            'count': len(rules_data),
            'rules': rules_data,
            'stats': stats,
        }

    def scan_source(
        self, data: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Collect, detect, correlate, and persist one scan request."""
        platform, log_path = self._parse_source_request(
            data,
            'platform must be "windows", "linux", or "macos"',
        )
        validated_path = self._validate_source_path(log_path, platform)
        components = self.components_provider()
        collector = components.collectors.get(platform)
        if not collector:
            raise RequestValidationError(
                f'No collector available for platform: {platform}'
            )

        self.logger.info(f"Scanning {platform} logs at {validated_path}")
        events = collector.collect_events(validated_path)
        self.logger.info(f"Collected {len(events)} events")
        alerts = components.engine.match_events(events)
        self.logger.info(f"Generated {len(alerts)} alerts")

        alert_results, new_alerts, duplicates, suppressed = (
            self._save_alert_results(alerts)
        )
        incident_results, new_incidents = self._save_incident_results(events)
        return {
            'events_processed': len(events),
            'alerts_generated': new_alerts,
            'duplicates_updated': duplicates,
            'suppressed': suppressed,
            'incidents_generated': new_incidents,
            'incident_results': incident_results,
            'results': alert_results,
        }

    def query_incidents(self, args: Any) -> list[Dict[str, Any]]:
        """Apply incident query parameters with validated values."""
        database = self.components_provider().database
        return database.get_incidents(
            chain_id=args.get('chain_id'),
            severity=args.get('severity'),
            platform=args.get('platform'),
            min_score=_parse_int_parameter(args, 'min_score', minimum=0),
            limit=_parse_limit_parameter(args, DEFAULT_INCIDENT_LIMIT),
        )

    def ingest_source(
        self, data: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Validate and execute an incremental ingestion request."""
        platform, log_path = self._parse_source_request(
            data,
            'incremental ingestion supports "linux", "windows", or "macos"',
        )
        validated_path = self._validate_source_path(log_path, platform)
        components = self.components_provider()
        service = IngestionService(
            components.database,
            components.engine,
            self._parser_for_platform(platform),
            correlator=components.correlator,
            batch_size=data.get('batch_size', 500),
        )
        return service.ingest_file(validated_path)

    @staticmethod
    def _audit_actor() -> str:
        """Return the audit actor for state and suppression changes (S9).

        The actor is always the authenticated key's label, never a value
        supplied by the caller. Unauthenticated demo mode records
        'unauthenticated'.
        """
        if has_request_context():
            label = getattr(g, 'auth_label', None)
            if label:
                return str(label)
        return 'unauthenticated'

    @staticmethod
    def _reason_with_reported_by(reason: Any, reported_by: Any) -> str:
        """Fold a caller-supplied analyst name into the reason annotation.

        The supplied name is not trusted as the audit actor (S9); it is
        kept as a clearly marked, separate annotation when present.
        """
        text = str(reason) if reason else ''
        reported = str(reported_by or '').strip()
        if not reported:
            return text
        if text:
            return f"{text}; reported_by={reported}"
        return f"reported_by={reported}"

    def update_alert_state(
        self, alert_id: int, data: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Validate and apply an alert lifecycle state change."""
        if not data:
            raise RequestValidationError('Request body is required')

        new_state = data.get('state')
        actor = self._audit_actor()
        reason = self._reason_with_reported_by(
            data.get('reason'), data.get('author')
        )
        if not new_state:
            raise RequestValidationError('state is required')

        database = self.components_provider().database
        updated = database.update_alert_state(
            alert_id,
            new_state,
            actor,
            reason,
        )
        if not updated:
            return None
        return {
            'status': 'updated',
            'alert_id': alert_id,
            'state': new_state,
        }

    def create_suppression(
        self, data: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Validate and persist an alert suppression request."""
        if not data:
            raise RequestValidationError('Request body is required')

        fingerprint = data.get('fingerprint')
        scope = data.get('scope', 'global')
        scope_value = data.get('scope_value')
        actor = self._audit_actor()
        reason = self._reason_with_reported_by(
            data.get('reason'), data.get('author')
        )
        duration_hours = data.get('duration_hours', 24)

        if not fingerprint:
            raise RequestValidationError('fingerprint is required')
        if scope not in ('global', 'host'):
            raise RequestValidationError('scope must be global or host')
        if scope == 'host' and not scope_value:
            raise RequestValidationError(
                'scope_value is required for host scope'
            )
        if not reason:
            raise RequestValidationError('reason is required')

        database = self.components_provider().database
        suppression_id = database.add_suppression(
            fingerprint,
            scope,
            scope_value,
            actor,
            reason,
            duration_hours,
        )
        return {
            'status': 'created',
            'suppression_id': suppression_id,
        }

    def _parse_source_request(
        self, data: Optional[Dict[str, Any]], platform_error: str
    ) -> Tuple[str, str]:
        """Validate the fields shared by scan and ingestion requests."""
        if not data:
            raise RequestValidationError('Request body is required')

        platform = data.get('platform')
        log_path = data.get('log_path')
        if not platform or not log_path:
            raise RequestValidationError('platform and log_path are required')
        if platform not in SUPPORTED_PLATFORMS:
            raise RequestValidationError(platform_error)
        return platform, log_path

    def _validate_source_path(self, log_path: str, platform: str) -> str:
        """Validate a client supplied source path against configured limits."""
        allowed_roots = self.app.config.get('ALLOWED_LOG_ROOTS', [])
        max_size_mb = self.app.config.get('MAX_FILE_SIZE_MB', 100)
        max_size_bytes = (
            max_size_mb * 1024 * 1024
            if max_size_mb
            else 100 * 1024 * 1024
        )
        try:
            return validate_log_source(
                log_path,
                platform,
                allowed_roots=allowed_roots,
                max_file_size=max_size_bytes,
            )
        except SourceValidationError as error:
            raise RequestValidationError(
                f'Invalid log source: {error}'
            ) from error

    def _save_alert_results(
        self, alerts: Iterable[Alert]
    ) -> Tuple[list[Dict[str, Any]], int, int, int]:
        """Persist alerts and summarize deduplication outcomes."""
        database = self.components_provider().database
        results = [
            database.save_alert_dedup(alert) for alert in alerts
        ]
        new_count = sum(
            1 for result in results
            if not result['is_duplicate'] and not result.get('is_suppressed')
        )
        duplicate_count = sum(
            1 for result in results if result['is_duplicate']
        )
        suppressed_count = sum(
            1 for result in results if result.get('is_suppressed')
        )
        return results, new_count, duplicate_count, suppressed_count

    def _save_incident_results(
        self, events: List[Event]
    ) -> Tuple[list[Dict[str, Any]], int]:
        """Correlate a batch, persist incidents, and count new records."""
        components = self.components_provider()
        correlator = components.correlator
        database = components.database
        incidents = correlator.correlate(events) if correlator else []
        results = []
        for incident in incidents:
            results.append({
                **database.save_incident(incident),
                'chain_id': incident.chain_id,
                'score': incident.score,
                'risk_band': incident.risk_band,
            })
        new_count = sum(
            1 for result in results if not result['is_duplicate']
        )
        self.logger.info(f"Correlated {new_count} new incidents")
        return results, new_count

    def _parser_for_platform(self, platform: str) -> EventParser:
        """Build the incremental parser for a supported platform."""
        parser_factories = {
            'linux': linux_auditd_parser,
            'windows': windows_sysmon_parser,
            'macos': macos_eslogger_parser,
        }
        return parser_factories[platform](
            self.components_provider().collectors[platform]
        )
