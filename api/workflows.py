"""Application workflows used by the REST API routes."""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from flask import Flask

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


class RequestValidationError(ValueError):
    """Represent a client input error with an API-safe message."""


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
        """Apply alert query parameters using the API's filter precedence."""
        database = self.components_provider().database
        start_time = args.get('start_time')
        end_time = args.get('end_time')
        if start_time:
            start_time = datetime.fromisoformat(start_time)
        if end_time:
            end_time = datetime.fromisoformat(end_time)

        severity = args.get('severity')
        platform = args.get('platform')
        min_score = args.get('min_score', type=int)
        limit = args.get('limit', type=int, default=100)
        if severity:
            return database.get_alerts_by_severity(severity)
        if platform:
            return database.get_alerts_by_platform(platform)
        if min_score is not None:
            return database.get_high_score_alerts(min_score)
        return database.get_alerts(
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )

    def query_export_records(
        self, args: Any
    ) -> Tuple[list[Dict[str, Any]], str]:
        """Load and filter records for the export endpoint."""
        database = self.components_provider().database
        kind = args.get('kind', 'alerts')
        output_format = args.get('format', 'json')
        if output_format.lower() not in ('cef', 'json'):
            raise RequestValidationError("format must be 'cef' or 'json'")

        severity = args.get('severity')
        platform = args.get('platform')
        min_score = args.get('min_score', type=int)
        limit = args.get('limit', type=int, default=1000)
        if kind == 'incidents':
            records = database.get_incidents(
                severity=severity,
                platform=platform,
                min_score=min_score,
                limit=limit,
            )
            return records, output_format

        records = database.get_alerts(limit=limit)
        if severity:
            records = [
                record for record in records
                if record.get('severity') == severity
            ]
        if platform:
            records = [
                record for record in records
                if record.get('platform') == platform
            ]
        if min_score is not None:
            records = [
                record for record in records
                if record.get('score', 0) >= min_score
            ]
        return records, output_format

    def find_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Find one alert using the existing bounded database query."""
        database = self.components_provider().database
        alerts = database.get_alerts(limit=10000)
        return next(
            (alert for alert in alerts if alert['id'] == alert_id),
            None,
        )

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
        """Apply incident query parameters to the database query."""
        database = self.components_provider().database
        return database.get_incidents(
            chain_id=args.get('chain_id'),
            severity=args.get('severity'),
            platform=args.get('platform'),
            min_score=args.get('min_score', type=int),
            limit=args.get('limit', type=int, default=100),
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

    def update_alert_state(
        self, alert_id: int, data: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Validate and apply an alert lifecycle state change."""
        if not data:
            raise RequestValidationError('Request body is required')

        new_state = data.get('state')
        author = data.get('author', 'api')
        reason = data.get('reason', '')
        if not new_state:
            raise RequestValidationError('state is required')

        database = self.components_provider().database
        updated = database.update_alert_state(
            alert_id,
            new_state,
            author,
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
        author = data.get('author', 'api')
        reason = data.get('reason', '')
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
            author,
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
