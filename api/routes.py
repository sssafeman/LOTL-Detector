"""HTTP route registration and response handling for the REST API."""

import logging
from dataclasses import dataclass
from typing import Callable, Optional

from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue

from api.auth import KeyStore, require_scope
from api.workflows import ApiWorkflows, RequestValidationError
from core.export import format_records

ViewFunction = Callable[..., ResponseReturnValue]


def _passthrough(view: ViewFunction) -> ViewFunction:
    """Return an unprotected view when authentication is disabled."""
    return view


@dataclass
class ApiRoutes:
    """Register and serve the API's HTTP endpoints."""

    app: Flask
    workflows: ApiWorkflows
    logger: logging.Logger
    key_store: Optional[KeyStore] = None

    def register(self) -> Flask:
        """Register all public and scope-protected routes."""
        self.app.add_url_rule(
            '/api/health',
            endpoint='health_check',
            view_func=self.health_check,
            methods=['GET'],
        )
        routes = (
            ('/api/alerts', 'get_alerts', self.get_alerts, ['GET'], 'read'),
            (
                '/api/alerts/<int:alert_id>',
                'get_alert',
                self.get_alert,
                ['GET'],
                'read',
            ),
            ('/api/export', 'export_records', self.export_records, ['GET'], 'read'),
            ('/api/stats', 'get_stats', self.get_stats, ['GET'], 'read'),
            ('/api/rules', 'get_rules', self.get_rules, ['GET'], 'read'),
            ('/api/scan', 'scan_logs', self.scan_logs, ['POST'], 'scan'),
            (
                '/api/incidents',
                'get_incidents',
                self.get_incidents,
                ['GET'],
                'read',
            ),
            ('/api/ingest', 'ingest_source', self.ingest_source, ['POST'], 'scan'),
            (
                '/api/alerts/<int:alert_id>/state',
                'update_alert_state',
                self.update_alert_state,
                ['POST'],
                'admin',
            ),
            (
                '/api/suppressions',
                'create_suppression',
                self.create_suppression,
                ['POST'],
                'admin',
            ),
        )
        for rule, endpoint, view, methods, scope in routes:
            self.app.add_url_rule(
                rule,
                endpoint=endpoint,
                view_func=self._scope_decorator(scope)(view),
                methods=methods,
            )
        return self.app

    def health_check(self) -> ResponseReturnValue:
        """Return the minimal public health response."""
        return jsonify({'status': 'ok'})

    def get_alerts(self) -> ResponseReturnValue:
        """Return alerts with optional filtering."""
        try:
            alerts = self.workflows.query_alerts(request.args)
            return jsonify({
                'count': len(alerts),
                'alerts': alerts,
            })
        except ValueError as error:
            return jsonify({
                'error': 'Invalid parameter',
                'message': str(error),
            }), 400
        except Exception as error:
            self.logger.error(f"Error fetching alerts: {error}")
            return jsonify({
                'error': 'Failed to fetch alerts',
                'message': str(error),
            }), 500

    def get_alert(self, alert_id: int) -> ResponseReturnValue:
        """Return one alert by identifier."""
        try:
            alert = self.workflows.find_alert(alert_id)
            if alert:
                return jsonify(alert)
            return jsonify({'error': 'Alert not found'}), 404
        except Exception as error:
            self.logger.error(f"Error fetching alert {alert_id}: {error}")
            return jsonify({
                'error': 'Failed to fetch alert',
                'message': str(error),
            }), 500

    def export_records(self) -> ResponseReturnValue:
        """Export alert or incident records as newline-delimited text."""
        try:
            records, output_format = self.workflows.query_export_records(
                request.args
            )
            lines = format_records(records, output_format)
            body = "\n".join(lines) + ("\n" if lines else "")
            return self.app.response_class(body, mimetype='text/plain')
        except RequestValidationError as error:
            return jsonify({'error': str(error)}), 400
        except ValueError as error:
            return jsonify({
                'error': 'Invalid parameter',
                'message': str(error),
            }), 400
        except Exception as error:
            self.logger.error(f"Error exporting records: {error}")
            return jsonify({
                'error': 'Export failed',
                'message': str(error),
            }), 500

    def get_stats(self) -> ResponseReturnValue:
        """Return database and detection rule statistics."""
        try:
            return jsonify(self.workflows.stats_payload())
        except Exception as error:
            self.logger.error(f"Error fetching stats: {error}")
            return jsonify({
                'error': 'Failed to fetch statistics',
                'message': str(error),
            }), 500

    def get_rules(self) -> ResponseReturnValue:
        """Return all loaded detection rules and summary counts."""
        try:
            return jsonify(self.workflows.rules_payload())
        except Exception as error:
            self.logger.error(f"Error fetching rules: {error}")
            return jsonify({
                'error': 'Failed to fetch rules',
                'message': str(error),
            }), 500

    def scan_logs(self) -> ResponseReturnValue:
        """Scan a log source for threats."""
        try:
            return jsonify(
                self.workflows.scan_source(request.get_json())
            )
        except RequestValidationError as error:
            return jsonify({'error': str(error)}), 400
        except ValueError as error:
            return jsonify({
                'error': 'Invalid request',
                'message': str(error),
            }), 400
        except Exception as error:
            self.logger.error(f"Error during scan: {error}")
            return jsonify({
                'error': 'Scan failed',
                'message': str(error),
            }), 500

    def get_incidents(self) -> ResponseReturnValue:
        """Return correlated incidents with optional filtering."""
        try:
            incidents = self.workflows.query_incidents(request.args)
            return jsonify({
                'count': len(incidents),
                'incidents': incidents,
            })
        except Exception as error:
            self.logger.error(f"Error fetching incidents: {error}")
            return jsonify({
                'error': 'Failed to fetch incidents',
                'message': str(error),
            }), 500

    def ingest_source(self) -> ResponseReturnValue:
        """Incrementally ingest a line-oriented log source."""
        try:
            return jsonify(
                self.workflows.ingest_source(request.get_json())
            )
        except RequestValidationError as error:
            return jsonify({'error': str(error)}), 400
        except ValueError as error:
            return jsonify({
                'error': 'Invalid request',
                'message': str(error),
            }), 400
        except Exception as error:
            self.logger.error(f"Error during ingest: {error}")
            return jsonify({
                'error': 'Ingest failed',
                'message': str(error),
            }), 500

    def update_alert_state(self, alert_id: int) -> ResponseReturnValue:
        """Update an alert's lifecycle state."""
        try:
            payload = self.workflows.update_alert_state(
                alert_id,
                request.get_json(),
            )
            if payload:
                return jsonify(payload)
            return jsonify({'error': 'Alert not found'}), 404
        except ValueError as error:
            return jsonify({'error': str(error)}), 400
        except Exception as error:
            self.logger.error(f"Error updating alert state: {error}")
            return jsonify({
                'error': 'Failed to update state',
                'message': str(error),
            }), 500

    def create_suppression(self) -> ResponseReturnValue:
        """Create a new alert suppression."""
        try:
            return jsonify(
                self.workflows.create_suppression(request.get_json())
            )
        except RequestValidationError as error:
            return jsonify({'error': str(error)}), 400
        except Exception as error:
            self.logger.error(f"Error creating suppression: {error}")
            return jsonify({
                'error': 'Failed to create suppression',
                'message': str(error),
            }), 500

    def _scope_decorator(
        self, scope: str
    ) -> Callable[[ViewFunction], ViewFunction]:
        """Return the configured scope check or an identity decorator."""
        if self.key_store is None:
            return _passthrough
        return require_scope(self.key_store, scope)


def register_routes(
    app: Flask,
    workflows: ApiWorkflows,
    logger: logging.Logger,
    key_store: Optional[KeyStore] = None,
) -> Flask:
    """Register all API routes against an initialized workflow service."""
    return ApiRoutes(app, workflows, logger, key_store).register()
