"""
Startup safety for every LOTL-Detector server entry point.

This module hosts the shared startup error type and, from Sprint 1 item S2
onward, the binding validation used by run.py and api/server.py so all
entry points enforce the same rules.
"""


class StartupError(RuntimeError):
    """Raised when the server refuses to start because its configuration
    would expose an unauthenticated or debug service."""
