"""
Startup safety for every LOTL-Detector server entry point.

All entry points must enforce the same binding rules:
- Remote debug sessions are refused on non-loopback hosts.
- The unauthenticated demo bypass is refused on non-loopback hosts.

validate_startup_binding() is the single implementation; run.py and
api/server.py call it before binding a socket.
"""
import ipaddress


class StartupError(RuntimeError):
    """Raised when the server refuses to start because its configuration
    would expose an unauthenticated or debug service."""


def is_loopback_host(host: str) -> bool:
    """Return True when the host string denotes a loopback interface.

    Accepts 'localhost', bracketed or bare IPv6 loopback, and any address
    in the IPv4 loopback range (127.0.0.0/8).
    """
    if host is None:
        return False
    candidate = str(host).strip()
    if not candidate:
        return False
    if candidate.lower() == "localhost":
        return True
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def validate_startup_binding(
    host: str,
    *,
    debug: bool = False,
    allow_unauthenticated: bool = False,
) -> None:
    """Refuse unsafe bindings before any socket is opened.

    Args:
        host: The address the server would bind.
        debug: True when debug mode is requested.
        allow_unauthenticated: True when the app resolved to the explicit
            unauthenticated demo bypass.

    Raises:
        StartupError: When debug mode or the unauthenticated demo bypass
            would be exposed on a non-loopback host.
    """
    if is_loopback_host(host):
        return
    if debug:
        raise StartupError(
            f"Refusing to start: debug mode is only allowed on loopback "
            f"hosts, got {host!r}. Use 127.0.0.1 for debug mode, or disable "
            f"debug for remote access."
        )
    if allow_unauthenticated:
        raise StartupError(
            f"Refusing to start unauthenticated on non-loopback host "
            f"{host!r}. The demo bypass requires a loopback binding "
            f"(127.0.0.1, ::1, or localhost). Configure credentials or bind "
            f"to loopback."
        )
