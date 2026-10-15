"""Startup binding validation tests (S2).

Shared entry-point validation: loopback-only enforcement of the demo
bypass, no 0.0.0.0 fallback on config errors, and remote-debug refusal in
every entry point.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from api.startup import StartupError, is_loopback_host, validate_startup_binding

REPO_ROOT = Path(__file__).resolve().parents[1]

VALID_KEY = "unit-test-key-0123456789abcdefghij"  # >= MIN_KEY_LENGTH


class TestStartupBindingValidation:
    """Shared binding validation used by every entry point."""

    @pytest.mark.parametrize(
        "host",
        ["127.0.0.1", "127.0.0.5", "::1", "localhost"],
    )
    def test_loopback_hosts_recognized(self, host):
        assert is_loopback_host(host) is True

    @pytest.mark.parametrize(
        "host",
        ["0.0.0.0", "::", "192.168.50.10", "example.com", ""],
    )
    def test_non_loopback_hosts_rejected(self, host):
        assert is_loopback_host(host) is False

    def test_debug_on_public_host_refused(self):
        with pytest.raises(StartupError):
            validate_startup_binding("0.0.0.0", debug=True)

    def test_debug_on_loopback_allowed(self):
        validate_startup_binding("127.0.0.1", debug=True)

    def test_unauthenticated_on_public_host_refused(self):
        with pytest.raises(StartupError):
            validate_startup_binding("0.0.0.0", allow_unauthenticated=True)

    def test_unauthenticated_on_loopback_allowed(self):
        validate_startup_binding("::1", allow_unauthenticated=True)

    def test_authenticated_public_binding_allowed(self):
        validate_startup_binding("0.0.0.0")


def _subprocess_env(tmp_path, **overrides):
    """Base environment for entry-point subprocess tests: no ambient keys."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("LOTL_")}
    env["HOME"] = str(tmp_path)  # hide any real default key file
    env.update(overrides)
    return env


class TestEntryPointRefusals:
    """Both entry points refuse unsafe startup before binding."""

    def test_run_py_refuses_without_credentials(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "run.py"),
                "--db",
                str(tmp_path / "t.db"),
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env=_subprocess_env(tmp_path),
            timeout=60,
        )
        assert result.returncode != 0
        assert "LOTL_API_KEY" in result.stderr

    def test_run_py_refuses_remote_debug(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "run.py"),
                "--db",
                str(tmp_path / "t.db"),
                "--host",
                "0.0.0.0",
                "--debug",
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env=_subprocess_env(tmp_path, LOTL_API_KEY=VALID_KEY),
            timeout=60,
        )
        assert result.returncode != 0
        assert "debug" in result.stderr.lower()

    def test_run_py_refuses_unauthenticated_non_loopback(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "run.py"),
                "--db",
                str(tmp_path / "t.db"),
                "--host",
                "0.0.0.0",
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env=_subprocess_env(tmp_path, LOTL_ALLOW_UNAUTHENTICATED="1"),
            timeout=60,
        )
        assert result.returncode != 0
        assert "loopback" in result.stderr.lower()

    def test_run_py_fails_on_config_error_without_0_0_0_0_fallback(self, tmp_path):
        (tmp_path / "config.yml").write_text("api: [unclosed")
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "run.py"),
                "--db",
                str(tmp_path / "t.db"),
            ],
            capture_output=True,
            text=True,
            cwd=tmp_path,
            env=_subprocess_env(tmp_path),
            timeout=60,
        )
        assert result.returncode != 0
        assert "0.0.0.0" not in result.stdout
        assert "configuration" in result.stderr.lower()

    def test_server_module_refuses_remote_debug(self, tmp_path):
        # RuleLoader resolves rules/schema.json relative to the working
        # directory (E17 keeps that dependency for Sprint 2), so expose the
        # repository rules through a symlink in the temporary directory.
        (tmp_path / "rules").symlink_to(REPO_ROOT / "rules")
        (tmp_path / "config.yml").write_text(
            "api:\n"
            "  host: 0.0.0.0\n"
            "  port: 5099\n"
            "  debug: true\n"
            "database:\n"
            f"  path: {tmp_path / 't.db'}\n"
        )
        env = _subprocess_env(
            tmp_path, PYTHONPATH=str(REPO_ROOT), LOTL_API_KEY=VALID_KEY
        )
        result = subprocess.run(
            [sys.executable, "-m", "api.server"],
            capture_output=True,
            text=True,
            cwd=tmp_path,
            env=env,
            timeout=60,
        )
        assert result.returncode != 0
        assert "debug" in result.stderr.lower()
