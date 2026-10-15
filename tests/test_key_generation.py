"""Tests for exclusive, symlink-safe API key generation (S10).

Key files are created with O_EXCL, never follow or replace symlinks, and
only an explicit replace/--force call overwrites an existing file.
"""
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from api.auth import generate_api_key

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestExclusiveCreation:
    def test_creates_file_with_0600_and_newline(self, tmp_path):
        target = tmp_path / "api.key"
        key = generate_api_key(target)
        assert target.read_text() == key + "\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_existing_file_is_not_overwritten(self, tmp_path):
        target = tmp_path / "api.key"
        target.write_text("existing-content")
        with pytest.raises(FileExistsError):
            generate_api_key(target)
        assert target.read_text() == "existing-content"

    def test_replace_is_an_explicit_operation(self, tmp_path):
        target = tmp_path / "api.key"
        target.write_text("old-content")
        key = generate_api_key(target, replace=True)
        assert target.read_text() == key + "\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_missing_parent_created_with_0700(self, tmp_path):
        target = tmp_path / "nested" / "dir" / "api.key"
        generate_api_key(target)
        mode = stat.S_IMODE((tmp_path / "nested" / "dir").stat().st_mode)
        assert mode == 0o700

    def test_existing_parent_permissions_unchanged(self, tmp_path):
        parent = tmp_path / "shared"
        parent.mkdir()
        os.chmod(parent, 0o755)
        generate_api_key(parent / "api.key")
        assert stat.S_IMODE(parent.stat().st_mode) == 0o755

    def test_directory_target_is_rejected(self, tmp_path):
        target = tmp_path / "api.key"
        target.mkdir()
        with pytest.raises(OSError):
            generate_api_key(target, replace=True)


class TestSymlinkSafety:
    def test_symlink_target_not_written(self, tmp_path):
        secret = tmp_path / "victim.txt"
        secret.write_text("important")
        link = tmp_path / "api.key"
        link.symlink_to(secret)
        with pytest.raises(FileExistsError):
            generate_api_key(link)
        assert secret.read_text() == "important"
        assert link.is_symlink()

    def test_symlink_not_replaced_even_with_replace(self, tmp_path):
        secret = tmp_path / "victim.txt"
        secret.write_text("important")
        link = tmp_path / "api.key"
        link.symlink_to(secret)
        with pytest.raises(FileExistsError):
            generate_api_key(link, replace=True)
        assert secret.read_text() == "important"
        assert link.is_symlink()

    def test_dangling_symlink_is_not_followed(self, tmp_path):
        link = tmp_path / "api.key"
        link.symlink_to(tmp_path / "does-not-exist")
        with pytest.raises(FileExistsError):
            generate_api_key(link)
        # Nothing may be created at the symlink target.
        assert not (tmp_path / "does-not-exist").exists()


def _run_cli(home, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("LOTL_")}
    env["HOME"] = str(home)
    return subprocess.run(
        [sys.executable, "-m", "api.auth", *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=60,
    )


class TestGenerateCli:
    def test_generate_with_output_and_force(self, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        target = tmp_path / "cli.key"

        first = _run_cli(home, "generate", "--output", str(target))
        assert first.returncode == 0
        assert target.exists()
        original = target.read_text()

        second = _run_cli(home, "generate", "--output", str(target))
        assert second.returncode == 1
        assert "already exists" in second.stderr
        assert target.read_text() == original

        third = _run_cli(
            home, "generate", "--output", str(target), "--force"
        )
        assert third.returncode == 0
        assert target.read_text() != original

    def test_generate_default_location(self, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        result = _run_cli(home, "generate")
        assert result.returncode == 0
        expected = home / ".config" / "lotl-detector" / "api.key"
        assert expected.exists()
        assert stat.S_IMODE(expected.stat().st_mode) == 0o600

        # A second run must not silently clobber the key.
        result = _run_cli(home, "generate")
        assert result.returncode == 1
        assert "already exists" in result.stderr
