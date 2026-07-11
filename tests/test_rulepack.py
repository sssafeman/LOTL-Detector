"""
Tests for rule pack signing, verification, and staged distribution.
"""
from datetime import datetime
from pathlib import Path

import pytest

from core.rulepack import (
    ENGINE_CONTRACT_VERSION,
    PACK_FORMAT_VERSION,
    PackError,
    PackRegistry,
    build_manifest,
    build_pack,
    load_verified_rules,
    verify_pack,
)

KEY = b"test-signing-key-do-not-use-in-prod"
WRONG_KEY = b"a-different-key"
STAMP = datetime(2026, 7, 11, 12, 0, 0)


@pytest.fixture
def mini_rules(tmp_path):
    """A tiny valid rules directory with a schema and one rule."""
    src = tmp_path / "rules_src"
    (src / "windows").mkdir(parents=True)
    # Copy the real schema so load_verified_rules can validate.
    schema = Path("rules/schema.json").read_text()
    (src / "schema.json").write_text(schema)
    (src / "windows" / "probe.yml").write_text(
        'name: "Probe"\n'
        'id: "WIN-777"\n'
        'platform: windows\n'
        'severity: high\n'
        'detection:\n'
        '  process_name: "powershell.exe"\n'
    )
    return src


class TestBuildAndVerify:
    def test_manifest_lists_all_files_with_hashes(self, mini_rules):
        manifest = build_manifest(str(mini_rules), "v1", created_at=STAMP)
        assert manifest["pack_format_version"] == PACK_FORMAT_VERSION
        assert manifest["rule_count"] == 2  # schema.json + probe.yml
        paths = {e["path"] for e in manifest["rules"]}
        assert paths == {"schema.json", "windows/probe.yml"}
        for entry in manifest["rules"]:
            assert len(entry["sha256"]) == 64

    def test_build_then_verify_ok(self, mini_rules, tmp_path):
        pack = tmp_path / "pack"
        build_pack(str(mini_rules), str(pack), "v1", KEY, created_at=STAMP)
        result = verify_pack(str(pack), KEY)
        assert result.valid
        assert result.pack_version == "v1"
        assert len(result.verified_files) == 2

    def test_empty_rules_dir_raises(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(PackError, match="No rule files"):
            build_manifest(str(empty), "v1")

    def test_build_requires_key(self, mini_rules, tmp_path):
        with pytest.raises(PackError, match="signing key"):
            build_pack(str(mini_rules), str(tmp_path / "p"), "v1", b"")


class TestTamperDetection:
    def test_wrong_key_fails(self, mini_rules, tmp_path):
        pack = tmp_path / "pack"
        build_pack(str(mini_rules), str(pack), "v1", KEY, created_at=STAMP)
        result = verify_pack(str(pack), WRONG_KEY)
        assert not result.valid
        assert any("signature mismatch" in r for r in result.reasons)

    def test_modified_rule_file_fails(self, mini_rules, tmp_path):
        pack = tmp_path / "pack"
        build_pack(str(mini_rules), str(pack), "v1", KEY, created_at=STAMP)
        # Tamper with a rule after signing.
        target = pack / "windows" / "probe.yml"
        target.write_text(target.read_text() + "\n# injected\n")
        result = verify_pack(str(pack), KEY)
        assert not result.valid
        assert any("hash mismatch" in r for r in result.reasons)

    def test_added_unlisted_file_fails(self, mini_rules, tmp_path):
        pack = tmp_path / "pack"
        build_pack(str(mini_rules), str(pack), "v1", KEY, created_at=STAMP)
        (pack / "windows" / "sneaky.yml").write_text("name: x\n")
        result = verify_pack(str(pack), KEY)
        assert not result.valid
        assert any("unlisted file" in r for r in result.reasons)

    def test_removed_file_fails(self, mini_rules, tmp_path):
        pack = tmp_path / "pack"
        build_pack(str(mini_rules), str(pack), "v1", KEY, created_at=STAMP)
        (pack / "windows" / "probe.yml").unlink()
        result = verify_pack(str(pack), KEY)
        assert not result.valid
        assert any("missing file" in r for r in result.reasons)

    def test_missing_manifest_fails(self, tmp_path):
        bare = tmp_path / "bare"
        bare.mkdir()
        result = verify_pack(str(bare), KEY)
        assert not result.valid
        assert any("missing" in r for r in result.reasons)


class TestCompatibility:
    def test_future_engine_requirement_rejected(self, mini_rules, tmp_path):
        pack = tmp_path / "pack"
        build_pack(
            str(mini_rules), str(pack), "v1", KEY,
            engine_min_version=ENGINE_CONTRACT_VERSION + 1, created_at=STAMP,
        )
        result = verify_pack(str(pack), KEY)
        assert not result.valid
        assert any("needs engine version" in r for r in result.reasons)

    def test_unsupported_format_rejected(self, mini_rules, tmp_path):
        pack = tmp_path / "pack"
        build_pack(str(mini_rules), str(pack), "v1", KEY, created_at=STAMP)
        # Rewrite manifest with a bad format version, re-sign so only the
        # compatibility check (not the signature) trips.
        import json
        from core.rulepack import _canonical_manifest, _sign, MANIFEST_NAME, SIGNATURE_NAME
        manifest = json.loads((pack / MANIFEST_NAME).read_bytes())
        manifest["pack_format_version"] = 999
        blob = _canonical_manifest(manifest)
        (pack / MANIFEST_NAME).write_bytes(blob)
        (pack / SIGNATURE_NAME).write_text(_sign(blob, KEY))
        result = verify_pack(str(pack), KEY)
        assert not result.valid
        assert any("unsupported pack_format_version" in r for r in result.reasons)


class TestLoadVerifiedRules:
    def test_loads_after_verification(self, mini_rules, tmp_path):
        pack = tmp_path / "pack"
        build_pack(str(mini_rules), str(pack), "v1", KEY, created_at=STAMP)
        rules = load_verified_rules(str(pack), KEY)
        assert any(r.id == "WIN-777" for r in rules)

    def test_refuses_tampered_pack(self, mini_rules, tmp_path):
        pack = tmp_path / "pack"
        build_pack(str(mini_rules), str(pack), "v1", KEY, created_at=STAMP)
        (pack / "windows" / "probe.yml").write_text("name: evil\n")
        with pytest.raises(PackError):
            load_verified_rules(str(pack), KEY)


class TestPackRegistry:
    def _pack(self, mini_rules, tmp_path, version):
        pack = tmp_path / f"pack_{version}"
        build_pack(str(mini_rules), str(pack), version, KEY, created_at=STAMP)
        return str(pack)

    def test_stage_activate_rollback(self, mini_rules, tmp_path):
        reg = PackRegistry(str(tmp_path / "registry"))
        p1 = self._pack(mini_rules, tmp_path, "v1")
        p2 = self._pack(mini_rules, tmp_path, "v2")

        assert reg.stage(p1, KEY, when=STAMP) == "v1"
        assert reg.stage(p2, KEY, when=STAMP) == "v2"

        reg.activate("v1", KEY, when=STAMP)
        assert reg.active_version() == "v1"
        reg.activate("v2", KEY, when=STAMP)
        assert reg.active_version() == "v2"

        restored = reg.rollback(KEY, when=STAMP)
        assert restored == "v1"
        assert reg.active_version() == "v1"

    def test_activate_unstaged_fails(self, tmp_path):
        reg = PackRegistry(str(tmp_path / "registry"))
        with pytest.raises(PackError, match="not staged"):
            reg.activate("v9", KEY)

    def test_rollback_without_history_fails(self, mini_rules, tmp_path):
        reg = PackRegistry(str(tmp_path / "registry"))
        reg.stage(self._pack(mini_rules, tmp_path, "v1"), KEY, when=STAMP)
        reg.activate("v1", KEY, when=STAMP)
        with pytest.raises(PackError, match="No previous version"):
            reg.rollback(KEY)

    def test_stage_refuses_tampered_pack(self, mini_rules, tmp_path):
        reg = PackRegistry(str(tmp_path / "registry"))
        pack = tmp_path / "pack_bad"
        build_pack(str(mini_rules), str(pack), "v1", KEY, created_at=STAMP)
        (pack / "schema.json").write_text("{}")  # tamper
        with pytest.raises(PackError):
            reg.stage(str(pack), KEY)

    def test_audit_log_records_actions(self, mini_rules, tmp_path):
        reg = PackRegistry(str(tmp_path / "registry"))
        reg.stage(self._pack(mini_rules, tmp_path, "v1"), KEY, when=STAMP)
        reg.activate("v1", KEY, when=STAMP)
        audit = (tmp_path / "registry" / "audit.log").read_text()
        assert "stage" in audit
        assert "activate" in audit


def test_cli_build_and_verify(mini_rules, tmp_path, monkeypatch, capsys):
    from core.rulepack import _main
    monkeypatch.setenv("LOTL_RULEPACK_KEY", "cli-key")
    pack = tmp_path / "cli_pack"
    assert _main(["build", str(mini_rules), str(pack), "--version", "v1"]) == 0
    assert _main(["verify", str(pack)]) == 0
    out = capsys.readouterr().out
    assert "OK" in out


def test_cli_requires_key(mini_rules, tmp_path, monkeypatch):
    from core.rulepack import _main
    monkeypatch.delenv("LOTL_RULEPACK_KEY", raising=False)
    assert _main(["verify", str(tmp_path)]) == 2
