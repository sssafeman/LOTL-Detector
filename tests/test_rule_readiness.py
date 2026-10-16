"""
Rule loading and readiness tests (finding E17).

Rule loading must not depend on the current working directory, must
fail loudly on missing or broken rule sets (no silent partial
coverage), and the service must distinguish liveness (/api/health)
from readiness (/api/ready).
"""
import subprocess
import sys
from pathlib import Path

import pytest

from api.server import create_app
from api.startup import StartupError
from core.rule_loader import RuleLoader, RuleLoadError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPO_RULES = PROJECT_ROOT / "rules"
CERTUTIL = REPO_RULES / "windows" / "certutil_download.yml"


def test_rule_loader_resolves_schema_from_any_cwd(tmp_path, monkeypatch):
    """The loader works from any working directory, not just the repo root."""
    monkeypatch.chdir(tmp_path)

    loader = RuleLoader()
    assert loader.schema and "properties" in loader.schema

    rules = loader.load_rules_directory("rules")
    assert any(rule.id == "WIN-001" for rule in rules)


def test_demo_list_rules_works_outside_repo(tmp_path):
    """W2 regression: the demo previously failed outside the repo root."""
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "demo_detector.py"), "--list-rules"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "WIN-001" in result.stdout


def test_missing_rules_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        RuleLoader().load_rules_directory(str(tmp_path / "missing"))


def test_broken_rule_file_raises_instead_of_partial_load(tmp_path):
    """One bad rule file fails the load; no silent partial coverage."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "good.yml").write_text(CERTUTIL.read_text())
    (rules_dir / "broken.yml").write_text("name: broken\n")

    with pytest.raises(RuleLoadError) as excinfo:
        RuleLoader().load_rules_directory(str(rules_dir))
    assert "broken.yml" in str(excinfo.value)


def test_duplicate_rule_ids_are_rejected(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    content = CERTUTIL.read_text()
    (rules_dir / "a.yml").write_text(content)
    (rules_dir / "b.yml").write_text(content)

    with pytest.raises(RuleLoadError) as excinfo:
        RuleLoader().load_rules_directory(str(rules_dir))
    assert "WIN-001" in str(excinfo.value)


def test_empty_rules_directory_raises(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    with pytest.raises(RuleLoadError):
        RuleLoader().load_rules_directory(str(rules_dir))


def _app_config(tmp_path, **overrides):
    config = {
        "DATABASE_PATH": str(tmp_path / "api.db"),
        "RULES_DIR": str(REPO_RULES),
        "TESTING": True,
        "LOG_LEVEL": "ERROR",
    }
    config.update(overrides)
    return config


def test_create_app_fails_when_rules_directory_missing(tmp_path):
    with pytest.raises(StartupError):
        create_app(_app_config(tmp_path, RULES_DIR=str(tmp_path / "no-rules")))


def test_create_app_fails_when_correlation_rules_missing(tmp_path):
    rules_dir = tmp_path / "rules"
    (rules_dir / "windows").mkdir(parents=True)
    (rules_dir / "windows" / "certutil.yml").write_text(CERTUTIL.read_text())

    with pytest.raises(StartupError):
        create_app(_app_config(tmp_path, RULES_DIR=str(rules_dir)))


def test_ready_endpoint_reports_ready(tmp_path):
    app = create_app(_app_config(tmp_path))
    response = app.test_client().get("/api/ready")

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ready"
    assert data["rules_loaded"] > 0


def test_ready_endpoint_reports_not_ready_without_rules(tmp_path, monkeypatch):
    app = create_app(_app_config(tmp_path))

    import api.server as server_module

    monkeypatch.setattr(server_module.engine, "rules", [])

    response = app.test_client().get("/api/ready")
    assert response.status_code == 503
    assert response.get_json()["status"] == "not_ready"


def test_create_app_fails_when_a_chain_file_is_broken(tmp_path):
    """S2 review finding 2: a broken chain file must not yield a
    running service with zero correlation coverage reporting ready."""
    import shutil

    rules_dir = tmp_path / "rules"
    shutil.copytree(REPO_RULES, rules_dir)
    (rules_dir / "correlation" / "broken.yml").write_text("name: broken\n")

    with pytest.raises(StartupError):
        create_app(_app_config(tmp_path, RULES_DIR=str(rules_dir)))


def test_chain_loading_is_cwd_independent(tmp_path, monkeypatch):
    """S2 review finding 6: chain schema resolution must not use cwd."""
    monkeypatch.chdir(tmp_path)

    from core.correlator import ChainRuleLoader

    chains = ChainRuleLoader().load_chains_directory(
        str(REPO_RULES / "correlation")
    )
    assert chains
    assert all(chain.id for chain in chains)


def test_ready_reports_chain_count(tmp_path):
    app = create_app(_app_config(tmp_path))
    data = app.test_client().get("/api/ready").get_json()

    assert data["status"] == "ready"
    assert data["chains_loaded"] >= 1
