"""Example config files remain loadable and runnable."""

from pathlib import Path

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.config import load_config

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def test_example_configs_load():
    for name in (
        "vrscore.toml",
        "vrscore.json",
        "vrscore-triage.toml",
        "vrscore-ci.toml",
        "vrscore-multi.toml",
    ):
        cfg = load_config(EXAMPLES / name)
        assert "topology" in cfg
        assert "findings" in cfg


def test_triage_config_runs():
    rc = main(["--config", str(EXAMPLES / "vrscore-triage.toml"), "--format", "json", "--limit", "1"])
    assert rc == 0


def test_multi_config_runs():
    rc = main(["--config", str(EXAMPLES / "vrscore-multi.toml"), "--format", "json", "--limit", "3"])
    assert rc == 0
