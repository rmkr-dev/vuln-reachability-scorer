"""Config extends / composition."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.config import ConfigError, load_config


def test_extends_overlay(tmp_path: Path):
    base = tmp_path / "base.toml"
    base.write_text('topology = "t.json"\nformat = "table"\nsummary = true\n', encoding="utf-8")
    child = tmp_path / "child.toml"
    child.write_text('extends = "base.toml"\nformat = "json"\nlimit = 3\n', encoding="utf-8")
    cfg = load_config(child)
    assert cfg["topology"] == "t.json"
    assert cfg["format"] == "json"  # overlay wins
    assert cfg["summary"] is True
    assert cfg["limit"] == 3


def test_extends_cycle(tmp_path: Path):
    a = tmp_path / "a.toml"
    b = tmp_path / "b.toml"
    a.write_text('extends = "b.toml"\nformat = "json"\n', encoding="utf-8")
    b.write_text('extends = "a.toml"\nformat = "table"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="extends cycle"):
        load_config(a)


def test_extends_must_be_string(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"extends": ["x.toml"]}), encoding="utf-8")
    with pytest.raises(ConfigError, match="extends must be a non-empty string"):
        load_config(p)


def test_example_extends_runs():
    root = Path(__file__).resolve().parents[1]
    rc = main(["--config", str(root / "examples" / "vrscore-triage.toml"), "--format", "json", "--limit", "1"])
    assert rc == 0

def test_extends_max_depth(tmp_path: Path):
    from vuln_reachability_scorer.config import MAX_EXTENDS_DEPTH

    prev = None
    for i in range(MAX_EXTENDS_DEPTH + 2):
        f = tmp_path / f"c{i}.toml"
        if prev is None:
            f.write_text('format = "json"\n', encoding="utf-8")
        else:
            f.write_text(
                f'extends = "{prev.name}"\nformat = "json"\n',
                encoding="utf-8",
            )
        prev = f
    with pytest.raises(ConfigError, match="max depth"):
        load_config(prev)
