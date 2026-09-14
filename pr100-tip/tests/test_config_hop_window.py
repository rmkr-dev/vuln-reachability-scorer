"""Config hop window consistency (min_hops <= max_hops)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.config import ConfigError, load_config


def test_min_hops_exceeds_max_rejected(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"min_hops": 3, "max_hops": 1}), encoding="utf-8")
    with pytest.raises(ConfigError, match="min_hops cannot exceed max_hops"):
        load_config(p)


def test_equal_hops_ok(tmp_path: Path):
    p = tmp_path / "ok.json"
    p.write_text(json.dumps({"min_hops": 2, "max_hops": 2}), encoding="utf-8")
    assert load_config(p)["min_hops"] == 2


def test_cli_bad_hop_window_config(tmp_path: Path, capsys):
    p = tmp_path / "bad.json"
    p.write_text(
        json.dumps({"topology": "t.json", "min_hops": 4, "max_hops": 1}),
        encoding="utf-8",
    )
    assert main(["--config", str(p)]) == 2
    assert "min_hops cannot exceed max_hops" in capsys.readouterr().err
