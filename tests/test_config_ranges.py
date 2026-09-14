"""Config numeric range validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.config import ConfigError, load_config


@pytest.mark.parametrize(
    "payload,match",
    [
        ({"min_epss": 1.5}, "min_epss must be in"),
        ({"min_epss": -0.1}, "min_epss must be in"),
        ({"min_priority": -1}, "min_priority must be >= 0"),
        ({"fail_under": -0.5}, "fail_under must be >= 0"),
        ({"min_base": -1}, "min_base must be >= 0"),
        ({"limit": -1}, "limit must be >= 0"),
        ({"max_hops": -2}, "max_hops must be >= 0"),
        ({"min_hops": -1}, "min_hops must be >= 0"),
    ],
)
def test_range_rejected(tmp_path: Path, payload: dict, match: str):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConfigError, match=match):
        load_config(p)


def test_range_ok(tmp_path: Path):
    p = tmp_path / "ok.json"
    p.write_text(
        json.dumps(
            {
                "min_epss": 0.0,
                "min_priority": 0,
                "fail_under": 7,
                "min_base": 0,
                "limit": 0,
                "max_hops": 0,
                "min_hops": 0,
            }
        ),
        encoding="utf-8",
    )
    cfg = load_config(p)
    assert cfg["min_epss"] == 0.0
    assert cfg["limit"] == 0


def test_cli_range_exit_2(tmp_path: Path, capsys):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"topology": "t.json", "min_epss": 2}), encoding="utf-8")
    assert main(["--config", str(p)]) == 2
    assert "min_epss" in capsys.readouterr().err
