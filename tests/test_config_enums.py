"""Config enum validation for format, sort, and band."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.config import ConfigError, load_config


def test_invalid_format(tmp_path: Path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps({"format": "yaml"}), encoding="utf-8")
    with pytest.raises(ConfigError, match="format must be one of"):
        load_config(p)


def test_invalid_sort(tmp_path: Path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"sort": "score"}), encoding="utf-8")
    with pytest.raises(ConfigError, match="sort must be one of"):
        load_config(p)


def test_invalid_band(tmp_path: Path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"band": ["high", "urgent"]}), encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown: urgent"):
        load_config(p)


def test_valid_enums(tmp_path: Path):
    p = tmp_path / "ok.toml"
    p.write_text(
        'format = "jsonl"\nsort = "hops"\nband = ["critical", "low"]\n',
        encoding="utf-8",
    )
    cfg = load_config(p)
    assert cfg["format"] == "jsonl"
    assert cfg["sort"] == "hops"
    assert cfg["band"] == ["critical", "low"]


def test_cli_rejects_bad_format_config(tmp_path: Path, capsys):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"topology": "t.json", "format": "xml"}), encoding="utf-8")
    assert main(["--config", str(p)]) == 2
    assert "format must be one of" in capsys.readouterr().err
