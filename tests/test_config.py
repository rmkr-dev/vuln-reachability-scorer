import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.config import ConfigError, load_config


def test_load_toml_and_json(tmp_path: Path):
    toml = tmp_path / "vrscore.toml"
    toml.write_text(
        'topology = "topo.json"\nfindings = "find.json"\nformat = "json"\n'
        "summary = true\nband = [\"high\", \"critical\"]\n",
        encoding="utf-8",
    )
    cfg = load_config(toml)
    assert cfg["topology"] == "topo.json"
    assert cfg["format"] == "json"
    assert cfg["summary"] is True
    assert cfg["band"] == ["high", "critical"]

    js = tmp_path / "vrscore.json"
    js.write_text(json.dumps({"topology": "t.json", "quiet": True, "limit": 5}), encoding="utf-8")
    cfg2 = load_config(js)
    assert cfg2["quiet"] is True
    assert cfg2["limit"] == 5


def test_unknown_key_rejected(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text('{"topology": "t.json", "nope": 1}', encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(p)


def test_unsupported_extension(tmp_path: Path):
    p = tmp_path / "x.yaml"
    p.write_text("topology: t\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unsupported"):
        load_config(p)
