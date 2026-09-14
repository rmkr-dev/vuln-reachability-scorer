import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.cli import main
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


def test_cli_config_runs_examples(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    cfg = root / "examples" / "vrscore.toml"
    assert cfg.is_file()
    rc = main(["--config", str(cfg), "--format", "json", "--limit", "2"])
    assert rc == 0


def test_cli_overrides_config(tmp_path: Path, capsys):
    root = Path(__file__).resolve().parents[1]
    cfg = root / "examples" / "vrscore.json"
    # config asks for json + band filter; CLI forces table and drops band via full rescore path
    rc = main(["--config", str(cfg), "--format", "table", "--band", "low"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PRIORITY" in out


def test_config_relative_paths(tmp_path: Path):
    # copy mini topology/findings next to config
    topo = {
        "assets": [{"id": "i", "name": "I", "ingress": True, "criticality": 1.0}],
        "edges": [],
    }
    findings = {
        "findings": [
            {"id": "f1", "asset_id": "i", "base_score": 9.0, "cve_id": "CVE-1"}
        ]
    }
    (tmp_path / "t.json").write_text(json.dumps(topo), encoding="utf-8")
    (tmp_path / "f.json").write_text(json.dumps(findings), encoding="utf-8")
    cfg = tmp_path / "c.toml"
    cfg.write_text('topology = "t.json"\nfindings = "f.json"\nformat = "json"\n', encoding="utf-8")
    rc = main(["--config", str(cfg)])
    assert rc == 0


def test_unsupported_extension(tmp_path: Path):
    p = tmp_path / "x.yaml"
    p.write_text("topology: t\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unsupported"):
        load_config(p)
