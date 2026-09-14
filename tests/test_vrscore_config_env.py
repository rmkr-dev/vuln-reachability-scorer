
import json
import os
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_vrscore_config_env(tmp_path: Path, monkeypatch, capsys):
    topo = {"assets": [{"id": "i", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {"findings": [{"id": "1", "asset_id": "i", "cve_id": "CVE-1", "base_score": 5.0}]}
    (tmp_path / "t.json").write_text(json.dumps(topo), encoding="utf-8")
    (tmp_path / "f.json").write_text(json.dumps(findings), encoding="utf-8")
    cfg = tmp_path / "c.toml"
    cfg.write_text('topology = "t.json"\nfindings = "f.json"\nformat = "json"\n', encoding="utf-8")
    monkeypatch.setenv("VRSCORE_CONFIG", str(cfg))
    assert main([]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["results"][0]["id"] == "1"


def test_cli_config_overrides_env(tmp_path: Path, monkeypatch, capsys):
    topo = {"assets": [{"id": "i", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {"findings": [{"id": "1", "asset_id": "i", "cve_id": "CVE-1", "base_score": 5.0}]}
    (tmp_path / "t.json").write_text(json.dumps(topo), encoding="utf-8")
    (tmp_path / "f.json").write_text(json.dumps(findings), encoding="utf-8")
    env_cfg = tmp_path / "env.toml"
    env_cfg.write_text('topology = "t.json"\nfindings = "f.json"\nformat = "table"\n', encoding="utf-8")
    cli_cfg = tmp_path / "cli.toml"
    cli_cfg.write_text('topology = "t.json"\nfindings = "f.json"\nformat = "json"\n', encoding="utf-8")
    monkeypatch.setenv("VRSCORE_CONFIG", str(env_cfg))
    assert main(["--config", str(cli_cfg)]) == 0
    out = capsys.readouterr().out
    assert out.lstrip().startswith("{")
