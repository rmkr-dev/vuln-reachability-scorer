import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_min_base_filters(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "hi", "asset_id": "a", "cve_id": "CVE-HI", "base_score": 9.0},
            {"id": "lo", "asset_id": "a", "cve_id": "CVE-LO", "base_score": 3.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--min-base", "7"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["hi"]


def test_min_base_negative_errors(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {"findings": [{"id": "x", "asset_id": "a", "base_score": 1.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--min-base", "-1"]) == 2
    assert "min-base" in capsys.readouterr().err
