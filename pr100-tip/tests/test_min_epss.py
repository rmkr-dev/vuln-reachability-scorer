import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_min_epss_filters(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "hi", "asset_id": "a", "cve_id": "CVE-HI", "base_score": 5.0, "epss": 0.90},
            {"id": "lo", "asset_id": "a", "cve_id": "CVE-LO", "base_score": 5.0, "epss": 0.10},
            {"id": "none", "asset_id": "a", "cve_id": "CVE-N", "base_score": 9.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--min-epss", "0.5"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["hi"]


def test_min_epss_out_of_range(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {"findings": [{"id": "x", "asset_id": "a", "base_score": 1.0, "epss": 0.5}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--min-epss", "1.5"]) == 2
    assert "min-epss" in capsys.readouterr().err
