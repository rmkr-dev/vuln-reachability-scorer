import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def _topo_chain():
    return {
        "assets": [
            {"id": "edge", "ingress": True, "criticality": 0.5},
            {"id": "app", "ingress": False, "criticality": 0.5},
            {"id": "db", "ingress": False, "criticality": 0.5},
            {"id": "island", "ingress": False, "criticality": 0.5},
        ],
        "edges": [
            {"source": "edge", "target": "app"},
            {"source": "app", "target": "db"},
        ],
    }


def test_max_hops_filters(tmp_path: Path, capsys):
    findings = {
        "findings": [
            {"id": "h0", "asset_id": "edge", "cve_id": "CVE-0", "base_score": 5.0},
            {"id": "h1", "asset_id": "app", "cve_id": "CVE-1", "base_score": 5.0},
            {"id": "h2", "asset_id": "db", "cve_id": "CVE-2", "base_score": 5.0},
            {"id": "u", "asset_id": "island", "cve_id": "CVE-U", "base_score": 9.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(_topo_chain()), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--max-hops", "1"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["h0", "h1"]


def test_max_hops_zero_is_ingress_only(tmp_path: Path, capsys):
    findings = {
        "findings": [
            {"id": "h0", "asset_id": "edge", "cve_id": "CVE-0", "base_score": 5.0},
            {"id": "h1", "asset_id": "app", "cve_id": "CVE-1", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(_topo_chain()), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--max-hops", "0"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["h0"]


def test_max_hops_negative_errors(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {"findings": [{"id": "x", "asset_id": "a", "base_score": 1.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--max-hops", "-1"]) == 2
    assert "max-hops" in capsys.readouterr().err
