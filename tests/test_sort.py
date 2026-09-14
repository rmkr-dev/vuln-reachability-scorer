import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_sort_by_hops_and_asset(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "edge", "ingress": True, "criticality": 0.5},
            {"id": "app", "ingress": False, "criticality": 0.5},
            {"id": "island", "ingress": False, "criticality": 0.5},
        ],
        "edges": [{"source": "edge", "target": "app"}],
    }
    findings = {
        "findings": [
            {"id": "u", "asset_id": "island", "cve_id": "CVE-U", "base_score": 9.0},
            {"id": "a", "asset_id": "app", "cve_id": "CVE-A", "base_score": 5.0},
            {"id": "e", "asset_id": "edge", "cve_id": "CVE-E", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--sort", "hops"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["e", "a", "u"]

    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--sort", "asset"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["a", "e", "u"]


def test_sort_by_cve(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "2", "asset_id": "a", "cve_id": "CVE-2024-2", "base_score": 5.0},
            {"id": "1", "asset_id": "a", "cve_id": "CVE-2024-1", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--sort", "cve"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["1", "2"]
