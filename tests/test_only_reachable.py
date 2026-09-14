import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_only_reachable_filters(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "edge", "ingress": True, "criticality": 1.0},
            {"id": "island", "ingress": False, "criticality": 1.0},
        ],
        "edges": [],
    }
    findings = {
        "findings": [
            {"id": "r", "asset_id": "edge", "cve_id": "CVE-R", "base_score": 5.0},
            {"id": "u", "asset_id": "island", "cve_id": "CVE-U", "base_score": 9.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--only-reachable"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [r["id"] for r in payload["results"]] == ["r"]
    assert payload["results"][0]["hop_distance"] == 0


def test_only_reachable_keeps_multi_hop(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "edge", "ingress": True, "criticality": 0.5},
            {"id": "app", "ingress": False, "criticality": 0.5},
        ],
        "edges": [{"source": "edge", "target": "app"}],
    }
    findings = {
        "findings": [
            {"id": "a", "asset_id": "app", "cve_id": "CVE-A", "base_score": 8.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--only-reachable"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [r["id"] for r in payload["results"]] == ["a"]
    assert payload["results"][0]["hop_distance"] == 1
