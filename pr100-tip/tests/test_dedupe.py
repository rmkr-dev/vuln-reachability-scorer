import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_dedupe_keeps_highest_priority(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "low", "asset_id": "a", "cve_id": "CVE-1", "base_score": 4.0},
            {"id": "high", "asset_id": "a", "cve_id": "CVE-1", "base_score": 9.0},
            {"id": "other", "asset_id": "a", "cve_id": "CVE-2", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--dedupe"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["high", "other"]


def test_dedupe_case_insensitive_cve(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "a1", "asset_id": "a", "cve_id": "cve-9", "base_score": 6.0},
            {"id": "a2", "asset_id": "a", "cve_id": "CVE-9", "base_score": 8.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--dedupe"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["a2"]
