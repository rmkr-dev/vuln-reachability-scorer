import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_exclude_asset_and_cve(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "a", "ingress": True, "criticality": 1.0},
            {"id": "b", "ingress": True, "criticality": 1.0},
        ],
        "edges": [],
    }
    findings = {
        "findings": [
            {"id": "1", "asset_id": "a", "cve_id": "CVE-1", "base_score": 5.0},
            {"id": "2", "asset_id": "b", "cve_id": "CVE-2", "base_score": 5.0},
            {"id": "3", "asset_id": "b", "cve_id": "CVE-3", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--exclude-asset", "a"]) == 0
    ids = {r["id"] for r in json.loads(capsys.readouterr().out)["results"]}
    assert ids == {"2", "3"}
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--exclude-cve", "cve-2"]) == 0
    ids = {r["id"] for r in json.loads(capsys.readouterr().out)["results"]}
    assert ids == {"1", "3"}
