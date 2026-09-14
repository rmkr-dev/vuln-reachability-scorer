import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_min_priority_filters(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "hot", "ingress": True, "criticality": 1.0},
            {"id": "cold", "criticality": 0.1},
        ],
        "edges": [],
    }
    findings = {
        "findings": [
            {"id": "hi", "asset_id": "hot", "cve_id": "CVE-HI", "base_score": 9.0},
            {"id": "lo", "asset_id": "cold", "cve_id": "CVE-LO", "base_score": 9.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")

    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--min-priority", "5"]) == 0
    payload = json.loads(capsys.readouterr().out)
    ids = [r["id"] for r in payload["results"]]
    assert ids == ["hi"]


def test_min_priority_negative_rejected(tmp_path: Path):
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps({"assets": [], "edges": []}), encoding="utf-8")
    f.write_text(json.dumps({"findings": []}), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--min-priority", "-1"]) == 2
