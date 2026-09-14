import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_min_hops_filter(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "i", "ingress": True, "criticality": 1.0},
            {"id": "a", "criticality": 1.0},
            {"id": "b", "criticality": 1.0},
        ],
        "edges": [
            {"source": "i", "target": "a"},
            {"source": "a", "target": "b"},
        ],
    }
    findings = {
        "findings": [
            {"id": "0", "asset_id": "i", "cve_id": "CVE-0", "base_score": 5.0},
            {"id": "1", "asset_id": "a", "cve_id": "CVE-1", "base_score": 5.0},
            {"id": "2", "asset_id": "b", "cve_id": "CVE-2", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--min-hops", "1"]) == 0
    ids = {r["id"] for r in json.loads(capsys.readouterr().out)["results"]}
    assert ids == {"1", "2"}


def test_min_hops_with_max_hops(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "i", "ingress": True, "criticality": 1.0},
            {"id": "a", "criticality": 1.0},
            {"id": "b", "criticality": 1.0},
        ],
        "edges": [
            {"source": "i", "target": "a"},
            {"source": "a", "target": "b"},
        ],
    }
    findings = {
        "findings": [
            {"id": "0", "asset_id": "i", "cve_id": "CVE-0", "base_score": 5.0},
            {"id": "1", "asset_id": "a", "cve_id": "CVE-1", "base_score": 5.0},
            {"id": "2", "asset_id": "b", "cve_id": "CVE-2", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert (
        main(["-t", str(t), "-f", str(f), "--format", "json", "--min-hops", "1", "--max-hops", "1"])
        == 0
    )
    ids = {r["id"] for r in json.loads(capsys.readouterr().out)["results"]}
    assert ids == {"1"}
