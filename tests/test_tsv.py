import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_tsv_findings_and_asset_report(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "a", "ingress": True, "criticality": 1.0, "tags": ["pii"]},
            {"id": "b", "ingress": False, "criticality": 0.5},
        ],
        "edges": [],
    }
    findings = {
        "findings": [
            {"id": "1", "asset_id": "a", "cve_id": "CVE-1", "base_score": 9.0, "title": "x"},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "tsv"]) == 0
    out = capsys.readouterr().out
    header, row = out.strip().splitlines()[:2]
    assert "\t" in header
    assert "priority_score" in header
    assert "CVE-1" in row

    assert main(["-t", str(t), "--asset-report", "--format", "tsv"]) == 0
    aout = capsys.readouterr().out
    assert "asset_id" in aout.splitlines()[0]
    assert aout.count("\n") >= 2
