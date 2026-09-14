import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_show_title_column(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 0.5}], "edges": []}
    findings = {
        "findings": [
            {
                "id": "f",
                "asset_id": "a",
                "cve_id": "CVE-1",
                "base_score": 5.0,
                "title": "Example vulnerability title",
            }
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--show-title"]) == 0
    out = capsys.readouterr().out
    assert "TITLE" in out
    assert "Example vulnerability title" in out
