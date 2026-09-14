import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_stats_line_on_stderr(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "i", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {"findings": [{"id": "1", "asset_id": "i", "cve_id": "CVE-1", "base_score": 5.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--stats"]) == 0
    err = capsys.readouterr().err
    assert "stats: load=" in err
    assert "score=" in err
    assert "render=" in err
    assert "findings=1" in err
