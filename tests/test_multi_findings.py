import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_repeatable_findings_merged(tmp_path: Path, capsys):
    topo = {
        "assets": [{"id": "i", "name": "I", "ingress": True, "criticality": 1.0}],
        "edges": [],
    }
    f1 = {"findings": [{"id": "a", "asset_id": "i", "base_score": 5.0, "cve_id": "CVE-1"}]}
    f2 = {"findings": [{"id": "b", "asset_id": "i", "base_score": 9.0, "cve_id": "CVE-2"}]}
    t = tmp_path / "t.json"
    p1 = tmp_path / "f1.json"
    p2 = tmp_path / "f2.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    p1.write_text(json.dumps(f1), encoding="utf-8")
    p2.write_text(json.dumps(f2), encoding="utf-8")
    rc = main(["-t", str(t), "-f", str(p1), "-f", str(p2), "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    ids = {r["id"] for r in payload["results"]}
    assert ids == {"a", "b"}
