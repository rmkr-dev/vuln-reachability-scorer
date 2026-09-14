import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_only_kev_filters(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "k", "asset_id": "a", "cve_id": "CVE-K", "base_score": 5.0, "kev": True},
            {"id": "n", "asset_id": "a", "cve_id": "CVE-N", "base_score": 9.0, "kev": False},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--only-kev"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [r["id"] for r in payload["results"]] == ["k"]
