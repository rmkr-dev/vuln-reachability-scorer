import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_limit_applies_after_band(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "c", "asset_id": "a", "cve_id": "CVE-C", "base_score": 9.5},
            {"id": "h", "asset_id": "a", "cve_id": "CVE-H", "base_score": 7.5},
            {"id": "m", "asset_id": "a", "cve_id": "CVE-M", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert (
        main(
            [
                "-t",
                str(t),
                "-f",
                str(f),
                "--format",
                "json",
                "--band",
                "critical",
                "--band",
                "high",
                "--limit",
                "1",
            ]
        )
        == 0
    )
    rows = json.loads(capsys.readouterr().out)["results"]
    assert len(rows) == 1
    assert rows[0]["id"] == "c"
