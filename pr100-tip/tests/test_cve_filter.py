import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_cve_filter_case_insensitive(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "1", "asset_id": "a", "cve_id": "CVE-2024-1111", "base_score": 5.0},
            {"id": "2", "asset_id": "a", "cve_id": "CVE-2024-2222", "base_score": 5.0},
            {"id": "3", "asset_id": "a", "cve_id": "", "base_score": 9.0},
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
                "--cve",
                "cve-2024-1111",
            ]
        )
        == 0
    )
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["1"]

    assert (
        main(
            [
                "-t",
                str(t),
                "-f",
                str(f),
                "--format",
                "json",
                "--cve",
                "CVE-2024-1111",
                "--cve",
                "CVE-2024-2222",
            ]
        )
        == 0
    )
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert set(ids) == {"1", "2"}
