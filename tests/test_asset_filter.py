import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_asset_filter_single_and_multi(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "edge", "ingress": True, "criticality": 1.0},
            {"id": "app", "ingress": False, "criticality": 1.0},
        ],
        "edges": [{"source": "edge", "target": "app"}],
    }
    findings = {
        "findings": [
            {"id": "e", "asset_id": "edge", "cve_id": "CVE-E", "base_score": 5.0},
            {"id": "a", "asset_id": "app", "cve_id": "CVE-A", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--asset", "app"]) == 0
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["a"]

    assert (
        main(
            [
                "-t",
                str(t),
                "-f",
                str(f),
                "--format",
                "json",
                "--asset",
                "edge",
                "--asset",
                "app",
            ]
        )
        == 0
    )
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert set(ids) == {"e", "a"}
