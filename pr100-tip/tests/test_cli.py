import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_cli_table_and_json(tmp_path: Path, capsys):
    topology = {
        "assets": [
            {"id": "web", "name": "Web", "criticality": 0.9, "ingress": True},
            {"id": "api", "name": "API", "criticality": 0.7},
        ],
        "edges": [
            {"source": "web", "target": "api"},
        ],
    }
    findings = {
        "findings": [
            {
                "id": "f1",
                "asset_id": "web",
                "cve_id": "CVE-2023-44487",
                "base_score": 7.5,
                "title": "HTTP/2 Rapid Reset",
            },
            {
                "id": "f2",
                "asset_id": "api",
                "cve_id": "CVE-2021-44228",
                "base_score": 10.0,
                "title": "Log4Shell",
            },
        ]
    }
    tpath = tmp_path / "topology.json"
    fpath = tmp_path / "findings.json"
    tpath.write_text(json.dumps(topology), encoding="utf-8")
    fpath.write_text(json.dumps(findings), encoding="utf-8")

    assert main(["--topology", str(tpath), "--findings", str(fpath)]) == 0
    out = capsys.readouterr().out
    assert "PRIORITY" in out
    assert "CVE-2023-44487" in out

    assert main(
        ["--topology", str(tpath), "--findings", str(fpath), "--format", "json"]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["formula"].startswith("priority =")
    assert len(payload["results"]) == 2


def test_cli_missing_file(tmp_path: Path):
    rc = main(
        [
            "--topology",
            str(tmp_path / "nope.json"),
            "--findings",
            str(tmp_path / "nope2.json"),
        ]
    )
    assert rc == 2
