import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_exclude_tag_drops_matching(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "db", "ingress": True, "criticality": 1.0, "tags": ["pii"]},
            {"id": "web", "ingress": True, "criticality": 1.0, "tags": ["public"]},
            {"id": "auth", "ingress": True, "criticality": 1.0, "tags": ["identity"]},
        ],
        "edges": [],
    }
    findings = {
        "findings": [
            {"id": "1", "asset_id": "db", "cve_id": "CVE-1", "base_score": 5.0},
            {"id": "2", "asset_id": "web", "cve_id": "CVE-2", "base_score": 5.0},
            {"id": "3", "asset_id": "auth", "cve_id": "CVE-3", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--exclude-tag", "pii"]) == 0
    ids = {r["id"] for r in json.loads(capsys.readouterr().out)["results"]}
    assert ids == {"2", "3"}


def test_tag_then_exclude_tag(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "db", "ingress": True, "criticality": 1.0, "tags": ["pii", "identity"]},
            {"id": "auth", "ingress": True, "criticality": 1.0, "tags": ["identity"]},
        ],
        "edges": [],
    }
    findings = {
        "findings": [
            {"id": "1", "asset_id": "db", "cve_id": "CVE-1", "base_score": 5.0},
            {"id": "2", "asset_id": "auth", "cve_id": "CVE-2", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert (
        main(
            [
                "-t", str(t), "-f", str(f), "--format", "json",
                "--tag", "identity", "--exclude-tag", "PII",
            ]
        )
        == 0
    )
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids == ["2"]
