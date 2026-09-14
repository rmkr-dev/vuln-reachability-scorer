import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_jsonl_findings(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "1", "asset_id": "a", "cve_id": "CVE-1", "base_score": 9.0},
            {"id": "2", "asset_id": "a", "cve_id": "CVE-2", "base_score": 5.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "jsonl"]) == 0
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 2
    rows = [json.loads(ln) for ln in lines]
    assert {r.get("id") or r.get("asset_id") for r in rows} == {"1", "2"}
    assert all("priority_score" in r for r in rows)


def test_jsonl_asset_report(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "a", "ingress": True, "criticality": 1.0},
            {"id": "b", "ingress": False, "criticality": 0.5},
        ],
        "edges": [],
    }
    t = tmp_path / "t.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    assert main(["-t", str(t), "--asset-report", "--format", "jsonl"]) == 0
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 2
    rows = [json.loads(ln) for ln in lines]
    assert {r.get("id") or r.get("asset_id") for r in rows} == {"a", "b"}


def test_jsonl_output_file(tmp_path: Path):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {"findings": [{"id": "1", "asset_id": "a", "base_score": 5.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    out = tmp_path / "out.jsonl"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "jsonl", "-o", str(out)]) == 0
    rows = [json.loads(ln) for ln in out.read_text(encoding="utf-8").splitlines() if ln]
    assert len(rows) == 1
    assert rows[0]["id"] == "1"
