import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_quiet_suppresses_unknown_edge_warnings(tmp_path: Path, capsys):
    topo = {
        "assets": [{"id": "a", "ingress": True, "criticality": 1.0}],
        "edges": [{"source": "a", "target": "missing"}],
    }
    findings = {"findings": [{"id": "f", "asset_id": "a", "base_score": 5.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")

    assert main(["-t", str(t), "-f", str(f), "--format", "json"]) == 0
    assert "warning:" in capsys.readouterr().err

    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--quiet"]) == 0
    err = capsys.readouterr().err
    assert "warning:" not in err


def test_quiet_still_allows_summary(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {"findings": [{"id": "f", "asset_id": "a", "base_score": 5.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "-q", "--summary"]) == 0
    assert "summary:" in capsys.readouterr().err


def test_quiet_does_not_hide_strict_errors(tmp_path: Path, capsys):
    topo = {
        "assets": [{"id": "a", "ingress": True, "criticality": 1.0}],
        "edges": [{"source": "a", "target": "missing"}],
    }
    findings = {"findings": [{"id": "f", "asset_id": "a", "base_score": 5.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--strict", "--quiet"]) == 2
    assert "error:" in capsys.readouterr().err
