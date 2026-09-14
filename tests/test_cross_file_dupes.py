import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def _write(tmp_path: Path):
    topo = {"assets": [{"id": "i", "ingress": True, "criticality": 1.0}], "edges": []}
    f1 = {"findings": [{"id": "same", "asset_id": "i", "cve_id": "CVE-1", "base_score": 5.0}]}
    f2 = {"findings": [{"id": "same", "asset_id": "i", "cve_id": "CVE-2", "base_score": 6.0}]}
    t = tmp_path / "t.json"
    p1 = tmp_path / "a.json"
    p2 = tmp_path / "b.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    p1.write_text(json.dumps(f1), encoding="utf-8")
    p2.write_text(json.dumps(f2), encoding="utf-8")
    return t, p1, p2


def test_cross_file_dupe_warns(tmp_path: Path, capsys):
    t, p1, p2 = _write(tmp_path)
    assert main(["-t", str(t), "-f", str(p1), "-f", str(p2), "--format", "json"]) == 0
    err = capsys.readouterr().err
    assert "warning: duplicate finding id(s) across inputs: same" in err


def test_cross_file_dupe_strict(tmp_path: Path, capsys):
    t, p1, p2 = _write(tmp_path)
    assert main(["-t", str(t), "-f", str(p1), "-f", str(p2), "--strict"]) == 2
    err = capsys.readouterr().err
    assert "error: duplicate finding id(s) across inputs: same" in err


def test_cross_file_dupe_quiet(tmp_path: Path, capsys):
    t, p1, p2 = _write(tmp_path)
    assert main(["-t", str(t), "-f", str(p1), "-f", str(p2), "--quiet", "--format", "json"]) == 0
    err = capsys.readouterr().err
    assert "duplicate finding id" not in err
