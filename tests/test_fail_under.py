import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def _write(tmp_path: Path, base_score: float = 9.0):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "f", "asset_id": "a", "cve_id": "CVE-1", "base_score": base_score}
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    return t, f


def test_fail_under_triggers(tmp_path: Path, capsys):
    t, f = _write(tmp_path, 9.0)
    # priority = 9.0 * 1 * 1 = 9.0
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--fail-under", "8"]) == 1
    assert "fail-under" in capsys.readouterr().err


def test_fail_under_passes(tmp_path: Path):
    t, f = _write(tmp_path, 3.0)
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--fail-under", "8"]) == 0


def test_fail_under_negative_rejected(tmp_path: Path):
    t, f = _write(tmp_path, 1.0)
    assert main(["-t", str(t), "-f", str(f), "--fail-under", "-1"]) == 2
