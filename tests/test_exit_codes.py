import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_exit_codes_success_fail_under_and_usage(tmp_path: Path):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {"findings": [{"id": "f", "asset_id": "a", "base_score": 9.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json"]) == 0
    assert main(["-t", str(t), "-f", str(f), "--fail-under", "7"]) == 1
    assert main(["-t", str(t), "-f", str(f), "--min-priority", "-1"]) == 2
