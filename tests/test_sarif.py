from vuln_reachability_scorer.models import Asset, Edge, Finding
from vuln_reachability_scorer.sarif import to_sarif
from vuln_reachability_scorer.scoring import score_findings
from vuln_reachability_scorer.cli import main
import json
from pathlib import Path


def test_sarif_structure():
    assets = [Asset(id="web", name="Web", criticality=0.9, ingress=True)]
    edges: list[Edge] = []
    findings = [
        Finding(id="f1", asset_id="web", cve_id="CVE-1", base_score=9.0, title="t")
    ]
    scored = score_findings(findings, assets, edges)
    doc = to_sarif(scored)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "vuln-reachability-scorer"
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "CVE-1"
    assert result["level"] == "error"
    assert result["properties"]["priority_score"] == scored[0].priority_score


def test_cli_sarif_format(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 0.5}], "edges": []}
    findings = {"findings": [{"id": "f", "asset_id": "a", "cve_id": "CVE-X", "base_score": 2.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "sarif"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 1
