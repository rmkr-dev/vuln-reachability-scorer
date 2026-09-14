from vuln_reachability_scorer.explain import explain_score
from vuln_reachability_scorer.models import Asset, Finding
from vuln_reachability_scorer.scoring import score_findings
from vuln_reachability_scorer.cli import main
import json
from pathlib import Path


def test_explain_score_text():
    assets = [Asset(id="a", name="A", criticality=0.5, ingress=True)]
    findings = [Finding(id="f", asset_id="a", cve_id="CVE-1", base_score=8.0)]
    scored = score_findings(findings, assets, [])[0]
    text = explain_score(scored)
    assert "priority 4.00" in text
    assert "ingress" in text


def test_cli_explain_json(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {"findings": [{"id": "f", "asset_id": "a", "cve_id": "CVE-1", "base_score": 5.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--explain"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "explain" in payload["results"][0]
    assert "priority" in payload["results"][0]["explain"]
