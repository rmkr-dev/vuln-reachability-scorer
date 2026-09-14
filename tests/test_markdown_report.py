import json
from pathlib import Path

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.markdown_report import to_markdown
from vuln_reachability_scorer.models import Asset, Finding
from vuln_reachability_scorer.scoring import score_findings


def test_to_markdown_table_and_pipe_escape():
    assets = [Asset(id="a", name="A", criticality=1.0, ingress=True)]
    findings = [
        Finding(
            id="f|1",
            asset_id="a",
            cve_id="CVE-1",
            base_score=8.0,
            title="pipe | title",
        )
    ]
    text = to_markdown(score_findings(findings, assets, []), explain=True)
    assert text.startswith("# vuln-reachability-scorer")
    assert "| PRIORITY |" in text
    assert "CVE-1" in text
    assert "\\|" in text
    assert "priority" in text


def test_to_markdown_empty():
    text = to_markdown([])
    assert "No findings to report." in text


def test_cli_markdown_file(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 0.5}], "edges": []}
    findings = {
        "findings": [{"id": "f", "asset_id": "a", "cve_id": "CVE-X", "base_score": 4.0}]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    out = tmp_path / "out.md"
    assert main(["-t", str(t), "-f", str(f), "--format", "markdown", "-o", str(out)]) == 0
    assert capsys.readouterr().out == ""
    text = out.read_text(encoding="utf-8")
    assert "CVE-X" in text
    assert "| PRIORITY |" in text


def test_cli_asset_report_markdown(tmp_path: Path, capsys):
    topo = {
        "assets": [{"id": "web", "name": "Web", "ingress": True, "criticality": 0.6}],
        "edges": [],
    }
    t = tmp_path / "t.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    assert main(["-t", str(t), "--asset-report", "--format", "markdown"]) == 0
    out = capsys.readouterr().out
    assert "Asset reachability inventory" in out
    assert "web" in out
