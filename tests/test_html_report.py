import json
from pathlib import Path

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.html_report import to_html
from vuln_reachability_scorer.models import Asset, Finding
from vuln_reachability_scorer.scoring import score_findings


def test_to_html_escapes_and_lists_findings():
    assets = [Asset(id="a", name="A", criticality=1.0, ingress=True)]
    findings = [
        Finding(
            id="f<1>",
            asset_id="a",
            cve_id="CVE-1",
            base_score=8.0,
            title='<script>alert("x")</script>',
        )
    ]
    html = to_html(score_findings(findings, assets, []), explain=True)
    assert "<!DOCTYPE html>" in html
    assert "<table>" in html
    assert "CVE-1" in html
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "f&lt;1&gt;" in html
    assert "priority" in html


def test_to_html_empty():
    html = to_html([])
    assert "No findings to report." in html


def test_cli_html_file(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 0.5}], "edges": []}
    findings = {
        "findings": [{"id": "f", "asset_id": "a", "cve_id": "CVE-X", "base_score": 4.0}]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    out = tmp_path / "out.html"
    assert main(["-t", str(t), "-f", str(f), "--format", "html", "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert capsys.readouterr().out == ""
    assert "CVE-X" in text
    assert "PRIORITY" in text


def test_cli_asset_report_html(tmp_path: Path, capsys):
    topo = {
        "assets": [{"id": "web", "name": "Web", "ingress": True, "criticality": 0.6}],
        "edges": [],
    }
    t = tmp_path / "t.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    assert main(["-t", str(t), "--asset-report", "--format", "html"]) == 0
    out = capsys.readouterr().out
    assert "Asset reachability inventory" in out
    assert "web" in out
