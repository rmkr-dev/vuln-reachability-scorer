import json
from pathlib import Path

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.models import Asset, Finding
from vuln_reachability_scorer.scoring import score_findings
from vuln_reachability_scorer.summary import format_summary_line, summarize


def test_summarize_bands():
    assets = [Asset(id="a", name="A", criticality=1.0, ingress=True)]
    findings = [
        Finding(id="c", asset_id="a", cve_id="CVE-C", base_score=9.5),
        Finding(id="h", asset_id="a", cve_id="CVE-H", base_score=7.5),
        Finding(id="m", asset_id="a", cve_id="CVE-M", base_score=5.0),
        Finding(id="l", asset_id="a", cve_id="CVE-L", base_score=2.0),
        Finding(id="k", asset_id="a", cve_id="CVE-K", base_score=8.0, kev=True, epss=0.8),
    ]
    scored = score_findings(findings, assets, [])
    stats = summarize(scored)
    assert stats["count"] == 5
    assert stats["kev_count"] == 1
    assert stats["epss_count"] == 1
    assert stats["bands"]["critical"] >= 1
    assert "summary: n=5" in format_summary_line(stats)


def test_cli_summary_stderr(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "f", "asset_id": "a", "cve_id": "CVE-1", "base_score": 9.0, "kev": True, "epss": 0.5}
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--summary"]) == 0
    err = capsys.readouterr().err
    assert "summary: n=1" in err
    assert "kev=1" in err
    assert "epss=" in err
