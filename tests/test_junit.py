import json
from pathlib import Path
from xml.etree import ElementTree as ET

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.junit_report import to_junit
from vuln_reachability_scorer.models import Finding, ScoredFinding


def test_to_junit_marks_high_priority_as_failure():
    high = ScoredFinding(
        finding=Finding(id="h", asset_id="a", cve_id="CVE-H", base_score=9.0),
        reachability_factor=1.0,
        exposure_factor=1.0,
        priority_score=9.0,
        hop_distance=0,
    )
    low = ScoredFinding(
        finding=Finding(id="l", asset_id="a", cve_id="CVE-L", base_score=2.0),
        reachability_factor=1.0,
        exposure_factor=1.0,
        priority_score=2.0,
        hop_distance=0,
    )
    root = ET.fromstring(to_junit([high, low]))
    assert root.attrib["tests"] == "2"
    assert root.attrib["failures"] == "1"
    cases = list(root.findall("testcase"))
    assert len(cases) == 2
    assert cases[0].find("failure") is not None
    assert cases[1].find("failure") is None


def test_cli_junit_and_asset_report_rejected(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {"id": "h", "asset_id": "a", "cve_id": "CVE-H", "base_score": 9.0},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    out = tmp_path / "out.xml"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "junit", "-o", str(out)]) == 0
    root = ET.fromstring(out.read_text(encoding="utf-8"))
    assert root.tag == "testsuite"
    assert root.attrib["failures"] == "1"

    assert main(["-t", str(t), "--asset-report", "--format", "junit"]) == 2
    assert "junit" in capsys.readouterr().err
