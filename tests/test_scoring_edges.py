from vuln_reachability_scorer.models import Asset, Edge, Finding
from vuln_reachability_scorer.scoring import score_findings


def test_empty_findings():
    assert score_findings([], [], []) == []


def test_self_loop_ingress():
    assets = [Asset(id="solo", name="Solo", criticality=0.5, ingress=True)]
    edges = [Edge(source="solo", target="solo")]
    findings = [Finding(id="f", asset_id="solo", cve_id="CVE-1", base_score=5.0)]
    scored = score_findings(findings, assets, edges)
    assert scored[0].hop_distance == 0
    assert scored[0].priority_score == 2.5


def test_tie_break_by_finding_id():
    assets = [
        Asset(id="a", name="A", criticality=1.0, ingress=True),
    ]
    findings = [
        Finding(id="b-find", asset_id="a", cve_id="CVE-B", base_score=5.0),
        Finding(id="a-find", asset_id="a", cve_id="CVE-A", base_score=5.0),
    ]
    scored = score_findings(findings, assets, [])
    assert [s.finding.id for s in scored] == ["a-find", "b-find"]
