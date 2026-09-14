from vuln_reachability_scorer.models import Asset, Edge
from vuln_reachability_scorer.paths import shortest_path
from vuln_reachability_scorer.scoring import KEV_FACTOR, score_findings
from vuln_reachability_scorer.models import Finding


def test_shortest_path_with_cycle():
    assets = [
        Asset(id="i", name="I", ingress=True),
        Asset(id="a", name="A"),
        Asset(id="b", name="B"),
    ]
    edges = [
        Edge(source="i", target="a"),
        Edge(source="a", target="b"),
        Edge(source="b", target="a"),
    ]
    assert shortest_path("b", assets, edges) == ["i", "a", "b"]


def test_kev_clamp_at_ten():
    assets = [Asset(id="a", name="A", criticality=1.0, ingress=True)]
    finding = Finding(id="f", asset_id="a", cve_id="CVE-1", base_score=10.0, kev=True)
    scored = score_findings([finding], assets, [])[0]
    assert scored.priority_score == 10.0
    assert KEV_FACTOR > 1.0
