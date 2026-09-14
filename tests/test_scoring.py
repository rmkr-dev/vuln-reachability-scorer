from vuln_reachability_scorer.models import Asset, Edge, Finding
from vuln_reachability_scorer.scoring import (
    compute_priority,
    reachability_factor,
    score_findings,
)


def test_reachability_factor_table():
    assert reachability_factor(0) == 1.0
    assert reachability_factor(1) == 0.8
    assert reachability_factor(2) == 0.55
    assert reachability_factor(3) == 0.35
    assert reachability_factor(4) == 0.2
    assert reachability_factor(None) == 0.1


def test_compute_priority():
    # 9.8 * 1.0 * 0.9 = 8.82
    assert compute_priority(9.8, 1.0, 0.9) == 8.82


def _sample_topology():
    assets = [
        Asset(id="lb", name="Load balancer", criticality=0.6, ingress=True),
        Asset(id="app", name="App", criticality=0.8),
        Asset(id="db", name="Database", criticality=1.0),
        Asset(id="batch", name="Batch worker", criticality=0.4),
    ]
    edges = [
        Edge(source="lb", target="app"),
        Edge(source="app", target="db"),
        # batch is isolated — no path from ingress
    ]
    return assets, edges


def test_score_orders_by_reachability():
    assets, edges = _sample_topology()
    findings = [
        Finding(id="f-db", asset_id="db", cve_id="CVE-2024-0001", base_score=9.8),
        Finding(id="f-lb", asset_id="lb", cve_id="CVE-2024-0002", base_score=9.8),
        Finding(id="f-batch", asset_id="batch", cve_id="CVE-2024-0003", base_score=9.8),
    ]
    scored = score_findings(findings, assets, edges)
    by_id = {s.finding.id: s for s in scored}

    assert by_id["f-lb"].hop_distance == 0
    assert by_id["f-lb"].reachability_factor == 1.0
    assert by_id["f-db"].hop_distance == 2
    assert by_id["f-db"].reachability_factor == 0.55
    assert by_id["f-batch"].hop_distance is None
    assert by_id["f-batch"].reachability_factor == 0.1

    # Same base; ingress + high exposure should rank above deep/unreachable
    assert scored[0].finding.id == "f-lb"
    assert by_id["f-lb"].priority_score > by_id["f-db"].priority_score
    assert by_id["f-db"].priority_score > by_id["f-batch"].priority_score


def test_unknown_asset_uses_defaults():
    findings = [Finding(id="f1", asset_id="missing", cve_id="CVE-X", base_score=5.0)]
    scored = score_findings(findings, [], [])
    assert scored[0].reachability_factor == 0.1
    assert scored[0].exposure_factor == 0.5
    assert scored[0].priority_score == 0.25
    assert any("unknown asset" in n for n in scored[0].notes)
