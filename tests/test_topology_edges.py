"""Graph/path/scoring edge cases that real topologies hit."""

from vuln_reachability_scorer.graph import build_adjacency, hop_distance, ingress_asset_ids
from vuln_reachability_scorer.models import Asset, Edge, Finding
from vuln_reachability_scorer.paths import shortest_path
from vuln_reachability_scorer.scoring import reachability_factor, score_findings


def _assets(*ids: str, ingress: str | None = None) -> list[Asset]:
    return [
        Asset(id=i, name=i, ingress=(i == ingress), criticality=0.5) for i in ids
    ]


def test_self_loop_on_ingress_stays_zero_hops():
    assets = _assets("a", ingress="a")
    edges = [Edge(source="a", target="a")]
    adj = build_adjacency(edges)
    ingress = ingress_asset_ids(assets, edges)
    assert hop_distance("a", adj, ingress) == 0
    assert shortest_path("a", assets, edges) == ["a"]


def test_self_loop_does_not_reach_isolated_peer():
    assets = _assets("a", "b", ingress="a")
    edges = [Edge(source="b", target="b")]
    assert hop_distance("b", build_adjacency(edges), ingress_asset_ids(assets, edges)) is None
    assert shortest_path("b", assets, edges) is None


def test_uneven_diamond_takes_shortest_leg():
    assets = _assets("i", "a", "b", "c", "t", ingress="i")
    edges = [
        Edge(source="i", target="a"),
        Edge(source="a", target="t"),
        Edge(source="i", target="b"),
        Edge(source="b", target="c"),
        Edge(source="c", target="t"),
    ]
    adj = build_adjacency(edges)
    ingress = ingress_asset_ids(assets, edges)
    assert hop_distance("t", adj, ingress) == 2
    assert shortest_path("t", assets, edges) == ["i", "a", "t"]


def test_closest_of_multiple_ingress_wins():
    assets = [
        Asset(id="i1", name="i1", ingress=True, criticality=0.5),
        Asset(id="i2", name="i2", ingress=True, criticality=0.5),
        Asset(id="mid", name="mid", criticality=0.5),
        Asset(id="t", name="t", criticality=0.5),
    ]
    edges = [
        Edge(source="i1", target="mid"),
        Edge(source="mid", target="t"),
        Edge(source="i2", target="t"),
    ]
    assert hop_distance("t", build_adjacency(edges), ingress_asset_ids(assets, edges)) == 1
    assert shortest_path("t", assets, edges) == ["i2", "t"]


def test_reverse_only_edge_does_not_reach_from_ingress():
    assets = _assets("i", "t", ingress="i")
    edges = [Edge(source="t", target="i")]
    assert hop_distance("t", build_adjacency(edges), ingress_asset_ids(assets, edges)) is None
    assert shortest_path("t", assets, edges) is None


def test_duplicate_parallel_edges_do_not_inflate_hops():
    assets = _assets("i", "t", ingress="i")
    edges = [
        Edge(source="i", target="t"),
        Edge(source="i", target="t"),
        Edge(source="i", target="t"),
    ]
    assert hop_distance("t", build_adjacency(edges), {"i"}) == 1
    assert shortest_path("t", assets, edges) == ["i", "t"]


def test_empty_topology_is_unreachable():
    assert hop_distance("x", {}, set()) is None
    assert shortest_path("x", [], []) is None
    scored = score_findings(
        [Finding(id="f", asset_id="x", cve_id="CVE-1", base_score=5.0)],
        [],
        [],
    )
    assert scored[0].hop_distance is None
    assert scored[0].reachability_factor == 0.1


def test_five_hop_chain_uses_deep_factor():
    ids = ["i", "a", "b", "c", "d", "e"]
    assets = _assets(*ids, ingress="i")
    edges = [
        Edge(source=ids[n], target=ids[n + 1]) for n in range(len(ids) - 1)
    ]
    dist = hop_distance("e", build_adjacency(edges), {"i"})
    assert dist == 5
    assert reachability_factor(dist) == 0.20
    assert shortest_path("e", assets, edges) == ids


def test_internet_facing_unknown_source_marks_target_ingress():
    assets = _assets("lb", "app")
    edges = [
        Edge(source="internet", target="lb", internet_facing=True),
        Edge(source="lb", target="app"),
    ]
    ingress = ingress_asset_ids(assets, edges)
    assert ingress == {"lb"}
    assert hop_distance("app", build_adjacency(edges), ingress) == 1


def test_disconnected_component_stays_unreachable():
    assets = _assets("i", "a", "island", ingress="i")
    edges = [
        Edge(source="i", target="a"),
        Edge(source="island", target="island"),
    ]
    ingress = ingress_asset_ids(assets, edges)
    adj = build_adjacency(edges)
    assert hop_distance("a", adj, ingress) == 1
    assert hop_distance("island", adj, ingress) is None


def test_bidirectional_edge_reaches_both_ways():
    assets = _assets("i", "peer", ingress="i")
    edges = [
        Edge(source="i", target="peer"),
        Edge(source="peer", target="i"),
    ]
    assert hop_distance("peer", build_adjacency(edges), {"i"}) == 1
    assert shortest_path("peer", assets, edges) == ["i", "peer"]


def test_all_assets_ingress_are_zero_hops():
    assets = [
        Asset(id="a", name="a", ingress=True, criticality=0.5),
        Asset(id="b", name="b", ingress=True, criticality=0.5),
    ]
    edges = [Edge(source="a", target="b")]
    ingress = ingress_asset_ids(assets, edges)
    adj = build_adjacency(edges)
    assert hop_distance("a", adj, ingress) == 0
    assert hop_distance("b", adj, ingress) == 0
