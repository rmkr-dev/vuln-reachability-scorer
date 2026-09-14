from vuln_reachability_scorer.graph import build_adjacency, hop_distance, ingress_asset_ids
from vuln_reachability_scorer.models import Asset, Edge


def test_ingress_from_asset_flag_and_internet_facing_edge():
    assets = [
        Asset(id="a", name="A", ingress=True),
        Asset(id="b", name="B"),
        Asset(id="c", name="C"),
    ]
    edges = [
        Edge(source="ext", target="b", internet_facing=True),
        Edge(source="a", target="c"),
    ]
    ingress = ingress_asset_ids(assets, edges)
    assert ingress == {"a", "b"}


def test_hop_distance_bfs():
    adj = build_adjacency(
        [
            Edge(source="i", target="x"),
            Edge(source="x", target="y"),
            Edge(source="y", target="z"),
        ]
    )
    assert hop_distance("i", adj, {"i"}) == 0
    assert hop_distance("x", adj, {"i"}) == 1
    assert hop_distance("z", adj, {"i"}) == 3
    assert hop_distance("orphan", adj, {"i"}) is None
    assert hop_distance("x", adj, set()) is None


def test_cycle_does_not_loop_forever():
    adj = build_adjacency(
        [
            Edge(source="a", target="b"),
            Edge(source="b", target="a"),
            Edge(source="b", target="c"),
        ]
    )
    assert hop_distance("c", adj, {"a"}) == 2
