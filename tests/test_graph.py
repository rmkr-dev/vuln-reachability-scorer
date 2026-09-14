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


def test_all_hop_distances_matches_single_lookups():
    from vuln_reachability_scorer.graph import all_hop_distances

    assets = [
        Asset(id="i", name="I", ingress=True),
        Asset(id="x", name="X"),
        Asset(id="y", name="Y"),
        Asset(id="z", name="Z"),
        Asset(id="orphan", name="O"),
    ]
    edges = [
        Edge(source="i", target="x"),
        Edge(source="x", target="y"),
        Edge(source="y", target="z"),
    ]
    adj = build_adjacency(edges)
    ingress = ingress_asset_ids(assets, edges)
    all_d = all_hop_distances(adj, ingress)
    assert all_d == {"i": 0, "x": 1, "y": 2, "z": 3}
    for aid in ("i", "x", "y", "z", "orphan"):
        assert all_d.get(aid) == hop_distance(aid, adj, ingress)


def test_all_hop_distances_empty_ingress():
    from vuln_reachability_scorer.graph import all_hop_distances

    adj = build_adjacency([Edge(source="a", target="b")])
    assert all_hop_distances(adj, set()) == {}


def test_duplicate_parallel_edges_collapsed():
    edges = [
        Edge(source="i", target="x"),
        Edge(source="i", target="x"),
        Edge(source="i", target="x"),
    ]
    adj = build_adjacency(edges)
    assert adj["i"] == ["x"]
