"""Topology graph helpers: adjacency and hop distance from ingress."""

from __future__ import annotations

from collections import defaultdict, deque

from vuln_reachability_scorer.models import Asset, Edge


def build_adjacency(edges: list[Edge]) -> dict[str, list[str]]:
    """Build directed adjacency; parallel duplicate edges collapse to one neighbor."""
    adj: dict[str, list[str]] = defaultdict(list)
    seen_pair: set[tuple[str, str]] = set()
    for edge in edges:
        pair = (edge.source, edge.target)
        if pair in seen_pair:
            continue
        seen_pair.add(pair)
        adj[edge.source].append(edge.target)
    return dict(adj)


def ingress_asset_ids(assets: list[Asset], edges: list[Edge]) -> set[str]:
    """Assets that are attack entry points.

    An asset is ingress if it is marked ``ingress=True``, or if any inbound
    edge is ``internet_facing=True`` (traffic arrives from outside the modeled
    topology onto that target).
    """
    ids = {a.id for a in assets if a.ingress}
    for edge in edges:
        if edge.internet_facing:
            ids.add(edge.target)
    return ids


def hop_distance(
    asset_id: str,
    adjacency: dict[str, list[str]],
    ingress_ids: set[str],
) -> int | None:
    """Shortest hop count from any ingress asset to ``asset_id``.

    Returns 0 if the asset itself is ingress, None if unreachable from all
    ingress nodes (including when there are no ingress nodes).
    """
    if asset_id in ingress_ids:
        return 0
    if not ingress_ids:
        return None

    # BFS outward from all ingress nodes along directed edges.
    queue: deque[tuple[str, int]] = deque((i, 0) for i in ingress_ids)
    seen: set[str] = set(ingress_ids)
    while queue:
        node, dist = queue.popleft()
        for nxt in adjacency.get(node, []):
            if nxt in seen:
                continue
            if nxt == asset_id:
                return dist + 1
            seen.add(nxt)
            queue.append((nxt, dist + 1))
    return None


def all_hop_distances(
    adjacency: dict[str, list[str]],
    ingress_ids: set[str],
) -> dict[str, int]:
    """Map every reachable asset id to its shortest hop distance from ingress.

    Runs one multi-source BFS. Assets absent from the result are unreachable
    (or there were no ingress nodes). Ingress nodes themselves map to ``0``.
    """
    if not ingress_ids:
        return {}
    distances: dict[str, int] = {i: 0 for i in ingress_ids}
    queue: deque[str] = deque(ingress_ids)
    while queue:
        node = queue.popleft()
        dist = distances[node]
        for nxt in adjacency.get(node, []):
            if nxt in distances:
                continue
            distances[nxt] = dist + 1
            queue.append(nxt)
    return distances

