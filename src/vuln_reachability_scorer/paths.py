"""Shortest-path reconstruction from ingress to an asset."""

from __future__ import annotations

from collections import deque

from vuln_reachability_scorer.graph import build_adjacency, ingress_asset_ids
from vuln_reachability_scorer.models import Asset, Edge


def shortest_path(
    asset_id: str,
    assets: list[Asset],
    edges: list[Edge],
) -> list[str] | None:
    """Return one shortest ingress→asset node id path, or None if unreachable."""
    ingress = ingress_asset_ids(assets, edges)
    if asset_id in ingress:
        return [asset_id]
    if not ingress:
        return None

    adj = build_adjacency(edges)
    parent: dict[str, str | None] = {i: None for i in ingress}
    queue: deque[str] = deque(ingress)
    seen = set(ingress)
    found = False
    while queue:
        node = queue.popleft()
        for nxt in adj.get(node, []):
            if nxt in seen:
                continue
            parent[nxt] = node
            if nxt == asset_id:
                found = True
                queue.clear()
                break
            seen.add(nxt)
            queue.append(nxt)
    if not found:
        return None

    path = [asset_id]
    cur = asset_id
    while parent.get(cur) is not None:
        cur = parent[cur]  # type: ignore[assignment]
        path.append(cur)
    path.reverse()
    return path



def all_shortest_paths(
    assets: list[Asset],
    edges: list[Edge],
) -> dict[str, list[str]]:
    """Map each reachable asset id to one shortest ingress→asset path.

    One multi-source BFS; unreachable assets are omitted. Ingress nodes map
    to a single-element path ``[asset_id]``.
    """
    ingress = ingress_asset_ids(assets, edges)
    if not ingress:
        return {}
    adj = build_adjacency(edges)
    parent: dict[str, str | None] = {i: None for i in ingress}
    queue: deque[str] = deque(ingress)
    seen = set(ingress)
    while queue:
        node = queue.popleft()
        for nxt in adj.get(node, []):
            if nxt in seen:
                continue
            parent[nxt] = node
            seen.add(nxt)
            queue.append(nxt)

    paths: dict[str, list[str]] = {}
    for asset_id in parent:
        path = [asset_id]
        cur = asset_id
        while parent.get(cur) is not None:
            cur = parent[cur]  # type: ignore[assignment]
            path.append(cur)
        path.reverse()
        paths[asset_id] = path
    return paths


def format_path(path: list[str] | None) -> str:
    if path is None:
        return "(unreachable)"
    return " -> ".join(path)
