"""Performance guard: scoring large topologies stays near-linear in V+E."""

from __future__ import annotations

import time

from vuln_reachability_scorer.graph import all_hop_distances, build_adjacency, ingress_asset_ids
from vuln_reachability_scorer.models import Asset, Edge, Finding
from vuln_reachability_scorer.scoring import score_findings


def _chain_topology(n: int) -> tuple[list[Asset], list[Edge]]:
    assets = [Asset(id=f"n{i}", name=f"N{i}", ingress=(i == 0), criticality=0.5) for i in range(n)]
    edges = [Edge(source=f"n{i}", target=f"n{i+1}") for i in range(n - 1)]
    # sprinkle duplicate parallel edges (should not inflate work after dedupe)
    edges.extend([Edge(source=f"n{i}", target=f"n{i+1}") for i in range(0, n - 1, 17)])
    return assets, edges


def test_large_chain_all_hop_distances_fast():
    assets, edges = _chain_topology(4000)
    adj = build_adjacency(edges)
    ingress = ingress_asset_ids(assets, edges)
    t0 = time.perf_counter()
    distances = all_hop_distances(adj, ingress)
    elapsed = time.perf_counter() - t0
    assert distances["n0"] == 0
    assert distances["n3999"] == 3999
    assert elapsed < 1.5  # generous CI bound; typically << 0.2s


def test_large_score_findings_fast():
    assets, edges = _chain_topology(2000)
    findings = [
        Finding(id=f"f{i}", asset_id=f"n{i % 2000}", base_score=5.0 + (i % 5), cve_id=f"CVE-2024-{i:05d}")
        for i in range(8000)
    ]
    t0 = time.perf_counter()
    scored = score_findings(findings, assets, edges)
    elapsed = time.perf_counter() - t0
    assert len(scored) == 8000
    assert elapsed < 3.0
