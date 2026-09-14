"""Reachability-aware priority scoring.

Formula
-------
``priority_score = round(base_score * reachability_factor * exposure_factor, 2)``

All factors are in ``[0, 1]`` except ``base_score`` which is in ``[0, 10]``
(CVSS-like). The product therefore stays in ``[0, 10]``.

Reachability factor
-------------------
Derived from shortest hop distance from an ingress / internet-facing entry:

| Hop distance | Factor |
| --- | --- |
| 0 (asset is ingress / internet-facing) | 1.00 |
| 1 | 0.80 |
| 2 | 0.55 |
| 3 | 0.35 |
| 4+ | 0.20 |
| unreachable / no ingress in topology | 0.10 |

Exposure factor
---------------
``exposure_factor = clamp(asset.criticality + sum(tag_boosts), 0, 1)``

Default tag boosts (overridable via topology ``tag_boosts`` object):

| Tag | Boost |
| --- | --- |
| pii | 0.15 |
| identity | 0.20 |
| secrets | 0.20 |

Asset criticality is supplied in the topology (0 = negligible, 1 = crown jewel).
"""

from __future__ import annotations

from vuln_reachability_scorer.graph import build_adjacency, hop_distance, ingress_asset_ids
from vuln_reachability_scorer.models import Asset, Edge, Finding, ScoredFinding

_REACHABILITY_BY_HOPS: dict[int, float] = {
    0: 1.00,
    1: 0.80,
    2: 0.55,
    3: 0.35,
}

_UNREACHABLE_FACTOR = 0.10
_DEEP_FACTOR = 0.20  # 4+ hops

DEFAULT_TAG_BOOSTS: dict[str, float] = {
    "pii": 0.15,
    "identity": 0.20,
    "secrets": 0.20,
}


def reachability_factor(distance: int | None) -> float:
    if distance is None:
        return _UNREACHABLE_FACTOR
    if distance in _REACHABILITY_BY_HOPS:
        return _REACHABILITY_BY_HOPS[distance]
    if distance < 0:
        raise ValueError(f"distance must be >= 0, got {distance}")
    return _DEEP_FACTOR


def exposure_factor(
    asset: Asset | None,
    tag_boosts: dict[str, float] | None = None,
) -> float:
    if asset is None:
        return 0.5
    boosts = DEFAULT_TAG_BOOSTS if tag_boosts is None else tag_boosts
    bonus = 0.0
    for tag in asset.tags:
        bonus += float(boosts.get(tag, 0.0))
    return max(0.0, min(1.0, asset.criticality + bonus))


def compute_priority(base_score: float, r_factor: float, e_factor: float) -> float:
    return round(base_score * r_factor * e_factor, 2)


def score_findings(
    findings: list[Finding],
    assets: list[Asset],
    edges: list[Edge],
    tag_boosts: dict[str, float] | None = None,
) -> list[ScoredFinding]:
    """Score each finding and return results sorted by priority descending."""
    by_id = {a.id: a for a in assets}
    adj = build_adjacency(edges)
    ingress = ingress_asset_ids(assets, edges)
    boosts = DEFAULT_TAG_BOOSTS if tag_boosts is None else tag_boosts

    scored: list[ScoredFinding] = []
    for finding in findings:
        asset = by_id.get(finding.asset_id)
        notes: list[str] = []
        if asset is None:
            notes.append(f"unknown asset_id={finding.asset_id}; using default exposure 0.5")
            dist = None
            r = reachability_factor(None)
            e = exposure_factor(None)
        else:
            dist = hop_distance(finding.asset_id, adj, ingress)
            r = reachability_factor(dist)
            e = exposure_factor(asset, boosts)
            applied = [t for t in asset.tags if t in boosts and boosts[t]]
            if applied:
                notes.append(f"tag boosts applied: {', '.join(applied)}")
            if dist is None:
                notes.append("asset not reachable from any ingress node")
            if not ingress:
                notes.append("topology has no ingress assets or internet_facing edges")

        priority = compute_priority(finding.base_score, r, e)
        scored.append(
            ScoredFinding(
                finding=finding,
                reachability_factor=r,
                exposure_factor=e,
                priority_score=priority,
                hop_distance=dist,
                notes=tuple(notes),
            )
        )

    scored.sort(key=lambda s: (-s.priority_score, s.finding.id))
    return scored
