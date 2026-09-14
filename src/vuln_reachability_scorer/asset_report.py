"""Per-asset reachability inventory (no findings required)."""

from __future__ import annotations

from dataclasses import dataclass

from vuln_reachability_scorer.graph import build_adjacency, all_hop_distances, ingress_asset_ids
from vuln_reachability_scorer.models import Asset, Edge
from vuln_reachability_scorer.scoring import exposure_factor, reachability_factor


@dataclass(frozen=True, slots=True)
class AssetReachability:
    asset: Asset
    hop_distance: int | None
    reachability_factor: float
    exposure_factor: float

    def as_dict(self) -> dict:
        return {
            "asset_id": self.asset.id,
            "name": self.asset.name,
            "kind": self.asset.kind,
            "criticality": self.asset.criticality,
            "ingress": self.asset.ingress,
            "hop_distance": self.hop_distance,
            "reachability_factor": self.reachability_factor,
            "exposure_factor": self.exposure_factor,
            "tags": list(self.asset.tags),
        }


def report_assets(
    assets: list[Asset],
    edges: list[Edge],
    tag_boosts: dict[str, float] | None = None,
) -> list[AssetReachability]:
    adj = build_adjacency(edges)
    ingress = ingress_asset_ids(assets, edges)
    distances = all_hop_distances(adj, ingress)
    rows: list[AssetReachability] = []
    for asset in assets:
        dist = distances.get(asset.id)
        rows.append(
            AssetReachability(
                asset=asset,
                hop_distance=dist,
                reachability_factor=reachability_factor(dist),
                exposure_factor=exposure_factor(asset, tag_boosts),
            )
        )
    rows.sort(
        key=lambda r: (
            -(r.reachability_factor * r.exposure_factor),
            r.asset.id,
        )
    )
    return rows
