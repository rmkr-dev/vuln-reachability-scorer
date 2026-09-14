"""Domain models for topology and vulnerability findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Asset:
    """A node in the topology graph (host, service, datastore, …)."""

    id: str
    name: str
    kind: str = "host"
    criticality: float = 0.5
    tags: tuple[str, ...] = ()
    ingress: bool = False

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("asset id must be non-empty")
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError(f"criticality must be in [0, 1], got {self.criticality}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Asset:
        tags = data.get("tags") or []
        return cls(
            id=str(data["id"]),
            name=str(data.get("name") or data["id"]),
            kind=str(data.get("kind") or "host"),
            criticality=float(data.get("criticality", 0.5)),
            tags=tuple(str(t) for t in tags),
            ingress=bool(data.get("ingress", False)),
        )


@dataclass(frozen=True, slots=True)
class Edge:
    """Directed reachability from source asset to target asset."""

    source: str
    target: str
    protocol: str = "network"
    internet_facing: bool = False

    def __post_init__(self) -> None:
        if not self.source or not self.target:
            raise ValueError("edge source and target must be non-empty")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Edge:
        return cls(
            source=str(data["source"]),
            target=str(data["target"]),
            protocol=str(data.get("protocol") or "network"),
            internet_facing=bool(data.get("internet_facing", False)),
        )


@dataclass(frozen=True, slots=True)
class Finding:
    """A vulnerability finding bound to an asset, with a numeric base score."""

    id: str
    asset_id: str
    cve_id: str
    base_score: float
    title: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("finding id must be non-empty")
        if not self.asset_id:
            raise ValueError("finding asset_id must be non-empty")
        if not 0.0 <= self.base_score <= 10.0:
            raise ValueError(f"base_score must be in [0, 10], got {self.base_score}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=str(data["id"]),
            asset_id=str(data["asset_id"]),
            cve_id=str(data.get("cve_id") or data.get("cve") or ""),
            base_score=float(data["base_score"]),
            title=str(data.get("title") or ""),
        )


@dataclass(frozen=True, slots=True)
class ScoredFinding:
    """A finding after reachability/exposure scoring."""

    finding: Finding
    reachability_factor: float
    exposure_factor: float
    priority_score: float
    hop_distance: int | None
    notes: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding.id,
            "cve_id": self.finding.cve_id,
            "asset_id": self.finding.asset_id,
            "title": self.finding.title,
            "base_score": self.finding.base_score,
            "reachability_factor": self.reachability_factor,
            "exposure_factor": self.exposure_factor,
            "priority_score": self.priority_score,
            "hop_distance": self.hop_distance,
            "notes": list(self.notes),
        }
