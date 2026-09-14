"""Load topology and findings JSON documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vuln_reachability_scorer.models import Asset, Edge, Finding
from vuln_reachability_scorer.scoring import DEFAULT_TAG_BOOSTS


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def load_topology(path: Path) -> tuple[list[Asset], list[Edge]]:
    raw = _read_json(path)
    if not isinstance(raw, dict):
        raise ValueError(f"topology root must be an object: {path}")
    assets_raw = raw.get("assets")
    edges_raw = raw.get("edges")
    if not isinstance(assets_raw, list):
        raise ValueError("topology.assets must be a list")
    if not isinstance(edges_raw, list):
        raise ValueError("topology.edges must be a list")
    assets = [Asset.from_dict(a) for a in assets_raw]
    ids = [a.id for a in assets]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate asset id(s): {', '.join(dupes)}")
    edges = [Edge.from_dict(e) for e in edges_raw]
    return assets, edges


def unknown_edge_endpoints(assets: list[Asset], edges: list[Edge]) -> list[str]:
    """Return warning strings for edges that reference missing asset ids."""
    known = {a.id for a in assets}
    warnings: list[str] = []
    for edge in edges:
        missing = [n for n in (edge.source, edge.target) if n not in known]
        if missing:
            warnings.append(
                f"edge {edge.source}->{edge.target} references unknown "
                f"asset id(s): {', '.join(missing)}"
            )
    return warnings


def load_findings(path: Path) -> list[Finding]:
    raw = _read_json(path)
    if isinstance(raw, dict):
        items = raw.get("findings")
        if not isinstance(items, list):
            raise ValueError("findings object must contain a findings list")
    elif isinstance(raw, list):
        items = raw
    else:
        raise ValueError(f"findings root must be an object or list: {path}")
    findings = [Finding.from_dict(f) for f in items]
    ids = [f.id for f in findings]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate finding id(s): {', '.join(dupes)}")
    return findings


def load_tag_boosts(path: Path) -> dict[str, float]:
    """Merge topology ``tag_boosts`` over :data:`DEFAULT_TAG_BOOSTS`."""
    raw = _read_json(path)
    boosts = dict(DEFAULT_TAG_BOOSTS)
    if isinstance(raw, dict):
        custom = raw.get("tag_boosts")
        if custom is None:
            return boosts
        if not isinstance(custom, dict):
            raise ValueError("topology.tag_boosts must be an object")
        for key, value in custom.items():
            boosts[str(key)] = float(value)
    return boosts
