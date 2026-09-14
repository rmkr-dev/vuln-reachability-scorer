"""Load topology and findings JSON documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vuln_reachability_scorer.models import Asset, Edge, Finding


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
    edges = [Edge.from_dict(e) for e in edges_raw]
    return assets, edges


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
    return [Finding.from_dict(f) for f in items]
