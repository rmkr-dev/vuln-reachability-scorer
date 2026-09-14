"""Load topology and findings JSON documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vuln_reachability_scorer.models import Asset, Edge, Finding
from vuln_reachability_scorer.scoring import DEFAULT_TAG_BOOSTS


def _read_json(path: Path, kind: str) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"{kind} file not found: {path}")
    if path.is_dir():
        raise ValueError(f"{kind} path is a directory, expected a JSON file: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{kind} is not valid UTF-8 ({path}): {exc.reason}") from exc
    if not text.strip():
        raise ValueError(f"{kind} file is empty: {path}")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{kind} is not valid JSON ({path}): {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno})"
        ) from exc


def load_topology(path: Path) -> tuple[list[Asset], list[Edge]]:
    raw = _read_json(path, "topology")
    if not isinstance(raw, dict):
        raise ValueError(
            f"topology root must be an object, got {type(raw).__name__}: {path}"
        )
    assets_raw = raw.get("assets")
    edges_raw = raw.get("edges")
    if not isinstance(assets_raw, list):
        raise ValueError(f"topology.assets must be a list: {path}")
    if not isinstance(edges_raw, list):
        raise ValueError(f"topology.edges must be a list: {path}")
    assets: list[Asset] = []
    for i, item in enumerate(assets_raw):
        try:
            assets.append(Asset.from_dict(item))
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"topology.assets[{i}]: {exc}") from exc
    ids = [a.id for a in assets]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate asset id(s): {', '.join(dupes)}")
    edges: list[Edge] = []
    for i, item in enumerate(edges_raw):
        try:
            edges.append(Edge.from_dict(item))
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"topology.edges[{i}]: {exc}") from exc
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
    raw = _read_json(path, "findings")
    if isinstance(raw, dict):
        items = raw.get("findings")
        if not isinstance(items, list):
            raise ValueError(f"findings object must contain a findings list: {path}")
    elif isinstance(raw, list):
        items = raw
    else:
        raise ValueError(
            f"findings root must be an object or list, got {type(raw).__name__}: {path}"
        )
    findings: list[Finding] = []
    for i, item in enumerate(items):
        try:
            findings.append(Finding.from_dict(item))
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"findings[{i}]: {exc}") from exc
    ids = [f.id for f in findings]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate finding id(s): {', '.join(dupes)}")
    return findings


def load_tag_boosts(path: Path) -> dict[str, float]:
    """Merge topology ``tag_boosts`` over :data:`DEFAULT_TAG_BOOSTS`."""
    raw = _read_json(path, "topology")
    boosts = dict(DEFAULT_TAG_BOOSTS)
    if isinstance(raw, dict):
        custom = raw.get("tag_boosts")
        if custom is None:
            return boosts
        if not isinstance(custom, dict):
            raise ValueError(f"topology.tag_boosts must be an object: {path}")
        for key, value in custom.items():
            try:
                boosts[str(key)] = float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"topology.tag_boosts[{key!r}] must be a number: {path}"
                ) from exc
    return boosts
