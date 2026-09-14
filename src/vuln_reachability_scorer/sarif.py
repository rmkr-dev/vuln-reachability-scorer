"""Emit SARIF 2.1.0 for scored findings (static analysis results interchange)."""

from __future__ import annotations

from typing import Any

from vuln_reachability_scorer import __version__
from vuln_reachability_scorer.models import ScoredFinding

_TOOL_NAME = "vuln-reachability-scorer"
_TOOL_INFO_URI = "https://github.com/rmkr-dev/vuln-reachability-scorer"


def _level(priority: float) -> str:
    if priority >= 7.0:
        return "error"
    if priority >= 4.0:
        return "warning"
    return "note"


def to_sarif(scored: list[ScoredFinding]) -> dict[str, Any]:
    """Build a minimal SARIF 2.1.0 document from scored findings."""
    results = []
    for item in scored:
        f = item.finding
        message = (
            f"{f.cve_id or f.id}: priority {item.priority_score:.2f} "
            f"(base={f.base_score:.1f}, R={item.reachability_factor:.2f}, "
            f"E={item.exposure_factor:.2f}, hops={item.hop_distance})"
        )
        results.append(
            {
                "ruleId": f.cve_id or f.id,
                "level": _level(item.priority_score),
                "message": {"text": message},
                "properties": {
                    "priority_score": item.priority_score,
                    "base_score": f.base_score,
                    "reachability_factor": item.reachability_factor,
                    "exposure_factor": item.exposure_factor,
                    "hop_distance": item.hop_distance,
                    "asset_id": f.asset_id,
                    "finding_id": f.id,
                    "notes": list(item.notes),
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": __version__,
                        "informationUri": _TOOL_INFO_URI,
                        "rules": [],
                    }
                },
                "results": results,
            }
        ],
    }
