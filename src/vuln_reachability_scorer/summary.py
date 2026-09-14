"""Aggregate summary stats for scored findings."""

from __future__ import annotations

from vuln_reachability_scorer.models import ScoredFinding


def summarize(scored: list[ScoredFinding]) -> dict:
    """Return counts and score bands for a scored result set."""
    bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    kev_count = 0
    for item in scored:
        p = item.priority_score
        if p >= 9.0:
            bands["critical"] += 1
        elif p >= 7.0:
            bands["high"] += 1
        elif p >= 4.0:
            bands["medium"] += 1
        else:
            bands["low"] += 1
        if item.finding.kev:
            kev_count += 1
    top = scored[0].priority_score if scored else 0.0
    return {
        "count": len(scored),
        "kev_count": kev_count,
        "max_priority": top,
        "bands": bands,
    }


def format_summary_line(stats: dict) -> str:
    b = stats["bands"]
    return (
        f"summary: n={stats['count']} max={stats['max_priority']:.2f} "
        f"kev={stats['kev_count']} "
        f"bands[crit={b['critical']} high={b['high']} med={b['medium']} low={b['low']}]"
    )
