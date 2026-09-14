"""Human-readable explanations for scored findings."""

from __future__ import annotations

from vuln_reachability_scorer.models import ScoredFinding


def explain_score(item: ScoredFinding, path_text: str | None = None) -> str:
    hops = item.hop_distance
    if hops is None:
        hop_txt = "unreachable from ingress (R=0.10)"
    elif hops == 0:
        hop_txt = "asset is ingress (R=1.00)"
    else:
        hop_txt = f"{hops} hop(s) from ingress (R={item.reachability_factor:.2f})"
    text = (
        f"priority {item.priority_score:.2f} = "
        f"base {item.finding.base_score:.1f} × R {item.reachability_factor:.2f} × "
        f"E {item.exposure_factor:.2f}; {hop_txt}"
    )
    if item.finding.kev:
        text += "; KEV multiplier applied"
    if item.finding.epss is not None:
        text += f"; EPSS {item.finding.epss:.2f} applied"
    if path_text:
        text += f"; path {path_text}"
    return text
