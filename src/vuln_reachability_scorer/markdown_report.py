"""GitHub-flavored Markdown report for scored findings."""

from __future__ import annotations

from vuln_reachability_scorer import __version__
from vuln_reachability_scorer.explain import explain_score
from vuln_reachability_scorer.models import ScoredFinding
from vuln_reachability_scorer.paths import format_path


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def to_markdown(
    scored: list[ScoredFinding],
    *,
    explain: bool = False,
    path_by_asset: dict | None = None,
) -> str:
    lines = [
        f"# vuln-reachability-scorer {__version__}",
        "",
        f"{len(scored)} finding(s). Formula: `priority = base × R × E` "
        "(KEV/EPSS multipliers after, clamp 10).",
        "",
        "| PRIORITY | BASE | R | E | HOPS | CVE | ASSET | ID | TITLE | KEV | EPSS |",
        "| ---: | ---: | ---: | ---: | ---: | --- | --- | --- | --- | --- | ---: |",
    ]
    if not scored:
        lines.append("|  |  |  |  |  |  |  |  | _No findings to report._ |  |  |")
        lines.append("")
        return "\n".join(lines)
    for item in scored:
        hops = "-" if item.hop_distance is None else str(item.hop_distance)
        epss = "-" if item.finding.epss is None else f"{item.finding.epss:.3f}"
        kev = "yes" if item.finding.kev else "no"
        lines.append(
            "| "
            + " | ".join(
                [
                    f"{item.priority_score:.2f}",
                    f"{item.finding.base_score:.1f}",
                    f"{item.reachability_factor:.2f}",
                    f"{item.exposure_factor:.2f}",
                    hops,
                    _cell(item.finding.cve_id or "-"),
                    _cell(item.finding.asset_id),
                    _cell(item.finding.id),
                    _cell(item.finding.title or "-"),
                    kev,
                    epss,
                ]
            )
            + " |"
        )
        if explain:
            path_txt = None
            if path_by_asset is not None:
                path_txt = format_path(path_by_asset.get(item.finding.asset_id))
            lines.append(f"|  |  |  |  |  |  |  |  | {_cell(explain_score(item, path_txt))} |  |  |")
    lines.append("")
    return "\n".join(lines)


def to_asset_markdown(rows: list) -> str:
    lines = [
        f"# Asset reachability inventory ({__version__})",
        "",
        f"{len(rows)} asset(s).",
        "",
        "| ASSET | KIND | HOPS | R | E | CRIT | INGRESS | NAME | TAGS |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |",
    ]
    if not rows:
        lines.append("|  |  |  |  |  |  |  | _No assets in topology._ |  |")
        lines.append("")
        return "\n".join(lines)
    for r in rows:
        hops = "-" if r.hop_distance is None else str(r.hop_distance)
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(r.asset.id),
                    _cell(r.asset.kind),
                    hops,
                    f"{r.reachability_factor:.2f}",
                    f"{r.exposure_factor:.2f}",
                    f"{r.asset.criticality:.2f}",
                    "yes" if r.asset.ingress else "no",
                    _cell(r.asset.name),
                    _cell(", ".join(r.asset.tags)),
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)
