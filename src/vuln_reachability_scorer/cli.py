"""CLI entrypoint: ``vrscore`` / ``vuln-reachability``."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from io import StringIO
from pathlib import Path

from vuln_reachability_scorer import __version__
from vuln_reachability_scorer.asset_report import report_assets
from vuln_reachability_scorer.explain import explain_score
from vuln_reachability_scorer.paths import format_path, shortest_path
from vuln_reachability_scorer.loaders import (
    load_findings,
    load_tag_boosts,
    load_topology,
    unknown_edge_endpoints,
)
from vuln_reachability_scorer.html_report import to_asset_html, to_html
from vuln_reachability_scorer.markdown_report import to_asset_markdown, to_markdown
from vuln_reachability_scorer.sarif import to_sarif
from vuln_reachability_scorer.scoring import score_findings
from vuln_reachability_scorer.summary import format_summary_line, summarize



_BAND_PREDICATES = {
    "critical": lambda p: p >= 9.0,
    "high": lambda p: 7.0 <= p < 9.0,
    "medium": lambda p: 4.0 <= p < 7.0,
    "low": lambda p: p < 4.0,
}


def _in_selected_bands(priority: float, bands: list[str]) -> bool:
    return any(_BAND_PREDICATES[b](priority) for b in bands)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vrscore",
        description=(
            "Score CVE findings by reachability and exposure using a topology graph. "
            "priority = base_score × reachability_factor × exposure_factor"
        ),
    )
    parser.add_argument(
        "--topology",
        "-t",
        type=Path,
        required=True,
        help="Path to topology JSON (assets + edges)",
    )
    parser.add_argument(
        "--findings",
        "-f",
        type=Path,
        help="Path to findings JSON (required unless --asset-report)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "jsonl", "sarif", "csv", "html", "markdown"),
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Write output to this file instead of stdout",
    )
    parser.add_argument(
        "--min-priority",
        type=float,
        default=0.0,
        help="Omit findings with priority_score below this threshold (default: 0)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Emit at most N results after sorting/filtering (0 = no limit)",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Include human-readable score explanations (table notes / JSON explain field)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat unknown edge endpoints as errors instead of warnings",
    )
    parser.add_argument(
        "--asset-report",
        action="store_true",
        help="Emit per-asset reachability inventory (findings not required)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print aggregate band counts to stderr after scoring",
    )
    parser.add_argument(
        "--fail-under",
        type=float,
        default=None,
        metavar="SCORE",
        help="Exit 1 if any result has priority_score >= SCORE (CI gate)",
    )
    parser.add_argument(
        "--show-title",
        action="store_true",
        help="Include finding title column in table output",
    )
    parser.add_argument(
        "--only-kev",
        action="store_true",
        help="Keep only findings marked kev=true after scoring",
    )
    parser.add_argument(
        "--only-reachable",
        action="store_true",
        help="Keep only findings on assets reachable from an ingress node",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=None,
        metavar="N",
        help="Keep only findings with hop_distance <= N (excludes unreachable)",
    )
    parser.add_argument(
        "--band",
        action="append",
        choices=("critical", "high", "medium", "low"),
        default=None,
        metavar="BAND",
        help=(
            "Keep findings in priority band(s): critical>=9, high>=7, medium>=4, low<4. "
            "Repeatable."
        ),
    )
    parser.add_argument(
        "--min-epss",
        type=float,
        default=None,
        metavar="P",
        help="Keep findings with epss >= P (findings without epss are dropped)",
    )
    parser.add_argument(
        "--asset",
        action="append",
        default=None,
        metavar="ID",
        help="Keep findings for this asset id only (repeatable)",
    )
    parser.add_argument(
        "--cve",
        action="append",
        default=None,
        metavar="CVE",
        help="Keep findings matching this CVE id (repeatable; case-insensitive)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress non-error stderr messages (edge warnings; --summary still prints)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _print_table(scored: list, sink, explain: bool = False, path_by_asset: dict | None = None, show_title: bool = False) -> None:
    headers_list = [
        "PRIORITY",
        "BASE",
        "R",
        "E",
        "HOPS",
        "CVE",
        "ASSET",
        "ID",
    ]
    if show_title:
        headers_list.append("TITLE")
    headers = tuple(headers_list)
    rows = []
    for s in scored:
        row = [
            f"{s.priority_score:.2f}",
            f"{s.finding.base_score:.1f}",
            f"{s.reachability_factor:.2f}",
            f"{s.exposure_factor:.2f}",
            "-" if s.hop_distance is None else str(s.hop_distance),
            s.finding.cve_id or "-",
            s.finding.asset_id,
            s.finding.id,
        ]
        if show_title:
            title = s.finding.title or "-"
            if len(title) > 40:
                title = title[:37] + "..."
            row.append(title)
        rows.append(tuple(row))
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(row: tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    print(fmt(headers), file=sink)
    print(fmt(tuple("-" * w for w in widths)), file=sink)
    for idx, row in enumerate(rows):
        print(fmt(row), file=sink)
        if explain:
            asset_id = scored[idx].finding.asset_id
            path_txt = None
            if path_by_asset is not None:
                path_txt = format_path(path_by_asset.get(asset_id))
            print(f"  # {explain_score(scored[idx], path_txt)}", file=sink)


def _render_csv(scored: list) -> str:
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "priority_score",
            "base_score",
            "reachability_factor",
            "exposure_factor",
            "hop_distance",
            "cve_id",
            "asset_id",
            "id",
            "title",
            "epss",
        ]
    )
    for s in scored:
        writer.writerow(
            [
                f"{s.priority_score:.2f}",
                f"{s.finding.base_score:.1f}",
                f"{s.reachability_factor:.2f}",
                f"{s.exposure_factor:.2f}",
                "" if s.hop_distance is None else s.hop_distance,
                s.finding.cve_id,
                s.finding.asset_id,
                s.finding.id,
                s.finding.title,
                "" if s.finding.epss is None else f"{s.finding.epss:.3f}",
            ]
        )
    return buf.getvalue()


def _render(scored: list, fmt: str, explain: bool = False, path_by_asset: dict | None = None) -> str:
    if fmt == "json":
        payload = {
            "version": __version__,
            "formula": "priority = base_score * reachability_factor * exposure_factor",
            "results": [
                {
                    **s.as_dict(),
                    **(
                        {
                            "explain": explain_score(
                                s,
                                format_path(path_by_asset.get(s.finding.asset_id))
                                if path_by_asset is not None
                                else None,
                            )
                        }
                        if explain
                        else {}
                    ),
                }
                for s in scored
            ],
        }
        return json.dumps(payload, indent=2) + "\n"
    if fmt == "jsonl":
        lines = []
        for s in scored:
            row = dict(s.as_dict())
            if explain:
                row["explain"] = explain_score(
                    s,
                    format_path(path_by_asset.get(s.finding.asset_id))
                    if path_by_asset is not None
                    else None,
                )
            lines.append(json.dumps(row, separators=(",", ":")))
        return ("\n".join(lines) + ("\n" if lines else ""))
    if fmt == "sarif":
        return json.dumps(to_sarif(scored), indent=2) + "\n"
    if fmt == "csv":
        return _render_csv(scored)
    if fmt == "html":
        return to_html(scored, explain=explain, path_by_asset=path_by_asset)
    if fmt == "markdown":
        return to_markdown(scored, explain=explain, path_by_asset=path_by_asset)
    return ""


def _print_asset_table(rows: list, sink) -> None:
    headers = ("ASSET", "KIND", "HOPS", "R", "E", "CRIT", "INGRESS", "NAME")
    table = [
        (
            r.asset.id,
            r.asset.kind,
            "-" if r.hop_distance is None else str(r.hop_distance),
            f"{r.reachability_factor:.2f}",
            f"{r.exposure_factor:.2f}",
            f"{r.asset.criticality:.2f}",
            "yes" if r.asset.ingress else "no",
            r.asset.name,
        )
        for r in rows
    ]
    widths = [len(h) for h in headers]
    for row in table:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(row: tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    print(fmt(headers), file=sink)
    print(fmt(tuple("-" * w for w in widths)), file=sink)
    for row in table:
        print(fmt(row), file=sink)



def _render_asset_csv(rows: list) -> str:
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "asset_id",
            "name",
            "kind",
            "hop_distance",
            "reachability_factor",
            "exposure_factor",
            "criticality",
            "ingress",
            "tags",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r.asset.id,
                r.asset.name,
                r.asset.kind,
                "" if r.hop_distance is None else r.hop_distance,
                f"{r.reachability_factor:.2f}",
                f"{r.exposure_factor:.2f}",
                f"{r.asset.criticality:.2f}",
                "yes" if r.asset.ingress else "no",
                "|".join(r.asset.tags),
            ]
        )
    return buf.getvalue()


def _emit_asset_report(assets, edges, args, tag_boosts=None) -> int:
    rows = report_assets(assets, edges, tag_boosts=tag_boosts)
    try:
        if args.format == "json":
            payload = {
                "version": __version__,
                "assets": [r.as_dict() for r in rows],
            }
            text = json.dumps(payload, indent=2) + "\n"
            if args.output is not None:
                args.output.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
        elif args.format == "jsonl":
            lines = [json.dumps(r.as_dict(), separators=(",", ":")) for r in rows]
            text = ("\n".join(lines) + ("\n" if lines else ""))
            if args.output is not None:
                args.output.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
        elif args.format == "csv":
            text = _render_asset_csv(rows)
            if args.output is not None:
                args.output.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
        elif args.format == "html":
            text = to_asset_html(rows)
            if args.output is not None:
                args.output.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
        elif args.format == "markdown":
            text = to_asset_markdown(rows)
            if args.output is not None:
                args.output.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
        elif args.format == "sarif":
            print(
                "error: --asset-report does not support --format sarif",
                file=sys.stderr,
            )
            return 2
        else:
            if args.output is not None:
                with args.output.open("w", encoding="utf-8") as fh:
                    _print_asset_table(rows, fh)
            else:
                _print_asset_table(rows, sys.stdout)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.asset_report and args.findings is None:
        parser.error("--findings is required unless --asset-report is set")

    if args.min_priority < 0:
        print("error: --min-priority must be >= 0", file=sys.stderr)
        return 2
    if args.limit < 0:
        print("error: --limit must be >= 0", file=sys.stderr)
        return 2
    if args.fail_under is not None and args.fail_under < 0:
        print("error: --fail-under must be >= 0", file=sys.stderr)
        return 2
    if args.max_hops is not None and args.max_hops < 0:
        print("error: --max-hops must be >= 0", file=sys.stderr)
        return 2
    if args.min_epss is not None and not (0.0 <= args.min_epss <= 1.0):
        print("error: --min-epss must be between 0 and 1", file=sys.stderr)
        return 2

    try:
        assets, edges = load_topology(args.topology)
        tag_boosts = load_tag_boosts(args.topology)
        findings = load_findings(args.findings) if args.findings is not None else []
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    edge_warnings = unknown_edge_endpoints(assets, edges)
    if edge_warnings:
        for msg in edge_warnings:
            label = "error" if args.strict else "warning"
            if args.strict or not args.quiet:
                print(f"{label}: {msg}", file=sys.stderr)
        if args.strict:
            return 2

    if args.asset_report:
        return _emit_asset_report(assets, edges, args, tag_boosts)

    scored = score_findings(findings, assets, edges, tag_boosts=tag_boosts)
    if args.only_kev:
        scored = [s for s in scored if s.finding.kev]
    if args.only_reachable:
        scored = [s for s in scored if s.hop_distance is not None]
    if args.max_hops is not None:
        scored = [
            s
            for s in scored
            if s.hop_distance is not None and s.hop_distance <= args.max_hops
        ]
    if args.band:
        scored = [s for s in scored if _in_selected_bands(s.priority_score, args.band)]
    if args.min_epss is not None:
        scored = [
            s
            for s in scored
            if s.finding.epss is not None and s.finding.epss >= args.min_epss
        ]
    if args.asset:
        wanted = set(args.asset)
        scored = [s for s in scored if s.finding.asset_id in wanted]
    if args.cve:
        wanted_cves = {c.upper() for c in args.cve}
        scored = [
            s
            for s in scored
            if (s.finding.cve_id or "").upper() in wanted_cves
        ]
    if args.min_priority > 0:
        scored = [s for s in scored if s.priority_score >= args.min_priority]
    if args.limit > 0:
        scored = scored[: args.limit]

    path_by_asset = None
    if args.explain:
        path_by_asset = {
            a.id: shortest_path(a.id, assets, edges) for a in assets
        }

    try:
        if args.format == "table":
            if args.output is not None:
                with args.output.open("w", encoding="utf-8") as fh:
                    _print_table(
                        scored,
                        fh,
                        explain=args.explain,
                        path_by_asset=path_by_asset,
                        show_title=args.show_title,
                    )
            else:
                _print_table(
                    scored,
                    sys.stdout,
                    explain=args.explain,
                    path_by_asset=path_by_asset,
                    show_title=args.show_title,
                )
        else:
            text = _render(
                scored, args.format, explain=args.explain, path_by_asset=path_by_asset
            )
            if args.output is not None:
                args.output.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.summary:
        print(format_summary_line(summarize(scored)), file=sys.stderr)

    if args.fail_under is not None:
        offenders = [s for s in scored if s.priority_score >= args.fail_under]
        if offenders:
            print(
                f"error: {len(offenders)} finding(s) at or above --fail-under "
                f"{args.fail_under}",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
