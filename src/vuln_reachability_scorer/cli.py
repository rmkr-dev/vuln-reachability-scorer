"""CLI entrypoint: ``vrscore`` / ``vuln-reachability``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vuln_reachability_scorer import __version__
from vuln_reachability_scorer.loaders import (
    load_findings,
    load_topology,
    unknown_edge_endpoints,
)
from vuln_reachability_scorer.sarif import to_sarif
from vuln_reachability_scorer.explain import explain_score
from vuln_reachability_scorer.scoring import score_findings


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
        required=True,
        help="Path to findings JSON",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "sarif", "csv"),
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
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _print_table(scored: list, sink, explain: bool = False) -> None:
    headers = (
        "PRIORITY",
        "BASE",
        "R",
        "E",
        "HOPS",
        "CVE",
        "ASSET",
        "ID",
    )
    rows = [
        (
            f"{s.priority_score:.2f}",
            f"{s.finding.base_score:.1f}",
            f"{s.reachability_factor:.2f}",
            f"{s.exposure_factor:.2f}",
            "-" if s.hop_distance is None else str(s.hop_distance),
            s.finding.cve_id or "-",
            s.finding.asset_id,
            s.finding.id,
        )
        for s in scored
    ]
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
            print(f"  # {explain_score(scored[idx])}", file=sink)


def _render_csv(scored: list) -> str:
    import csv
    from io import StringIO

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
            ]
        )
    return buf.getvalue()


def _render(scored: list, fmt: str, explain: bool = False) -> str:
    if fmt == "json":
        payload = {
            "version": __version__,
            "formula": "priority = base_score * reachability_factor * exposure_factor",
            "results": [
                {**s.as_dict(), **({"explain": explain_score(s)} if explain else {})}
                for s in scored
            ],
        }
        return json.dumps(payload, indent=2) + "\n"
    if fmt == "sarif":
        return json.dumps(to_sarif(scored), indent=2) + "\n"
    if fmt == "csv":
        return _render_csv(scored)
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.min_priority < 0:
        print("error: --min-priority must be >= 0", file=sys.stderr)
        return 2
    if args.limit < 0:
        print("error: --limit must be >= 0", file=sys.stderr)
        return 2

    try:
        assets, edges = load_topology(args.topology)
        findings = load_findings(args.findings)
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    edge_warnings = unknown_edge_endpoints(assets, edges)
    if edge_warnings:
        for msg in edge_warnings:
            print(f"{'error' if args.strict else 'warning'}: {msg}", file=sys.stderr)
        if args.strict:
            return 2

    scored = score_findings(findings, assets, edges)
    if args.min_priority > 0:
        scored = [s for s in scored if s.priority_score >= args.min_priority]
    if args.limit > 0:
        scored = scored[: args.limit]

    try:
        if args.format == "table":
            if args.output is not None:
                with args.output.open("w", encoding="utf-8") as fh:
                    _print_table(scored, fh, explain=args.explain)
            else:
                _print_table(scored, sys.stdout, explain=args.explain)
        else:
            text = _render(scored, args.format, explain=args.explain)
            if args.output is not None:
                args.output.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
