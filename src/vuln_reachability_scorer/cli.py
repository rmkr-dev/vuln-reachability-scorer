"""CLI entrypoint: ``vrscore`` / ``vuln-reachability``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vuln_reachability_scorer import __version__
from vuln_reachability_scorer.loaders import load_findings, load_topology
from vuln_reachability_scorer.sarif import to_sarif
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
        choices=("table", "json", "sarif"),
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _print_table(scored: list) -> None:
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

    print(fmt(headers))
    print(fmt(tuple("-" * w for w in widths)))
    for row in rows:
        print(fmt(row))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        assets, edges = load_topology(args.topology)
        findings = load_findings(args.findings)
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    scored = score_findings(findings, assets, edges)

    if args.format == "json":
        payload = {
            "version": __version__,
            "formula": "priority = base_score * reachability_factor * exposure_factor",
            "results": [s.as_dict() for s in scored],
        }
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.format == "sarif":
        json.dump(to_sarif(scored), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_table(scored)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
