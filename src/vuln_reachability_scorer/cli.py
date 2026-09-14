"""CLI entrypoint: ``vrscore`` / ``vuln-reachability``."""

from __future__ import annotations

import argparse
import time
import csv
import json
import sys
from io import StringIO
from pathlib import Path

from vuln_reachability_scorer import __version__
from vuln_reachability_scorer.asset_report import report_assets
from vuln_reachability_scorer.explain import explain_score
from vuln_reachability_scorer.paths import all_shortest_paths, format_path
from vuln_reachability_scorer.loaders import (
    load_findings,
    load_tag_boosts,
    load_topology,
    unknown_edge_endpoints,
)
from vuln_reachability_scorer.html_report import to_asset_html, to_html
from vuln_reachability_scorer.markdown_report import to_asset_markdown, to_markdown
from vuln_reachability_scorer.junit_report import to_junit
from vuln_reachability_scorer.sarif import to_sarif
from vuln_reachability_scorer.scoring import score_findings
from vuln_reachability_scorer.summary import format_summary_line, summarize
from vuln_reachability_scorer.config import (
    ConfigError,
    apply_config_defaults,
    load_config,
    merge_list_defaults,
)



_BAND_PREDICATES = {
    "critical": lambda p: p >= 9.0,
    "high": lambda p: 7.0 <= p < 9.0,
    "medium": lambda p: 4.0 <= p < 7.0,
    "low": lambda p: p < 4.0,
}


def _in_selected_bands(priority: float, bands: list[str]) -> bool:
    return any(_BAND_PREDICATES[b](priority) for b in bands)



def _sort_scored(scored: list, key: str) -> list:
    if key == "priority":
        return sorted(scored, key=lambda s: (-s.priority_score, s.finding.id))
    if key == "base":
        return sorted(scored, key=lambda s: (-s.finding.base_score, s.finding.id))
    if key == "hops":
        return sorted(
            scored,
            key=lambda s: (
                s.hop_distance is None,
                s.hop_distance if s.hop_distance is not None else 0,
                s.finding.id,
            ),
        )
    if key == "asset":
        return sorted(scored, key=lambda s: (s.finding.asset_id, s.finding.id))
    if key == "cve":
        return sorted(scored, key=lambda s: ((s.finding.cve_id or ""), s.finding.id))
    return scored



def _dedupe_scored(scored: list) -> list:
    best: dict[tuple[str, str], object] = {}
    order: list[tuple[str, str]] = []
    for s in scored:
        cve = (s.finding.cve_id or "").strip() or s.finding.id
        key = (cve.upper(), s.finding.asset_id)
        prev = best.get(key)
        if prev is None:
            best[key] = s
            order.append(key)
        elif s.priority_score > prev.priority_score:  # type: ignore[union-attr]
            best[key] = s
        elif (
            s.priority_score == prev.priority_score  # type: ignore[union-attr]
            and s.finding.id < prev.finding.id  # type: ignore[union-attr]
        ):
            best[key] = s
    return [best[k] for k in order]  # type: ignore[misc]


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
        help="Path to topology JSON (assets + edges); may come from --config",
    )
    parser.add_argument(
        "--findings",
        "-f",
        type=Path,
        action="append",
        default=None,
        help="Path to findings JSON (repeatable; merged in order; required unless --asset-report)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "jsonl", "sarif", "csv", "tsv", "html", "markdown", "junit"),
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
        "--min-base",
        type=float,
        default=0.0,
        help="Omit findings with base_score below this threshold (default: 0)",
    )
    parser.add_argument(
        "--sort",
        choices=("priority", "base", "hops", "asset", "cve"),
        default="priority",
        help="Sort results (default: priority desc; hops asc with nulls last)",
    )
    parser.add_argument(
        "--dedupe",
        action="store_true",
        help="Keep highest-priority finding per (cve_id, asset_id); empty cve uses finding id",
    )
    parser.add_argument(
        "--tag",
        action="append",
        default=None,
        metavar="TAG",
        help="Keep findings on assets that have this tag (repeatable; OR semantics)",
    )
    parser.add_argument(
        "--min-hops",
        type=int,
        default=None,
        metavar="N",
        help="Keep only findings with hop_distance >= N (excludes unreachable)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print timing stats for load/score/render to stderr",
    )
    parser.add_argument(
        "--exclude-tag",
        action="append",
        default=None,
        metavar="TAG",
        help="Drop findings on assets that have this tag (repeatable; OR semantics)",
    )
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        help="JSON or TOML config file with CLI defaults (flags override)",
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



def _render_tsv(scored: list) -> str:
    buf = StringIO()
    writer = csv.writer(buf, dialect="excel-tab")
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
    if fmt == "tsv":
        return _render_tsv(scored)
    if fmt == "html":
        return to_html(scored, explain=explain, path_by_asset=path_by_asset)
    if fmt == "markdown":
        return to_markdown(scored, explain=explain, path_by_asset=path_by_asset)
    if fmt == "junit":
        return to_junit(scored)
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



def _render_asset_tsv(rows: list) -> str:
    buf = StringIO()
    writer = csv.writer(buf, dialect="excel-tab")
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
    if getattr(args, "max_hops", None) is not None:
        rows = [
            r
            for r in rows
            if r.hop_distance is not None and r.hop_distance <= args.max_hops
        ]
    if getattr(args, "only_reachable", False):
        rows = [r for r in rows if r.hop_distance is not None]
    if args.limit > 0:
        rows = rows[: args.limit]
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
        elif args.format == "tsv":
            text = _render_asset_tsv(rows)
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
        elif args.format == "junit":
            print(
                "error: --asset-report does not support --format junit",
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
    argv = list(sys.argv[1:] if argv is None else argv)
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", "-c", type=Path)
    pre_args, _ = pre.parse_known_args(argv)

    parser = build_parser()
    config_defaults: dict = {}
    resolved_defaults: dict = {}
    if pre_args.config is not None:
        try:
            config_defaults = load_config(pre_args.config)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        resolved_defaults = apply_config_defaults(
            parser, config_defaults, config_dir=pre_args.config.parent
        )
    args = parser.parse_args(argv)
    if resolved_defaults:
        merge_list_defaults(args, resolved_defaults)

    if args.topology is None:
        print("error: --topology is required (pass -t or set topology in --config)", file=sys.stderr)
        return 2

    if not args.asset_report and not args.findings:
        parser.error("--findings is required unless --asset-report is set")

    if args.min_priority < 0:
        print("error: --min-priority must be >= 0", file=sys.stderr)
        return 2
    if args.min_base < 0:
        print("error: --min-base must be >= 0", file=sys.stderr)
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
    if args.min_hops is not None and args.min_hops < 0:
        print("error: --min-hops must be >= 0", file=sys.stderr)
        return 2
    if (
        args.min_hops is not None
        and args.max_hops is not None
        and args.min_hops > args.max_hops
    ):
        print("error: --min-hops cannot exceed --max-hops", file=sys.stderr)
        return 2
    if args.min_epss is not None and not (0.0 <= args.min_epss <= 1.0):
        print("error: --min-epss must be between 0 and 1", file=sys.stderr)
        return 2

    t0 = time.perf_counter()
    try:
        assets, edges = load_topology(args.topology)
        tag_boosts = load_tag_boosts(args.topology)
        findings = []
        if args.findings:
            for fpath in args.findings:
                findings.extend(load_findings(fpath))
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    t_load = time.perf_counter() - t0

    if findings:
        seen: dict[str, int] = {}
        dupes: list[str] = []
        for f in findings:
            if f.id in seen:
                if f.id not in dupes:
                    dupes.append(f.id)
            else:
                seen[f.id] = 1
        if dupes:
            msg = f"duplicate finding id(s) across inputs: {', '.join(dupes)}"
            if args.strict:
                print(f"error: {msg}", file=sys.stderr)
                return 2
            if not args.quiet:
                print(f"warning: {msg}", file=sys.stderr)

    edge_warnings = unknown_edge_endpoints(assets, edges)
    if edge_warnings:
        for msg in edge_warnings:
            label = "error" if args.strict else "warning"
            if args.strict or not args.quiet:
                print(f"{label}: {msg}", file=sys.stderr)
        if args.strict:
            return 2

    if args.asset_report:
        t1 = time.perf_counter()
        rc = _emit_asset_report(assets, edges, args, tag_boosts)
        if args.stats:
            print(
                f"stats: load={t_load:.3f}s asset_report={time.perf_counter()-t1:.3f}s",
                file=sys.stderr,
            )
        return rc

    t1 = time.perf_counter()
    scored = score_findings(findings, assets, edges, tag_boosts=tag_boosts)
    t_score = time.perf_counter() - t1
    assets_by_id = {a.id: a for a in assets}
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
    if args.min_hops is not None:
        scored = [
            s
            for s in scored
            if s.hop_distance is not None and s.hop_distance >= args.min_hops
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
    if args.min_base > 0:
        scored = [s for s in scored if s.finding.base_score >= args.min_base]
    if args.min_priority > 0:
        scored = [s for s in scored if s.priority_score >= args.min_priority]
    if args.tag:
        wanted = {t.lower() for t in args.tag}
        filtered = []
        for s in scored:
            asset = assets_by_id.get(s.finding.asset_id)
            tags = {tg.lower() for tg in (asset.tags if asset is not None else ())}
            if wanted.intersection(tags):
                filtered.append(s)
        scored = filtered
    if args.exclude_tag:
        blocked = {t.lower() for t in args.exclude_tag}
        filtered = []
        for s in scored:
            asset = assets_by_id.get(s.finding.asset_id)
            tags = {tg.lower() for tg in (asset.tags if asset is not None else ())}
            if not blocked.intersection(tags):
                filtered.append(s)
        scored = filtered
    if args.dedupe:
        scored = _dedupe_scored(scored)
    if args.sort != "priority":
        scored = _sort_scored(scored, args.sort)
    if args.limit > 0:
        scored = scored[: args.limit]

    path_by_asset = None
    if args.explain:
        path_by_asset = all_shortest_paths(assets, edges)

    t2 = time.perf_counter()
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

    t_render = time.perf_counter() - t2
    if args.stats:
        print(
            f"stats: load={t_load:.3f}s score={t_score:.3f}s render={t_render:.3f}s "
            f"findings={len(findings)} results={len(scored)} assets={len(assets)} edges={len(edges)}",
            file=sys.stderr,
        )

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
