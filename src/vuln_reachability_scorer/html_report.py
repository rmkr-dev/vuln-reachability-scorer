"""Self-contained HTML report for scored findings (stdlib only)."""

from __future__ import annotations

from html import escape

from vuln_reachability_scorer import __version__
from vuln_reachability_scorer.explain import explain_score
from vuln_reachability_scorer.models import ScoredFinding
from vuln_reachability_scorer.paths import format_path


def _band(priority: float) -> str:
    if priority >= 9.0:
        return "critical"
    if priority >= 7.0:
        return "high"
    if priority >= 4.0:
        return "medium"
    return "low"


def to_html(
    scored: list[ScoredFinding],
    *,
    explain: bool = False,
    path_by_asset: dict | None = None,
) -> str:
    """Return a complete HTML5 document ranking scored findings."""
    rows = []
    for item in scored:
        band = _band(item.priority_score)
        hops = "-" if item.hop_distance is None else str(item.hop_distance)
        epss = "-" if item.finding.epss is None else f"{item.finding.epss:.3f}"
        kev = "yes" if item.finding.kev else "no"
        explain_row = ""
        if explain:
            path_txt = None
            if path_by_asset is not None:
                path_txt = format_path(path_by_asset.get(item.finding.asset_id))
            explain_row = (
                f'<tr class="explain"><td colspan="11">'
                f"{escape(explain_score(item, path_txt))}</td></tr>"
            )
        rows.append(
            "<tr>"
            f'<td class="num band-{escape(band)}">{item.priority_score:.2f}</td>'
            f'<td class="num">{item.finding.base_score:.1f}</td>'
            f'<td class="num">{item.reachability_factor:.2f}</td>'
            f'<td class="num">{item.exposure_factor:.2f}</td>'
            f'<td class="num">{escape(hops)}</td>'
            f"<td>{escape(item.finding.cve_id or '-')}</td>"
            f"<td>{escape(item.finding.asset_id)}</td>"
            f"<td>{escape(item.finding.id)}</td>"
            f"<td>{escape(item.finding.title or '-')}</td>"
            f"<td>{escape(kev)}</td>"
            f'<td class="num">{escape(epss)}</td>'
            f"</tr>{explain_row}"
        )
    body = "\n".join(rows) if rows else (
        '<tr><td colspan="11" class="empty">No findings to report.</td></tr>'
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vuln-reachability-scorer {escape(__version__)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 1.5rem; line-height: 1.4; }}
  h1 {{ font-size: 1.25rem; margin: 0 0 0.25rem; }}
  .meta {{ color: #555; margin-bottom: 1rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border-bottom: 1px solid #ccc; padding: 0.35rem 0.5rem; text-align: left; }}
  th {{ font-size: 0.8rem; letter-spacing: 0.02em; }}
  td.num {{ font-variant-numeric: tabular-nums; text-align: right; }}
  tr.explain td {{ font-size: 0.85rem; color: #444; border-bottom-width: 2px; }}
  td.empty {{ text-align: center; color: #666; }}
  .band-critical {{ font-weight: 700; }}
  .band-high {{ font-weight: 600; }}
</style>
</head>
<body>
<h1>vuln-reachability-scorer</h1>
<p class="meta">version {escape(__version__)} · formula
<code>priority = base × R × E</code> (KEV/EPSS multipliers after, clamp 10)
· {len(scored)} finding(s)</p>
<table>
<thead>
<tr>
  <th>PRIORITY</th><th>BASE</th><th>R</th><th>E</th><th>HOPS</th>
  <th>CVE</th><th>ASSET</th><th>ID</th><th>TITLE</th><th>KEV</th><th>EPSS</th>
</tr>
</thead>
<tbody>
{body}
</tbody>
</table>
</body>
</html>
"""


def to_asset_html(rows: list) -> str:
    """Return a complete HTML5 document for an asset-report inventory."""
    body_rows = []
    for r in rows:
        hops = "-" if r.hop_distance is None else str(r.hop_distance)
        body_rows.append(
            "<tr>"
            f"<td>{escape(r.asset.id)}</td>"
            f"<td>{escape(r.asset.kind)}</td>"
            f'<td class="num">{escape(hops)}</td>'
            f'<td class="num">{r.reachability_factor:.2f}</td>'
            f'<td class="num">{r.exposure_factor:.2f}</td>'
            f'<td class="num">{r.asset.criticality:.2f}</td>'
            f"<td>{'yes' if r.asset.ingress else 'no'}</td>"
            f"<td>{escape(r.asset.name)}</td>"
            f"<td>{escape('|'.join(r.asset.tags))}</td>"
            "</tr>"
        )
    body = "\n".join(body_rows) if body_rows else (
        '<tr><td colspan="9" class="empty">No assets in topology.</td></tr>'
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vuln-reachability-scorer asset report {escape(__version__)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 1.5rem; line-height: 1.4; }}
  h1 {{ font-size: 1.25rem; margin: 0 0 0.25rem; }}
  .meta {{ color: #555; margin-bottom: 1rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border-bottom: 1px solid #ccc; padding: 0.35rem 0.5rem; text-align: left; }}
  td.num {{ font-variant-numeric: tabular-nums; text-align: right; }}
  td.empty {{ text-align: center; color: #666; }}
</style>
</head>
<body>
<h1>Asset reachability inventory</h1>
<p class="meta">version {escape(__version__)} · {len(rows)} asset(s)</p>
<table>
<thead>
<tr>
  <th>ASSET</th><th>KIND</th><th>HOPS</th><th>R</th><th>E</th>
  <th>CRIT</th><th>INGRESS</th><th>NAME</th><th>TAGS</th>
</tr>
</thead>
<tbody>
{body}
</tbody>
</table>
</body>
</html>
"""
