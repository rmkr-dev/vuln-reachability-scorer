# Usage cookbook

Practical recipes for `vrscore`. All commands assume an editable install (`pip install -e ".[dev]"`).

## Score the sample estate

```bash
vrscore -t examples/topology.json -f examples/findings.json
vrscore -t examples/topology.json -f examples/findings.json --explain
# explain lines include ingress -> asset path when reachable
```

## Validate topology before findings arrive

```bash
vrscore -t examples/topology.json --asset-report
vrscore -t examples/topology.json --asset-report --format json -o assets.json
vrscore -t examples/topology.json --asset-report --format csv -o assets.csv
```

## Export for spreadsheets or code scanning

```bash
vrscore -t examples/topology.json -f examples/findings.json --format csv -o scores.csv
vrscore -t examples/topology.json -f examples/findings.json --format jsonl -o scores.jsonl
vrscore -t examples/topology.json -f examples/findings.json --format sarif -o scores.sarif
vrscore -t examples/topology.json -f examples/findings.json --format html -o report.html
vrscore -t examples/topology.json -f examples/findings.json --format markdown -o report.md
vrscore -t examples/topology.json -f examples/findings.json --format junit -o report.xml
```

## Focus triage

```bash
vrscore -t examples/topology.json -f examples/findings.json --min-priority 4 --limit 10 --explain
vrscore -t examples/topology.json -f examples/findings.json --min-base 7 --explain
vrscore -t examples/topology.json -f examples/findings.json --sort hops --explain
vrscore -t examples/topology.json -f examples/findings.json --summary
# stderr includes kev= and epss= counts alongside bands
```

## Raise exposure for sensitive tags

Ship `tag_boosts` in topology (merged over defaults `pii` / `identity` / `secrets`):

```json
{
  "tag_boosts": {"pii": 0.25, "pci": 0.2},
  "assets": [{"id": "db", "criticality": 0.6, "tags": ["pii", "pci"], "ingress": false}],
  "edges": []
}
```

Effective exposure is `clamp(criticality + Σ boosts, 0, 1)`.

## Strict topology hygiene

```bash
vrscore -t topology.json -f findings.json --strict
```

Fails (exit 2) if any edge references an unknown asset id.

## Quiet mode

```bash
vrscore -t topology.json -f findings.json --quiet --format json
```

Suppresses non-error stderr warnings (unknown edge endpoints). `--strict` errors and `--summary` still print.

## Mark Known Exploited findings

Set `"kev": true` on a finding to apply the 1.15 KEV multiplier (see [ADR-003](../decisions/ADR-003-kev-multiplier.md)).

## Supply EPSS when you already have it

Set `"epss": 0.73` (or any value in `[0, 1]`) on a finding to apply the optional EPSS nudge (see [ADR-004](../decisions/ADR-004-epss-factor.md)). The CLI does not fetch EPSS; omit the field when you do not have a score.

## CI gate

```bash
vrscore -t topology.json -f findings.json --fail-under 7 --summary
```

Exits `1` if any scored finding has `priority_score >= 7`, suitable as a required check.

## KEV-only triage

```bash
vrscore -t examples/topology.json -f examples/findings.json --only-kev --explain --summary
```

## Reachable-only triage

```bash
vrscore -t examples/topology.json -f examples/findings.json --only-reachable --summary
```

Drops findings whose asset has no path from an ingress / internet-facing node (`hop_distance` is null / `R = 0.10`).

## Limit by hop distance

```bash
vrscore -t examples/topology.json -f examples/findings.json --max-hops 1 --explain
```

Keeps findings with `hop_distance <= N` and drops unreachable assets. `--max-hops 0` is ingress-only.

## Filter by priority band

```bash
vrscore -t examples/topology.json -f examples/findings.json --band critical --band high --summary
```

Bands match `--summary`: `critical` ≥ 9, `high` ≥ 7, `medium` ≥ 4, `low` < 4. Repeat `--band` to union bands.

## Filter by EPSS floor

```bash
vrscore -t examples/topology.json -f examples/findings.json --min-epss 0.5 --explain
```

Keeps findings with `epss >= P`. Findings that omit `epss` are dropped when this flag is set. `P` must be in `[0, 1]`.

## Scope to specific assets

```bash
vrscore -t examples/topology.json -f examples/findings.json --asset web-app --asset auth --explain
```

Repeat `--asset` to union asset ids. Unknown ids simply yield an empty match set for that id.

## Filter by CVE id

```bash
vrscore -t examples/topology.json -f examples/findings.json --cve CVE-2021-44228 --explain
```

Matching is case-insensitive. Repeat `--cve` to union ids. Findings without a CVE id never match.

## Topology pitfalls

Edges are **directed**. A path `db -> api` does not make `db` reachable from an ingress `api`. Other cases the scorer already covers:

- Self-loops never add hops; an ingress node stays hop 0.
- Duplicate parallel edges do not inflate hop distance.
- When two ingress nodes can reach an asset, the **closest** hop count wins.
- Uneven diamonds take the short leg.
- `internet_facing: true` marks the **target** as ingress even if the source id is outside `assets`.
- Isolated components and reverse-only edges are unreachable (`R = 0.10`).
- Five or more hops use the deep factor (`R = 0.20`).

`--strict` still only cares about edge endpoints missing from `assets`, not about reachability.

## Read error messages

Exit code `2` is an input/usage error. Messages name the file kind (`topology` / `findings`), the path, and (for JSON) the line and column. Indexed items (`findings[0]`, `topology.assets[2]`) point at the bad record. `--strict` promotes unknown edge endpoints from `warning:` to `error:`.

## Flag cheatsheet

| Flag | Purpose |
| --- | --- |
| `-t` / `--topology` | Topology JSON (required) |
| `-f` / `--findings` | Findings JSON (required unless `--asset-report`) |
| `--format` | `table` \| `json` \| `jsonl` \| `csv` \| `sarif` \| `html` \| `markdown` \| `junit` |
| `-o` / `--output` | Write to file |
| `--asset-report` | Per-asset reachability inventory |
| `--explain` | Human rationale + shortest path |
| `--summary` | Band counts + kev/epss counts on stderr |
| `--strict` | Unknown edge endpoints are errors |
| `--quiet` / `-q` | Suppress non-error warnings |
| `--fail-under SCORE` | Exit 1 if any priority >= SCORE |
| `--only-kev` | Keep `kev: true` findings only |
| `--only-reachable` | Drop unreachable assets |
| `--max-hops N` | Keep hop_distance <= N |
| `--band BAND` | Keep priority band(s); repeatable |
| `--min-epss P` | Keep epss >= P (omitters dropped) |
| `--asset ID` | Keep findings for asset id(s); repeatable |
| `--cve CVE` | Keep matching CVE id(s); repeatable |
| `--show-title` | TITLE column in table |
| `--min-priority` / `--limit` | Filter / cap results |
| `--min-base` | Omit low base_score findings |
| `--sort` | `priority` \| `base` \| `hops` \| `asset` \| `cve` |
