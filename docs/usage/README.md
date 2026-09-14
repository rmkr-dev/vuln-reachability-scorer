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
vrscore -t examples/topology.json --asset-report --only-reachable --max-hops 2 --limit 20
```

## Export for spreadsheets or code scanning

```bash
vrscore -t examples/topology.json -f examples/findings.json --format csv -o scores.csv
vrscore -t examples/topology.json -f examples/findings.json --format tsv -o scores.tsv
vrscore -t examples/topology.json -f examples/findings.json --format jsonl -o scores.jsonl
vrscore -t examples/topology.json -f examples/findings.json --format sarif -o scores.sarif
vrscore -t examples/topology.json -f examples/findings.json --format html -o report.html
vrscore -t examples/topology.json -f examples/findings.json --format markdown -o report.md
vrscore -t examples/topology.json -f examples/findings.json --format junit -o report.xml
```

## Triage playbook (sample estate)

1. Inventory reachability: `vrscore -t examples/topology.json --asset-report --only-reachable`
2. Score with explanations: `vrscore --config examples/vrscore.toml --explain --summary`
3. Keep attacker-relevant rows: `--only-reachable --max-hops 2 --band critical --band high`
4. Deduplicate noisy scanners: `--dedupe --sort hops`
5. Gate CI: `--fail-under 7` (exit `1` on offenders)
6. Export for tracking: `--format sarif` or `--format junit`

## Focus triage

```bash
vrscore -t examples/topology.json -f examples/findings.json --min-priority 4 --limit 10 --explain
vrscore -t examples/topology.json -f examples/findings.json --min-base 7 --explain
vrscore -t examples/topology.json -f examples/findings.json --sort hops --explain
vrscore -t examples/topology.json -f examples/findings.json --dedupe --summary
vrscore -t examples/topology.json -f examples/findings.json --tag pii --tag identity --explain
vrscore -t examples/topology.json -f examples/findings.json --exclude-tag experimental --summary
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

```bash
vrscore -t examples/topology.json -f examples/findings.json --min-hops 1 --max-hops 3 --explain
```

`--min-hops N` keeps `hop_distance >= N` (also drops unreachable). Combine with `--max-hops` for a hop window.

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


## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (including empty result sets after filters) |
| `1` | `--fail-under` gate tripped (one or more priorities at/above the threshold) |
| `2` | Usage / input error (missing files, invalid JSON, `--strict` unknown edges, bad flag values) |

`--quiet` only suppresses non-error warnings; it does not change exit codes.

Filter composition order is fixed; see [ADR-005](../decisions/ADR-005-triage-filter-order.md).

## GitHub Actions gate with a config file

Commit a project config (for example `vrscore.toml` next to your topology) and call the CLI in CI:

```yaml
- name: Reachability triage gate
  run: |
    pip install .
    vrscore --config vrscore.toml --fail-under 7 --summary --format sarif -o reachability.sarif
- name: Upload SARIF (optional)
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: reachability.sarif
```

Use `--quiet` in CI logs when edge warnings are expected noise; keep `--strict` when topology hygiene is a hard requirement. Pin this repo's reusable Python CI at `@v0.4.0` (see [development](../development/development.md)).

## Multiple findings files

Repeat `-f` / `--findings` to merge scanner exports (order preserved; later files append):

```bash
vrscore -t examples/topology.json -f scan-a.json -f scan-b.json --dedupe --summary
```

In a config file, `findings` may be a string or a list of paths.

## Config file defaults

Pass `--config` / `-c` with a JSON or TOML file. Flags on the command line always win. Relative paths inside the file are resolved against the config file's directory. See [ADR-006](../decisions/ADR-006-config-file.md) and the [config schema](../schemas/config.md).

```bash
vrscore --config examples/vrscore.toml
vrscore -c examples/vrscore.json --format table --band low
vrscore -c examples/vrscore.toml --fail-under 7 --summary
```

There is no automatic cwd discovery; omit `--config` to keep today's flag-only behavior.

## Timing stats

```bash
vrscore -t examples/topology.json -f examples/findings.json --stats --format json >/dev/null
```

Prints a single stderr line: load / score / render seconds plus finding/result/asset/edge counts. Useful when tuning large topologies (see Large topologies).

## Large topologies

Scoring and `--asset-report` run **one** multi-source BFS from all ingress / internet-facing nodes, then look up hop distance per asset (`all_hop_distances`). `--explain` likewise builds every shortest path in one BFS (`all_shortest_paths`). Cost is O(V+E) in the topology size, not O(findings × (V+E)). Duplicate parallel edges are collapsed when building adjacency.

For estates with tens of thousands of assets, prefer JSON/JSONL/CSV over the table format, drop `--explain` unless needed, and use filters (`--min-priority`, `--band`, `--only-reachable`, `--max-hops`, `--limit`) to shrink output.

## Flag cheatsheet

| Flag | Purpose |
| --- | --- |
| `-c` / `--config` | JSON/TOML defaults (flags override) |
| `-t` / `--topology` | Topology JSON (required; or via config) |
| `-f` / `--findings` | Findings JSON (repeatable merge; required unless `--asset-report`) |
| `--format` | `table` \| `json` \| `jsonl` \| `csv` \| `tsv` \| `sarif` \| `html` \| `markdown` \| `junit` |
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
| `--min-hops N` | Keep hop_distance >= N |
| `--stats` | Load/score/render timing on stderr |
| `--band BAND` | Keep priority band(s); repeatable |
| `--min-epss P` | Keep epss >= P (omitters dropped) |
| `--asset ID` | Keep findings for asset id(s); repeatable |
| `--cve CVE` | Keep matching CVE id(s); repeatable |
| `--show-title` | TITLE column in table |
| `--min-priority` / `--limit` | Filter / cap results |
| `--min-base` | Omit low base_score findings |
| `--sort` | `priority` \| `base` \| `hops` \| `asset` \| `cve` |
| `--dedupe` | Highest priority per CVE+asset |
| `--tag TAG` | Keep assets with tag(s); OR; repeatable |
| `--exclude-tag TAG` | Drop assets with tag(s); OR; repeatable |
