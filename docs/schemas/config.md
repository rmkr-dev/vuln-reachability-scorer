# Config file schema (`--config`)

Optional JSON or TOML defaults for the CLI ([ADR-006](../decisions/ADR-006-config-file.md)). Pass `--config` / `-c`, or set `VRSCORE_CONFIG` to an explicit path; there is no cwd auto-discovery.

## Precedence

built-in defaults < config file < explicit CLI flags

Relative `topology` / `findings` / `output` paths resolve against the config file's directory.

## Keys

| Key | Type | Notes |
| --- | --- | --- |
| `topology` | string (path) | Topology JSON |
| `findings` | string or list of paths | Findings JSON (list merges in order) |
| `format` | string | `table` \| `json` \| `jsonl` \| `csv` \| `tsv` \| `sarif` \| `html` \| `markdown` \| `junit` |
| `output` | string (path) | Write results to file |
| `min_priority` | number | Omit below threshold |
| `min_base` | number | Omit low base_score |
| `limit` | integer | Cap results |
| `explain` | bool | Rationales + paths |
| `strict` | bool | Unknown edges are errors |
| `asset_report` | bool | Per-asset inventory |
| `summary` | bool | Band counts on stderr |
| `fail_under` | number | CI gate threshold |
| `show_title` | bool | TITLE column |
| `only_kev` | bool | KEV-only |
| `only_reachable` | bool | Drop unreachable |
| `max_hops` | integer | Hop ceiling |
| `min_hops` | integer | Hop floor (excludes unreachable) |
| `stats` | bool | Timing line on stderr |
| `band` | list of string | `critical` / `high` / `medium` / `low` |
| `min_epss` | number in `[0,1]` | EPSS floor |
| `asset` | list of string | Asset id filter |
| `exclude_asset` | list of string | Drop asset id(s) |
| `cve` | list of string | CVE id filter |
| `exclude_cve` | list of string | Drop CVE id(s) |
| `tag` | list of string | Tag filter (OR) |
| `exclude_tag` | list of string | Drop assets with tag (OR) |
| `quiet` | bool | Suppress warnings |
| `sort` | string | `priority` \| `base` \| `hops` \| `asset` \| `cve` |
| `dedupe` | bool | Best per CVE+asset |

## Validation

- Unknown keys are errors (exit 2).
- `format` / `sort` must match CLI choices; `band` entries must be `critical` / `high` / `medium` / `low`.
- List keys apply only when the matching CLI flag is absent.

## Examples

See `examples/vrscore.toml`, `examples/vrscore.json`, `examples/vrscore-triage.toml`, and `examples/vrscore-ci.toml`.
