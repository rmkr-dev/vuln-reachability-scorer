# Config file schema (`--config`)

Optional JSON or TOML defaults for the CLI ([ADR-006](../decisions/ADR-006-config-file.md)). Pass `--config` / `-c`, or set `VRSCORE_CONFIG` to an explicit path; there is no cwd auto-discovery.

## Precedence

built-in defaults < config file < explicit CLI flags

Relative `topology` / `findings` / `output` paths resolve against the directory of the **file that defines them** (with `extends`, each file's paths stay rooted at that file).

## Keys

| Key | Type | Notes |
| --- | --- | --- |
| `extends` | string (path) | Base config to load first (relative or absolute; child keys overlay; lists replace) |
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
- `min_epss` must be in `[0, 1]`; `min_priority` / `fail_under` / `min_base` / `limit` / `max_hops` / `min_hops` must be `>= 0`.
- When both `min_hops` and `max_hops` are set (including after `extends` merge), `min_hops` must not exceed `max_hops`.
- `extends` chains detect cycles, reject missing targets / directories, and cap at depth `MAX_EXTENDS_DEPTH` (8).
- List keys apply only when the matching CLI flag is absent.

## Examples

See `examples/vrscore.toml`, `examples/vrscore.json`, `examples/vrscore-triage.toml`, `examples/vrscore-ci.toml`, and layered overlays such as `vrscore-tag-focus.toml`.

Cross-format `extends` is supported in both directions (`.json`↔`.toml`). Non-string `extends` values are rejected. List keys in the child **replace** the base list.

## JSON Schema

A draft schema lives at [`vrscore.schema.json`](vrscore.schema.json) for editor tooling. Runtime validation remains in `config.py`.
