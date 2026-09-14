# vuln-reachability-scorer

Python CLI that scores CVEs by **reachability and exposure** (topology), not raw CVSS alone.

Security scanners flood teams with CVSS numbers. Two findings with the same CVSS are not equal if one sits on an internet-facing edge and the other is three hops deep behind a bastion. This tool multiplies a base severity by topology-derived factors so prioritization matches how an attacker would actually move.

## Formula

```text
priority_score = round(base_score × reachability_factor × exposure_factor, 2)
```

- **base_score** — CVSS-like severity in `[0, 10]` from the finding
- **reachability_factor** — from shortest hop distance to an ingress / internet-facing asset (`1.0` at ingress → `0.1` if unreachable)
- **exposure_factor** — `clamp(criticality + tag_boosts, 0, 1)` (defaults for `pii` / `identity` / `secrets`)

See [ADR-001](docs/decisions/ADR-001-scoring-model.md) and `src/vuln_reachability_scorer/scoring.py`. Findings may set `kev: true` for a 1.15 Known Exploited Vulnerability multiplier (clamped at 10). Optional `epss` in `[0, 1]` applies a further `1 + 0.20 × epss` multiplier ([ADR-004](docs/decisions/ADR-004-epss-factor.md)).

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

```bash
vrscore --topology examples/topology.json --findings examples/findings.json
vrscore -t examples/topology.json -f examples/findings.json --format json
vrscore -t examples/topology.json -f examples/findings.json --format jsonl -o scores.jsonl
vrscore -t examples/topology.json -f examples/findings.json --format csv -o scores.csv
vrscore -t examples/topology.json -f examples/findings.json --format sarif -o results.sarif
vrscore -t examples/topology.json -f examples/findings.json --format html -o report.html
vrscore -t examples/topology.json -f examples/findings.json --format markdown -o report.md
vrscore -t examples/topology.json -f examples/findings.json --format junit -o report.xml
vrscore -t examples/topology.json -f examples/findings.json --min-priority 4.0 --limit 20
vrscore -t examples/topology.json -f examples/findings.json --explain
vrscore -t examples/topology.json -f examples/findings.json --summary
vrscore -t examples/topology.json -f examples/findings.json --fail-under 7
vrscore -t examples/topology.json --asset-report
# alias:
vuln-reachability -t examples/topology.json -f examples/findings.json
```

Output formats: `table` (default), `json`, `jsonl` (NDJSON), `csv`, `sarif` (SARIF 2.1.0), `html` (self-contained report), `markdown` (GFM table), `junit` (JUnit XML). Use `-o` / `--output` to write to a file. Use `--min-priority` and `--limit` to focus the report. Use `--explain` for per-finding rationales. Use `--summary` for band counts on stderr. Use `--fail-under SCORE` as a CI gate. Use `--show-title` to include titles in the table. Use `--only-kev` to filter to KEV findings. Use `--only-reachable` to drop findings on unreachable assets. Use `--max-hops N` to keep findings within N hops of ingress. Use `--band critical` (repeatable) to filter by priority band. Use `--min-epss P` to keep findings with EPSS at or above P. Use `--asset ID` (repeatable) to scope to specific assets. Use `--cve CVE` (repeatable) to filter by CVE id. Use `--strict` to fail on edges that reference unknown assets. Use `--quiet` / `-q` to suppress non-error warnings. Use `--min-base` to filter on raw CVSS-like base score. Use `--sort hops` (or base/asset/cve) to reorder results. Use `--dedupe` to keep the top finding per CVE+asset. Use `--tag TAG` (repeatable) to keep findings on tagged assets. Use `--asset-report` for a per-asset reachability inventory (no findings file).

Input field reference: [docs/schemas/README.md](docs/schemas/README.md).

See [examples/README.md](examples/README.md) for the sample topology narrative.

## Status

**v0.1.8** — core library, CLI (table / JSON / JSONL / CSV / SARIF / HTML / Markdown / JUnit), optional EPSS, KEV, filters, examples, tests, CI `@v0.3.0`, ADR-001–004. See [CHANGELOG.md](CHANGELOG.md).

## Docs

- [AGENTS.md](AGENTS.md) — human and agent guardrails
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose changes
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CHANGELOG.md](CHANGELOG.md) — release notes
- [docs/architecture/](docs/architecture/) — system shape and Mermaid diagram
- [docs/schemas/](docs/schemas/) — topology and findings field reference
- [docs/usage/](docs/usage/) — cookbook recipes
- [docs/references/](docs/references/) — background links
- [docs/security/security.md](docs/security/security.md) — security posture
- [docs/development/development.md](docs/development/development.md) — contributor workflow and CI

## License

[MIT](LICENSE)
