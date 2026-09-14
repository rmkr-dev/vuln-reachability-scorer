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

See [ADR-001](docs/decisions/ADR-001-scoring-model.md) and `src/vuln_reachability_scorer/scoring.py`. Findings may set `kev: true` for a 1.15 Known Exploited Vulnerability multiplier (clamped at 10).

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
vrscore -t examples/topology.json -f examples/findings.json --format csv -o scores.csv
vrscore -t examples/topology.json -f examples/findings.json --format sarif -o results.sarif
vrscore -t examples/topology.json -f examples/findings.json --min-priority 4.0 --limit 20
vrscore -t examples/topology.json -f examples/findings.json --explain
vrscore -t examples/topology.json -f examples/findings.json --summary
vrscore -t examples/topology.json -f examples/findings.json --fail-under 7
vrscore -t examples/topology.json --asset-report
# alias:
vuln-reachability -t examples/topology.json -f examples/findings.json
```

Output formats: `table` (default), `json`, `csv`, `sarif` (SARIF 2.1.0). Use `-o` / `--output` to write to a file. Use `--min-priority` and `--limit` to focus the report. Use `--explain` for per-finding rationales. Use `--summary` for band counts on stderr. Use `--fail-under SCORE` as a CI gate. Use `--show-title` to include titles in the table. Use `--strict` to fail on edges that reference unknown assets. Use `--asset-report` for a per-asset reachability inventory (no findings file).

Input field reference: [docs/schemas/README.md](docs/schemas/README.md).

See [examples/README.md](examples/README.md) for the sample topology narrative.

## Status

**v0.1.3** — core library, CLI (table / JSON / CSV / SARIF), filters, file output, examples, tests, CI, and ADR-001. See [CHANGELOG.md](CHANGELOG.md).

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
