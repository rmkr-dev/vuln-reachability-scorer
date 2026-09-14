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
# Prefer a config file over long flag chains (ADR-006)
vrscore --config examples/vrscore.toml
vrscore -c examples/vrscore-triage.toml
vrscore -c examples/vrscore-ci.toml
# Explicit paths still work
vrscore -t examples/topology.json -f examples/findings.json --explain --summary
vrscore -t examples/topology.json --asset-report
# alias:
vuln-reachability -c examples/vrscore.toml
```

Output formats: `table` (default), `json`, `jsonl`, `csv`, `tsv`, `sarif`, `html`, `markdown`, `junit`. Put repeatable filters in `--config` / `VRSCORE_CONFIG`; override one-off knobs on the CLI. Full recipes: [docs/usage/](docs/usage/) (config-first triage, Actions gate). Flag cheatsheet lives there too — this README stays short on purpose.

Input field reference: [docs/schemas/README.md](docs/schemas/README.md).

See [examples/README.md](examples/README.md) for the sample topology narrative and config samples.

## Status

**v0.3.2** — extends hop-window merge validation, defining-file path resolve, layered/cross-dir examples. See [CHANGELOG.md](CHANGELOG.md).

## Docs

- [AGENTS.md](AGENTS.md) — human and agent guardrails
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose changes
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CHANGELOG.md](CHANGELOG.md) — release notes
- [docs/architecture/](docs/architecture/) — system shape and Mermaid diagram
- [docs/schemas/](docs/schemas/) — topology, findings, and [config](docs/schemas/config.md) field reference
- [docs/usage/](docs/usage/) — cookbook recipes (triage playbook, Actions gate, config)
- [docs/references/](docs/references/) — background links
- [docs/security/security.md](docs/security/security.md) — security posture
- [docs/development/development.md](docs/development/development.md) — contributor workflow and CI

## License

[MIT](LICENSE)
