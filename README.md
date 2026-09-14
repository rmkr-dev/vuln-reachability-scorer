# vuln-reachability-scorer

Python CLI that scores CVEs by **reachability and exposure** (topology), not raw CVSS alone.

Security scanners flood teams with CVSS numbers. Two findings with the same CVSS are not equal if one sits on an internet-facing edge and the other is three hops deep behind a bastion. This tool multiplies a base severity by topology-derived factors so prioritization matches how an attacker would actually move.

## Formula

```text
priority_score = round(base_score × reachability_factor × exposure_factor, 2)
```

- **base_score** — CVSS-like severity in `[0, 10]` from the finding
- **reachability_factor** — from shortest hop distance to an ingress / internet-facing asset (`1.0` at ingress → `0.1` if unreachable)
- **exposure_factor** — asset `criticality` in `[0, 1]`

Factor tables live in `src/vuln_reachability_scorer/scoring.py`.

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
# alias:
vuln-reachability -t examples/topology.json -f examples/findings.json
```

See [examples/README.md](examples/README.md) for the sample topology narrative.

## Status

Core library, CLI, unit tests, sample inputs, and GitHub Actions CI (reusable Python workflow `@v0.2.0`) are present. An ADR for the scoring model and a `v0.1.0` tag follow.

## Docs

- [AGENTS.md](AGENTS.md) — human and agent guardrails
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose changes
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [docs/architecture/](docs/architecture/) — system shape and Mermaid diagram
- [docs/security/security.md](docs/security/security.md) — security posture
- [docs/development/development.md](docs/development/development.md) — contributor workflow and CI

## License

[MIT](LICENSE)
