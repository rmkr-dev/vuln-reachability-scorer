# vuln-reachability-scorer

Python CLI that scores CVEs by **reachability and exposure** (topology), not raw CVSS alone.

Security scanners flood teams with CVSS numbers. Two findings with the same CVSS are not equal if one sits on an internet-facing edge and the other is three hops deep behind a bastion. This tool multiplies a base severity by topology-derived factors so prioritization matches how an attacker would actually move.

## Status

Early scaffolding. Foundation docs ship first; the scoring library and CLI land in follow-up PRs. See [AGENTS.md](AGENTS.md) for guardrails.

## Planned shape

| Piece | Role |
| --- | --- |
| Topology input | Assets + directed edges (who can reach whom) |
| Findings input | CVE / finding records bound to assets, with a base score |
| Scoring | `priority = base_score × reachability_factor × exposure_factor` |
| CLI | Load inputs, emit ranked scores |

Exact formula and factors will be documented under `docs/` when the library lands.

## Docs

- [AGENTS.md](AGENTS.md) — human and agent guardrails
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose changes
- [docs/architecture/](docs/architecture/) — system shape (when present)
- [docs/security/](docs/security/) — security posture (when present)
- [docs/development/](docs/development/) — local workflow (when present)

## License

[MIT](LICENSE)
