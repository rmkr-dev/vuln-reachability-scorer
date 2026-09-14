# vuln-reachability-scorer

Python CLI that scores CVEs by **reachability and exposure** (topology), not raw CVSS alone.

Security scanners flood teams with CVSS numbers. Two findings with the same CVSS are not equal if one sits on an internet-facing edge and the other is three hops deep behind a bastion. This tool multiplies a base severity by topology-derived factors so prioritization matches how an attacker would actually move.

## Status

Foundation docs and repo hygiene are in place. The scoring library, CLI, examples, and CI ship in follow-up PRs.

## Planned shape

| Piece | Role |
| --- | --- |
| Topology input | Assets + directed edges (who can reach whom) |
| Findings input | CVE / finding records bound to assets, with a base score |
| Scoring | `priority = base_score × reachability_factor × exposure_factor` |
| CLI | Load inputs, emit ranked scores |

Exact formula and factors will be locked in an ADR when the library lands.

## Docs

- [AGENTS.md](AGENTS.md) — human and agent guardrails
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose changes
- [docs/architecture/](docs/architecture/) — system shape and Mermaid diagram
- [docs/security/security.md](docs/security/security.md) — security posture
- [docs/development/development.md](docs/development/development.md) — contributor workflow

## License

[MIT](LICENSE)
