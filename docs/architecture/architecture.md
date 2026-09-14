# Architecture

## Current state

`vuln-reachability-scorer` is a **local Python CLI**. There is no networked service, datastore, or cloud API in this repository.

Intended data flow (library and CLI land in a follow-up PR; this document describes the target shape that the foundation commits toward):

1. **Topology JSON** — assets (hosts, services, data stores) and directed edges (allowed reachability).
2. **Findings JSON** — vulnerability records bound to an asset id, each with a numeric base score (typically CVSS base).
3. **Scoring** — for each finding, derive a reachability factor from graph distance to an ingress / internet-facing edge, and an exposure factor from asset criticality; combine with the documented formula.
4. **Output** — ranked priority scores on stdout (and later optional JSON / SARIF).

Until the package exists, this repo holds documentation and repo hygiene only. Do not invent runtime behavior in docs that is not implemented.

## Boundaries

| In | Out |
| --- | --- |
| Offline scoring from user-supplied JSON | Live scanner / CVE feed pulls |
| Explicit, documented formula | Opaque ML ranking |
| stdlib + small Python deps | Node/npm, SaaS dashboards |

## Related

- [architecture-diagram.md](architecture-diagram.md)
- [../security/security.md](../security/security.md)
- [../development/development.md](../development/development.md)
