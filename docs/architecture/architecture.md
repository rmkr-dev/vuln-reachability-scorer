# Architecture

## Current state

`vuln-reachability-scorer` is a **local Python CLI** packaged under `src/vuln_reachability_scorer/`. There is no networked service, datastore, or cloud API in this repository.

Data flow:

1. **Topology JSON** — `assets` and directed `edges` (`loaders.load_topology`).
2. **Findings JSON** — vulnerability records bound to an asset id with a numeric `base_score` (`loaders.load_findings`).
3. **Graph** — adjacency + shortest hop distance from ingress nodes (`graph.py`).
4. **Scoring** — `priority = base_score × reachability_factor × exposure_factor` (`scoring.py`).
5. **CLI** — `vrscore` / `vuln-reachability` prints a ranked table or JSON (`cli.py`).

## Module map

| Module | Role |
| --- | --- |
| `models.py` | `Asset`, `Edge`, `Finding`, `ScoredFinding` |
| `graph.py` | Adjacency, ingress detection, hop distance |
| `scoring.py` | Factor tables and `score_findings` |
| `loaders.py` | JSON → models |
| `cli.py` | argparse entrypoint |

## Boundaries

| In | Out |
| --- | --- |
| Offline scoring from user-supplied JSON | Live scanner / CVE feed pulls |
| Explicit, documented formula | Opaque ML ranking |
| stdlib only at runtime | Node/npm, SaaS dashboards |

## Related

- [architecture-diagram.md](architecture-diagram.md)
- [../security/security.md](../security/security.md)
- [../development/development.md](../development/development.md)
- Scoring factor tables are documented in the `scoring.py` module docstring
