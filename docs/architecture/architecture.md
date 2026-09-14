# Architecture

## Current state

`vuln-reachability-scorer` is a **local Python CLI** packaged under `src/vuln_reachability_scorer/`. There is no networked service, datastore, or cloud API in this repository.

Data flow:

1. **Topology JSON** — `assets` and directed `edges` (`loaders.load_topology`).
2. **Findings JSON** — vulnerability records bound to an asset id with a numeric `base_score` (`loaders.load_findings`).
3. **Graph** — adjacency + shortest hop distance from ingress nodes (`graph.py`).
4. **Scoring** — `priority = base_score × reachability_factor × exposure_factor` (`scoring.py`; see [ADR-001](../decisions/ADR-001-scoring-model.md)).
5. **CLI** — `vrscore` / `vuln-reachability` prints a ranked table, JSON, CSV, SARIF 2.1.0, or HTML (`cli.py`, `sarif.py`, `html_report.py`). Optional finding `epss` is applied in scoring ([ADR-004](../decisions/ADR-004-epss-factor.md)).

Sample inputs live under `examples/`. CI calls the reusable Python workflow `@v0.3.0`.

## Module map

| Module | Role |
| --- | --- |
| `models.py` | `Asset`, `Edge`, `Finding`, `ScoredFinding` |
| `graph.py` | Adjacency, ingress detection, hop distance |
| `scoring.py` | Factor tables, KEV/EPSS multipliers, and `score_findings` |
| `loaders.py` | JSON → models |
| `sarif.py` | SARIF 2.1.0 document builder |
| `html_report.py` | Self-contained HTML report |
| `asset_report.py` | Per-asset reachability inventory |
| `explain.py` | Human-readable score rationales |
| `paths.py` | Shortest ingress→asset path reconstruction |
| `summary.py` | Priority band aggregates |
| `cli.py` | argparse entrypoint |

## CI and hygiene

| Surface | Role |
| --- | --- |
| `.github/workflows/ci.yml` | Calls reusable `python-ci.yml@v0.3.0` |
| `.github/dependabot.yml` | Weekly Actions + pip |
| `.github/CODEOWNERS` | `@rmkr-dev` |
| `SECURITY.md` | Private advisory reporting |

## Boundaries

| In | Out |
| --- | --- |
| Offline scoring from user-supplied JSON | Live scanner / CVE feed pulls |
| Explicit, documented formula ([ADR-001](../decisions/ADR-001-scoring-model.md)) | Opaque ML ranking |
| stdlib only at runtime | Node/npm, SaaS dashboards |

## Related

- [architecture-diagram.md](architecture-diagram.md)
- [../security/security.md](../security/security.md)
- [../development/development.md](../development/development.md)
- [../decisions/ADR-001-scoring-model.md](../decisions/ADR-001-scoring-model.md)
- [../decisions/ADR-002-tag-exposure-boosts.md](../decisions/ADR-002-tag-exposure-boosts.md)
- [../decisions/ADR-004-epss-factor.md](../decisions/ADR-004-epss-factor.md)
- [../usage/README.md](../usage/README.md)
- [../references/README.md](../references/README.md)
