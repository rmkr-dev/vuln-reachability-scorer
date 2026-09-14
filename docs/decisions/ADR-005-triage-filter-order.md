# ADR-005: Triage filter application order

- Status: Accepted
- Date: 2026-09-14

## Context

`vrscore` gained many post-scoring CLI filters (`--only-kev`, `--only-reachable`, `--max-hops`, `--min-hops`, `--band`, `--min-epss`, `--asset`, `--cve`, `--tag`, `--exclude-tag`, `--min-base`, `--min-priority`, `--dedupe`, `--sort`, `--limit`). Reviewers need a stable, documented order so combining flags is predictable.

## Decision

After `score_findings` (already sorted by priority desc), apply filters in this order:

1. `--only-kev`
2. `--only-reachable`
3. `--max-hops`
4. `--min-hops`
5. `--band`
6. `--min-epss`
7. `--asset`
8. `--cve`
9. `--tag`
10. `--exclude-tag`
11. `--min-base`
12. `--min-priority`
13. `--dedupe`
14. `--sort` (skipped when `priority`, which is the default from scoring)
15. `--limit`

`--asset-report` applies the subset that makes sense without findings: `--max-hops`, `--only-reachable`, then `--limit`.

## Consequences

- Operators can reason about compositions (e.g. `--band high --limit 10` caps after band filtering).
- Changing order is a breaking behavioral change and needs a new ADR revision.
- `--fail-under` and `--summary` run on the post-filter result set.
