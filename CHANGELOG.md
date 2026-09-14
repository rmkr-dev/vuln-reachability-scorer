# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `build_adjacency` collapses duplicate parallel edges; large-graph performance tests guard O(V+E) scoring.
- Pin CI reusable workflow to `rmkr-dev/gha-reusable-workflows` `python-ci.yml@v0.4.0` (compatible inputs; setup composite moves to `@v0.3.0`).

### Added

- Usage cookbook: triage playbook and GitHub Actions gate recipe using `--config` + SARIF/`--fail-under`.
- `--config` / `-c` JSON or TOML CLI defaults ([ADR-006](docs/decisions/ADR-006-config-file.md)); example `examples/vrscore.toml` / `examples/vrscore.json`.
- `all_hop_distances` / `all_shortest_paths` precompute reachability in one multi-source BFS; scoring, `--asset-report`, and `--explain` use them (O(V+E) instead of per-finding BFS).

## [0.1.10] - 2026-09-14

### Fixed

- ADR index table includes ADR-005 as a proper Accepted row.

### Added

- [ADR-005](docs/decisions/ADR-005-triage-filter-order.md) documents CLI triage filter application order.
- `--asset-report` honors `--limit`, `--max-hops`, and `--only-reachable`.
- Usage and development docs for CLI exit codes (`0` / `1` / `2`).

## [0.1.9] - 2026-09-14

### Added

- Example findings include duplicate-CVE and low-base rows for filter demos; examples README lists triage recipes.
- `--format tsv` tab-separated values for findings and `--asset-report`.
- `--tag TAG` (repeatable, OR, case-insensitive) to keep findings on assets with matching tags.

## [0.1.8] - 2026-09-14

### Added

- `--dedupe` keeps the highest-priority finding per `(cve_id, asset_id)`.
- `--format junit` JUnit XML report (findings with priority >= 7.0 marked as failures).
- `--sort priority|base|hops|asset|cve` to reorder results (default remains priority).
- `--min-base` to omit findings whose `base_score` is below a threshold.
- `--quiet` / `-q` to suppress non-error stderr warnings (edge endpoint warnings).

## [0.1.7] - 2026-09-14

### Added

- `--format jsonl` newline-delimited JSON for findings and `--asset-report`.
- `--summary` now reports `epss=` count of findings that supplied an EPSS value.
- `--cve CVE` (repeatable, case-insensitive) to keep findings matching CVE id(s).
- `--asset ID` (repeatable) to keep findings for selected asset id(s).
- `--min-epss P` to keep findings with `epss >= P` (omitters dropped).
- `--band BAND` (repeatable) to keep findings in priority bands matching `--summary` thresholds.
- `--max-hops N` to keep findings with hop_distance <= N (excludes unreachable).
- `--only-reachable` to keep findings on assets reachable from an ingress node.
- `--format markdown` GitHub-flavored table report (findings and `--asset-report`).

## [0.1.6] - 2026-09-14

### Added

- Optional finding `epss` (FIRST EPSS probability in `[0, 1]`) applies a `1 + 0.20 × epss` multiplier after KEV, clamped at 10.0 ([ADR-004](docs/decisions/ADR-004-epss-factor.md)).
- `--format html` self-contained report (findings and `--asset-report`).
- Clearer loader and CLI errors (file kind, path, JSON line/column, indexed missing fields).
- Topology graph edge-case tests (self-loops, diamonds, multi-ingress, reverse-only, duplicate edges, 5-hop chains).
- Pin CI to `rmkr-dev/gha-reusable-workflows` `python-ci.yml@v0.3.0`.
- Architecture diagram refresh and usage flag cheatsheet.

## [0.1.5] - 2026-09-14

### Added

- `--only-kev` to keep known-exploited findings only.

## [0.1.4] - 2026-09-14

### Added

- `--explain` includes reconstructed ingress→asset shortest path.
- Additional edge-case tests for path cycles, KEV clamp, and empty summary.
- `--show-title` adds a TITLE column to table output.
- CISA KEV link in docs/references.

## [0.1.3] - 2026-09-14

### Added

- Optional finding `kev: true` applies a 1.15 Known Exploited Vulnerability multiplier (clamped at 10.0) ([ADR-003](docs/decisions/ADR-003-kev-multiplier.md)).
- CSV output for `--asset-report`.
- `--summary` aggregate band counts on stderr after scoring.
- `--fail-under SCORE` CI gate (exit 1 when any priority >= SCORE).

## [0.1.2] - 2026-09-14

### Added

- `--asset-report` per-asset reachability inventory (topology only).
- Tag-based exposure boosts ([ADR-002](docs/decisions/ADR-002-tag-exposure-boosts.md)).
- `--explain`, `--strict`, usage cookbook.

## [0.1.1] - 2026-09-14

### Added

- SARIF/CSV formats, `--output`, `--min-priority`, `--limit`, schemas, validation, tests.

## [0.1.0] - 2026-09-14

### Added

- Initial package, scoring formula ([ADR-001](docs/decisions/ADR-001-scoring-model.md)), CLI, examples, CI.

[Unreleased]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.10...HEAD
[0.1.10]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rmkr-dev/vuln-reachability-scorer/releases/tag/v0.1.0
