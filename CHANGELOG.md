# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Additional edge-case tests for path cycles, KEV clamp, and empty summary.
- Nothing yet since the last release.

## [0.1.3] - 2026-09-14

### Added

- Optional finding `kev: true` applies a 1.15 Known Exploited Vulnerability multiplier (clamped at 10.0) ([ADR-003](docs/decisions/ADR-003-kev-multiplier.md)).
- CSV output for `--asset-report`.
- `--summary` aggregate band counts on stderr after scoring.
- `--fail-under SCORE` CI gate (exit 1 when any priority >= SCORE).

## [0.1.2] - 2026-09-14

### Added

- `--asset-report` per-asset reachability inventory (topology only).
- Tag-based exposure boosts (`pii` / `identity` / `secrets` defaults; override via topology `tag_boosts`) ([ADR-002](docs/decisions/ADR-002-tag-exposure-boosts.md)).
- `--explain` human-readable score rationales.
- Warnings (and `--strict` errors) when topology edges reference unknown asset ids.
- Usage cookbook under `docs/usage/`.

## [0.1.1] - 2026-09-14

### Added

- SARIF 2.1.0 output via `--format sarif` (`vuln_reachability_scorer.sarif`).
- CSV output via `--format csv`.
- `--output` / `-o` to write results to a file.
- `--min-priority` to filter results below a priority threshold.
- `--limit` to cap the number of emitted results after sorting/filtering.
- Informal input field reference under `docs/schemas/`.
- Duplicate asset/finding id validation in loaders.
- Additional unit tests (graph, loaders, SARIF, file output, filters, examples smoke tests).

## [0.1.0] - 2026-09-14

### Added

- Python 3.12 package `vuln-reachability-scorer` with CLI entry points `vrscore` and `vuln-reachability`.
- Domain models for `Asset`, `Edge`, `Finding`, and `ScoredFinding`.
- Reachability-aware scoring: `priority = base_score × reachability_factor × exposure_factor` ([ADR-001](docs/decisions/ADR-001-scoring-model.md)).
- Example topology and findings under `examples/`.
- Unit tests for models, scoring, and CLI.
- GitHub Actions CI via `rmkr-dev/gha-reusable-workflows` `python-ci.yml@v0.2.0`.
- Dependabot, CODEOWNERS, SECURITY.md, PR template, and foundation docs.

[Unreleased]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rmkr-dev/vuln-reachability-scorer/releases/tag/v0.1.0
