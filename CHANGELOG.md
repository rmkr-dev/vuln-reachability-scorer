# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Topology graph edge-case tests (self-loops, diamonds, multi-ingress, reverse-only, duplicate edges, 5-hop chains).
- Clearer loader and CLI errors (file kind, path, JSON line/column, indexed missing fields).
- `--format html` self-contained report (findings and `--asset-report`).
- Optional finding `epss` (FIRST EPSS probability in `[0, 1]`) applies a `1 + 0.20 × epss` multiplier after KEV, clamped at 10.0 ([ADR-004](docs/decisions/ADR-004-epss-factor.md)).
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

[Unreleased]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/rmkr-dev/vuln-reachability-scorer/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rmkr-dev/vuln-reachability-scorer/releases/tag/v0.1.0
