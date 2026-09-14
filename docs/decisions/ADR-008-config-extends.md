# ADR-008: Config file `extends`

- **Status:** Accepted
- **Date:** 2026-09-14

## Context

Operators want shared estate paths (`topology` / `findings`) with specialized triage vs CI overlays without duplicating keys or adding CLI flags ([ADR-007](ADR-007-config-first-cli.md)).

## Decision

- Support optional `extends` (string path) in JSON/TOML configs, resolved relative to the extending file.
- Load the base first (recursively), then overlay keys from the child; list values **replace** (do not concatenate).
- Detect cycles and reject non-string / empty `extends`.
- `extends` is reserved and not a CLI flag destination.

## Consequences

- Examples can share `vrscore-base.toml` from triage/CI configs.
- Documented in the config schema; unknown other keys remain errors.
- Extends chains are capped at depth 8 (`MAX_EXTENDS_DEPTH`) in addition to cycle detection.
