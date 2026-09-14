# ADR-007: Prefer config files over new CLI flags

- **Status:** Accepted
- **Date:** 2026-09-14

## Context

The CLI acquired many triage filters (`--band`, `--tag`, excludes, hop window, …). Long flag chains are hard to review in CI and invite “one more flag” PRs. ADR-006 already provides JSON/TOML defaults.

## Decision

- Encode stable project defaults and filter sets in `--config` / `VRSCORE_CONFIG` (and ship them under `examples/vrscore-*.toml`).
- Grow the [usage cookbook](../usage/README.md) and example configs before adding a new argparse flag.
- Add a new CLI flag only when: (a) it cannot be expressed as a config key mirroring an existing destination, or (b) an ADR documents a new capability that needs a first-class switch.
- Keep validating config enums/ranges in `config.py` so bad checked-in configs fail at load (exit 2).

## Consequences

- AGENTS.md and README point operators at config-first recipes.
- Flag cheatsheet remains in the cookbook; README stays short.
- Toward v0.3.0, invest in config ergonomics and tests—not flag surface area.
