# ADR-006: Optional CLI config file

- **Status:** Accepted
- **Date:** 2026-09-14

## Context

Operators repeat long `vrscore` flag sets across local triage and CI. We want a checked-in defaults file without adding dependencies or surprising auto-discovery.

## Decision

- Add `--config` / `-c` pointing at a `.json` or `.toml` file (stdlib `json` / `tomllib` only).
- Keys mirror argparse destinations (`topology`, `findings`, `format`, `band`, …). Unknown keys are errors.
- Precedence: built-in defaults < config file < explicit CLI flags.
- Relative `topology` / `findings` / `output` paths resolve against the config file's directory.
- List flags (`band`, `asset`, `cve`, `tag`) use config values only when the corresponding CLI flag is absent (argparse `append` would otherwise concatenate).
- No cwd auto-discovery in this release — config is opt-in via `--config`.
- `findings` may be a string or a list of paths (merged in order), matching repeatable `-f`.

## Consequences

- Examples ship `examples/vrscore.toml` and `examples/vrscore.json`.
- Toward v0.2.0 this is the primary “project defaults” mechanism; auto-discovery can be a later ADR if needed.
