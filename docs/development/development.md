# Development

## Prerequisites

- Python 3.12+
- A virtualenv

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Local checks

```bash
pytest
python -m compileall -q src
vrscore --topology examples/topology.json --findings examples/findings.json
vrscore --config examples/vrscore.toml --summary
```

## CI

Pull requests and pushes to `main` run [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), which calls the reusable workflow `rmkr-dev/gha-reusable-workflows/.github/workflows/python-ci.yml@v0.4.0` (Python 3.12, compile/lint, pytest).

Dependabot watches GitHub Actions and pip dependencies weekly (`.github/dependabot.yml`).

## Workflow

1. Branch from `main`.
2. Implement one slice per PR (see [AGENTS.md](../../AGENTS.md)).
3. Keep docs, tests, and CI in sync with behavior.
4. Conventional commits; open a PR with clear in/out of scope.

## Repo hygiene

- Respect `.editorconfig` / `.gitattributes`
- No Node/npm
- No secrets in fixtures
- Default code owner: `@rmkr-dev` (`.github/CODEOWNERS`)

## Optional scoring gate

```bash
vrscore -t examples/topology.json -f examples/findings.json --fail-under 9
```

## Exit codes

See [usage cookbook](../usage/README.md#exit-codes) for `0` / `1` / `2` semantics used by CI gates and loaders.

## Typing

The package includes `src/vuln_reachability_scorer/py.typed` (PEP 561) so type checkers can use inline annotations when the wheel/sdist is installed.

## Config validation tests

Config loading is covered without adding CLI flags ([ADR-007](../decisions/ADR-007-config-first-cli.md)):

| Module | Focus |
| --- | --- |
| `tests/test_config.py` | Load TOML/JSON, CLI override, relative paths |
| `tests/test_config_validation.py` | Types, parse errors, merge helpers, exit 2 |
| `tests/test_config_enums.py` | `format` / `sort` / `band` choices |
| `tests/test_config_ranges.py` | Numeric ranges |
| `tests/test_config_hop_window.py` | `min_hops` ≤ `max_hops` |
| `tests/test_config_extends.py` | `extends` overlay, cycles, max depth, hop-window merge, defining-file paths, examples |
| `tests/test_config_cli_enum_sync.py` | ALLOWED_* stays synced with argparse |
| `tests/test_config_schema_sync.py` | `vrscore.schema.json` properties ↔ `CONFIG_KEYS` + `extends` |
| `tests/test_example_config_extends_load.py` | Every `examples/**/vrscore*` config loads via `load_config` |
| `tests/test_examples_readme_sync.py` | `examples/README.md` lists every shipped `vrscore*` config |
| `tests/test_overlays_readme_sync.py` | `examples/overlays/README.md` lists every overlay `vrscore*` |
| `tests/test_extends_docs_sync.py` | Docs mention `MAX_EXTENDS_DEPTH` matching `config.py` |
| `tests/test_example_configs.py` | Shipped `examples/vrscore-*.toml` load/run |

Prefer growing these tests when changing `config.py`.

## Config-first local runs

Set `VRSCORE_CONFIG` to an example overlay (see [usage cookbook](../usage/README.md#config-file-defaults)) instead of inventing new CLI flags.
