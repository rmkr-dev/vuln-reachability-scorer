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
```

## CI

Pull requests and pushes to `main` run [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), which calls the reusable workflow `rmkr-dev/gha-reusable-workflows/.github/workflows/python-ci.yml@v0.3.0` (Python 3.12, compile/lint, pytest).

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
