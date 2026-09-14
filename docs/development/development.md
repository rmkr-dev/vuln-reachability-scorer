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

## Workflow

1. Branch from `main`.
2. Implement one slice per PR (see [AGENTS.md](../../AGENTS.md)).
3. Keep docs, tests, and CI in sync with behavior.
4. Conventional commits; open a PR with clear in/out of scope.

## Repo hygiene

- Respect `.editorconfig` / `.gitattributes`
- No Node/npm
- No secrets in fixtures
