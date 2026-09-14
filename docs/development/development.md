# Development

## Prerequisites (when the package exists)

- Python 3.12+
- A virtualenv
- `pip install -e ".[dev]"` from the repo root

Foundation commits may land before `pyproject.toml` exists. Do not document install steps as current until the package is present.

## Workflow

1. Branch from `main`.
2. Implement one slice per PR (see [AGENTS.md](../../AGENTS.md)).
3. Keep docs, tests, and CI in sync with behavior.
4. Conventional commits; open a PR with clear in/out of scope.

## Local checks (planned)

```text
pytest
python -m compileall -q src
```

Exact commands will match `pyproject.toml` and CI once those land.

## Repo hygiene already expected

- `.editorconfig` / `.gitattributes` when present — respect them
- No Node/npm
- No secrets in fixtures
