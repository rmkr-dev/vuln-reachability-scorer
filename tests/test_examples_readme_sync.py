"""Guard: examples/README.md indexes every shipped vrscore* config."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
README = EXAMPLES / "README.md"


def _shipped_configs() -> list[str]:
    files = []
    for p in sorted(EXAMPLES.rglob("vrscore*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in {".toml", ".json"}:
            continue
        rel = p.relative_to(EXAMPLES).as_posix()
        files.append(rel)
    return files


def test_examples_readme_lists_every_vrscore_config():
    text = README.read_text(encoding="utf-8")
    missing = [rel for rel in _shipped_configs() if rel not in text]
    assert not missing, f"examples/README.md missing config(s): {missing}"
