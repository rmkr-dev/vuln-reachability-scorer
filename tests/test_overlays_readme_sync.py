"""Guard: examples/overlays/README.md indexes every overlay vrscore* config."""

from __future__ import annotations

from pathlib import Path

OVERLAYS = Path(__file__).resolve().parents[1] / "examples" / "overlays"
README = OVERLAYS / "README.md"


def test_overlays_readme_lists_every_vrscore_config():
    text = README.read_text(encoding="utf-8")
    missing = []
    for p in sorted(OVERLAYS.glob("vrscore*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in {".toml", ".json"}:
            continue
        if p.name not in text:
            missing.append(p.name)
    assert not missing, f"overlays/README.md missing config(s): {missing}"
