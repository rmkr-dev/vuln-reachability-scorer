"""Every shipped vrscore*.toml/json under examples/ must load_config cleanly."""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_reachability_scorer.config import load_config

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.mark.parametrize(
    "name",
    sorted(
        p.name
        for p in EXAMPLES.rglob("vrscore*")
        if p.suffix in {".toml", ".json"} and p.is_file()
    ),
)
def test_example_config_loads(name: str):
    path = next(p for p in EXAMPLES.rglob(name) if p.is_file())
    cfg = load_config(path)
    assert isinstance(cfg, dict)
    # path keys from base should be absolute after defining-file resolve
    if "topology" in cfg:
        assert Path(cfg["topology"]).is_absolute()
