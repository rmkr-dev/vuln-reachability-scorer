"""Guard: docs/schemas/vrscore.schema.json properties stay aligned with CONFIG_KEYS + extends."""

from __future__ import annotations

import json
from pathlib import Path

from vuln_reachability_scorer.config import CONFIG_KEYS


def test_schema_properties_match_config_keys():
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "docs" / "schemas" / "vrscore.schema.json").read_text(encoding="utf-8"))
    props = set(schema["properties"])
    expected = set(CONFIG_KEYS) | {"extends"}
    assert props == expected, (
        f"schema extras={sorted(props - expected)} "
        f"missing={sorted(expected - props)}"
    )
    assert schema.get("additionalProperties") is False
