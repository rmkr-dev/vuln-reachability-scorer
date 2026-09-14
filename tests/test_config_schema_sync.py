"""Guard: docs/schemas/vrscore.schema.json properties stay aligned with CONFIG_KEYS + extends."""

from __future__ import annotations

import json
from pathlib import Path

from vuln_reachability_scorer.config import (
    ALLOWED_BANDS,
    ALLOWED_FORMATS,
    ALLOWED_SORTS,
    CONFIG_KEYS,
)


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


def test_schema_enums_match_allowed_sets():
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "docs" / "schemas" / "vrscore.schema.json").read_text(encoding="utf-8"))
    props = schema["properties"]
    assert set(props["format"]["enum"]) == set(ALLOWED_FORMATS)
    assert set(props["sort"]["enum"]) == set(ALLOWED_SORTS)
    assert set(props["band"]["items"]["enum"]) == set(ALLOWED_BANDS)
