"""Docs mention MAX_EXTENDS_DEPTH consistent with config.py."""

from __future__ import annotations

import json
from pathlib import Path

from vuln_reachability_scorer.config import MAX_EXTENDS_DEPTH


def test_docs_mention_max_extends_depth():
    root = Path(__file__).resolve().parents[1]
    schema = (root / "docs" / "schemas" / "config.md").read_text(encoding="utf-8")
    adr = (root / "docs" / "decisions" / "ADR-008-config-extends.md").read_text(encoding="utf-8")
    assert str(MAX_EXTENDS_DEPTH) in schema
    assert "MAX_EXTENDS_DEPTH" in schema or str(MAX_EXTENDS_DEPTH) in schema
    assert str(MAX_EXTENDS_DEPTH) in adr


def test_schema_json_extends_mentions_max_depth():
    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "docs" / "schemas" / "vrscore.schema.json").read_text(encoding="utf-8")
    )
    desc = schema["properties"]["extends"].get("description", "")
    assert "MAX_EXTENDS_DEPTH" in desc
    assert str(MAX_EXTENDS_DEPTH) in desc
