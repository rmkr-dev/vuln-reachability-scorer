import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.loaders import load_findings, load_topology


def test_duplicate_asset_ids_rejected(tmp_path: Path):
    p = tmp_path / "t.json"
    p.write_text(
        json.dumps(
            {
                "assets": [
                    {"id": "a", "name": "A"},
                    {"id": "a", "name": "A2"},
                ],
                "edges": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate asset"):
        load_topology(p)


def test_duplicate_finding_ids_rejected(tmp_path: Path):
    p = tmp_path / "f.json"
    p.write_text(
        json.dumps(
            [
                {"id": "f", "asset_id": "a", "base_score": 1.0},
                {"id": "f", "asset_id": "b", "base_score": 2.0},
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate finding"):
        load_findings(p)
