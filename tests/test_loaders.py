import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.loaders import load_findings, load_topology


def test_load_topology_and_findings(tmp_path: Path):
    topo = {
        "assets": [{"id": "a", "name": "A", "criticality": 0.2}],
        "edges": [{"source": "a", "target": "a"}],
    }
    findings = [{"id": "f", "asset_id": "a", "cve_id": "CVE-1", "base_score": 3.0}]
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assets, edges = load_topology(t)
    assert len(assets) == 1 and len(edges) == 1
    assert load_findings(f)[0].cve_id == "CVE-1"


def test_load_findings_wrapped_object(tmp_path: Path):
    f = tmp_path / "f.json"
    f.write_text(
        json.dumps({"findings": [{"id": "f", "asset_id": "a", "base_score": 1.0}]}),
        encoding="utf-8",
    )
    assert load_findings(f)[0].id == "f"


def test_load_topology_rejects_bad_root(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        load_topology(p)
