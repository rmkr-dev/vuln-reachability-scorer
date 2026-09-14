import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_asset_report_limit_and_max_hops(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "edge", "ingress": True, "criticality": 0.5},
            {"id": "app", "ingress": False, "criticality": 0.5},
            {"id": "db", "ingress": False, "criticality": 0.5},
            {"id": "island", "ingress": False, "criticality": 0.5},
        ],
        "edges": [
            {"source": "edge", "target": "app"},
            {"source": "app", "target": "db"},
        ],
    }
    t = tmp_path / "t.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    assert main(["-t", str(t), "--asset-report", "--format", "json", "--max-hops", "1"]) == 0
    ids = [a["asset_id"] for a in json.loads(capsys.readouterr().out)["assets"]]
    assert set(ids) == {"edge", "app"}

    assert main(["-t", str(t), "--asset-report", "--format", "json", "--only-reachable", "--limit", "2"]) == 0
    assets = json.loads(capsys.readouterr().out)["assets"]
    assert len(assets) == 2
    assert all(a["hop_distance"] is not None for a in assets)
