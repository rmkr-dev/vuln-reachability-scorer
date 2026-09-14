import csv
import json
from io import StringIO
from pathlib import Path

from vuln_reachability_scorer.cli import main


def test_asset_report_csv(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "a", "name": "A", "ingress": True, "criticality": 0.5, "tags": ["prod"]},
            {"id": "b", "name": "B", "criticality": 0.8},
        ],
        "edges": [{"source": "a", "target": "b"}],
    }
    t = tmp_path / "t.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    assert main(["-t", str(t), "--asset-report", "--format", "csv"]) == 0
    rows = list(csv.reader(StringIO(capsys.readouterr().out)))
    assert rows[0][0] == "asset_id"
    assert any(r[0] == "a" for r in rows[1:])


def test_asset_report_sarif_still_rejected(tmp_path: Path, capsys):
    t = tmp_path / "t.json"
    t.write_text(json.dumps({"assets": [], "edges": []}), encoding="utf-8")
    assert main(["-t", str(t), "--asset-report", "--format", "sarif"]) == 2
    assert "sarif" in capsys.readouterr().err
