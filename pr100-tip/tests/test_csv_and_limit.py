import csv
import json
from io import StringIO
from pathlib import Path

from vuln_reachability_scorer.cli import main


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    topo = {
        "assets": [
            {"id": "a", "ingress": True, "criticality": 1.0},
            {"id": "b", "criticality": 0.5},
        ],
        "edges": [{"source": "a", "target": "b"}],
    }
    findings = {
        "findings": [
            {"id": "f1", "asset_id": "a", "cve_id": "CVE-1", "base_score": 9.0, "title": "one"},
            {"id": "f2", "asset_id": "b", "cve_id": "CVE-2", "base_score": 9.0, "title": "two"},
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    return t, f


def test_csv_format(tmp_path: Path, capsys):
    t, f = _inputs(tmp_path)
    assert main(["-t", str(t), "-f", str(f), "--format", "csv"]) == 0
    rows = list(csv.reader(StringIO(capsys.readouterr().out)))
    assert rows[0][0] == "priority_score"
    assert len(rows) == 3  # header + 2


def test_limit(tmp_path: Path, capsys):
    t, f = _inputs(tmp_path)
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--limit", "1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["results"]) == 1
    assert payload["results"][0]["id"] == "f1"
