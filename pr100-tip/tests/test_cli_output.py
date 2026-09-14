import json
from pathlib import Path

from vuln_reachability_scorer.cli import main


def _write_inputs(tmp_path: Path) -> tuple[Path, Path]:
    topo = {
        "assets": [{"id": "a", "ingress": True, "criticality": 0.5}],
        "edges": [],
    }
    findings = {
        "findings": [
            {"id": "f", "asset_id": "a", "cve_id": "CVE-X", "base_score": 4.0}
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    return t, f


def test_output_json_file(tmp_path: Path):
    t, f = _write_inputs(tmp_path)
    out = tmp_path / "out.json"
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "-o", str(out)]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["results"][0]["cve_id"] == "CVE-X"


def test_output_table_file(tmp_path: Path):
    t, f = _write_inputs(tmp_path)
    out = tmp_path / "out.txt"
    assert main(["-t", str(t), "-f", str(f), "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "PRIORITY" in text
    assert "CVE-X" in text


def test_output_sarif_file(tmp_path: Path):
    t, f = _write_inputs(tmp_path)
    out = tmp_path / "out.sarif"
    assert main(["-t", str(t), "-f", str(f), "--format", "sarif", "-o", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
