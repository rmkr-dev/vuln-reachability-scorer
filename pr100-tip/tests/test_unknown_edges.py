import json
from pathlib import Path

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.loaders import load_topology, unknown_edge_endpoints
from vuln_reachability_scorer.models import Asset, Edge


def test_unknown_edge_endpoints_helper():
    assets = [Asset(id="a", name="A")]
    edges = [Edge(source="a", target="missing")]
    msgs = unknown_edge_endpoints(assets, edges)
    assert len(msgs) == 1
    assert "missing" in msgs[0]


def test_cli_warns_unknown_edge(tmp_path: Path, capsys):
    topo = {
        "assets": [{"id": "a", "ingress": True, "criticality": 0.5}],
        "edges": [{"source": "a", "target": "ghost"}],
    }
    findings = {"findings": [{"id": "f", "asset_id": "a", "cve_id": "CVE-1", "base_score": 1.0}]}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json"]) == 0
    err = capsys.readouterr().err
    assert "warning:" in err
    assert "ghost" in err


def test_cli_strict_unknown_edge(tmp_path: Path, capsys):
    topo = {
        "assets": [{"id": "a", "ingress": True, "criticality": 0.5}],
        "edges": [{"source": "ghost", "target": "a"}],
    }
    findings = {"findings": []}
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--strict"]) == 2
    assert "error:" in capsys.readouterr().err
