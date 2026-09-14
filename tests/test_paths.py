from vuln_reachability_scorer.explain import explain_score
from vuln_reachability_scorer.models import Asset, Edge, Finding
from vuln_reachability_scorer.paths import format_path, shortest_path
from vuln_reachability_scorer.scoring import score_findings
from vuln_reachability_scorer.cli import main
import json
from pathlib import Path


def test_shortest_path_and_format():
    assets = [
        Asset(id="lb", name="LB", ingress=True),
        Asset(id="app", name="App"),
        Asset(id="db", name="DB"),
        Asset(id="iso", name="Iso"),
    ]
    edges = [
        Edge(source="lb", target="app"),
        Edge(source="app", target="db"),
    ]
    assert shortest_path("lb", assets, edges) == ["lb"]
    assert shortest_path("db", assets, edges) == ["lb", "app", "db"]
    assert shortest_path("iso", assets, edges) is None
    assert format_path(["lb", "app"]) == "lb -> app"
    assert format_path(None) == "(unreachable)"


def test_explain_includes_path():
    assets = [Asset(id="a", name="A", criticality=1.0, ingress=True)]
    findings = [Finding(id="f", asset_id="a", cve_id="CVE-1", base_score=5.0)]
    scored = score_findings(findings, assets, [])[0]
    text = explain_score(scored, "a")
    assert "path a" in text


def test_cli_explain_json_includes_path(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "lb", "ingress": True, "criticality": 0.5},
            {"id": "app", "criticality": 0.8},
        ],
        "edges": [{"source": "lb", "target": "app"}],
    }
    findings = {
        "findings": [
            {"id": "f", "asset_id": "app", "cve_id": "CVE-1", "base_score": 5.0}
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--explain"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "lb -> app" in payload["results"][0]["explain"]


def test_all_shortest_paths_matches_single():
    from vuln_reachability_scorer.models import Asset, Edge
    from vuln_reachability_scorer.paths import all_shortest_paths, shortest_path

    assets = [
        Asset(id="i", name="I", ingress=True),
        Asset(id="x", name="X"),
        Asset(id="y", name="Y"),
        Asset(id="orphan", name="O"),
    ]
    edges = [
        Edge(source="i", target="x"),
        Edge(source="x", target="y"),
    ]
    bulk = all_shortest_paths(assets, edges)
    assert bulk["i"] == ["i"]
    assert bulk["x"] == ["i", "x"]
    assert bulk["y"] == ["i", "x", "y"]
    assert "orphan" not in bulk
    for aid in ("i", "x", "y", "orphan"):
        assert bulk.get(aid) == shortest_path(aid, assets, edges)
