import json
from pathlib import Path

from vuln_reachability_scorer.asset_report import report_assets
from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.models import Asset, Edge


def test_report_assets_orders_by_exposure_reachability():
    assets = [
        Asset(id="lb", name="LB", criticality=0.5, ingress=True),
        Asset(id="db", name="DB", criticality=1.0),
        Asset(id="iso", name="Isolated", criticality=0.9),
    ]
    edges = [Edge(source="lb", target="db")]
    rows = report_assets(assets, edges)
    by_id = {r.asset.id: r for r in rows}
    assert by_id["lb"].hop_distance == 0
    assert by_id["db"].hop_distance == 1
    assert by_id["iso"].hop_distance is None
    assert rows[0].asset.id in {"lb", "db"}


def test_cli_asset_report_table(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {"id": "a", "name": "A", "ingress": True, "criticality": 0.5},
            {"id": "b", "name": "B", "criticality": 0.8},
        ],
        "edges": [{"source": "a", "target": "b"}],
    }
    t = tmp_path / "t.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    assert main(["-t", str(t), "--asset-report"]) == 0
    out = capsys.readouterr().out
    assert "ASSET" in out
    assert "a" in out and "b" in out


def test_cli_asset_report_json(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True}], "edges": []}
    t = tmp_path / "t.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    assert main(["-t", str(t), "--asset-report", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["assets"][0]["asset_id"] == "a"
    assert payload["assets"][0]["reachability_factor"] == 1.0


def test_findings_required_without_asset_report(tmp_path: Path):
    t = tmp_path / "t.json"
    t.write_text(json.dumps({"assets": [], "edges": []}), encoding="utf-8")
    try:
        main(["-t", str(t)])
        assert False, "expected SystemExit"
    except SystemExit as exc:
        assert exc.code == 2
