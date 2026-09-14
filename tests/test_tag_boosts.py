import json
from pathlib import Path

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.loaders import load_tag_boosts
from vuln_reachability_scorer.models import Asset, Finding
from vuln_reachability_scorer.scoring import DEFAULT_TAG_BOOSTS, exposure_factor, score_findings


def test_default_tag_boost_raises_exposure():
    asset = Asset(id="db", name="DB", criticality=0.7, tags=("pii",))
    # 0.7 + 0.15 = 0.85
    assert exposure_factor(asset) == 0.85
    assert exposure_factor(asset, {}) == 0.7


def test_exposure_clamped_at_one():
    asset = Asset(id="x", name="X", criticality=0.95, tags=("pii", "identity", "secrets"))
    assert exposure_factor(asset) == 1.0


def test_score_findings_notes_tag_boosts():
    assets = [Asset(id="a", name="A", criticality=0.5, ingress=True, tags=("identity",))]
    findings = [Finding(id="f", asset_id="a", cve_id="CVE-1", base_score=5.0)]
    scored = score_findings(findings, assets, [])
    assert scored[0].exposure_factor == 0.7  # 0.5 + 0.2
    assert any("tag boosts" in n for n in scored[0].notes)


def test_load_tag_boosts_override(tmp_path: Path):
    p = tmp_path / "t.json"
    p.write_text(
        json.dumps(
            {
                "tag_boosts": {"pii": 0.5, "custom": 0.1},
                "assets": [],
                "edges": [],
            }
        ),
        encoding="utf-8",
    )
    boosts = load_tag_boosts(p)
    assert boosts["pii"] == 0.5
    assert boosts["custom"] == 0.1
    assert boosts["identity"] == DEFAULT_TAG_BOOSTS["identity"]


def test_cli_tag_boost_changes_priority(tmp_path: Path, capsys):
    topo = {
        "assets": [
            {
                "id": "db",
                "ingress": True,
                "criticality": 0.5,
                "tags": ["pii"],
            }
        ],
        "edges": [],
        "tag_boosts": {"pii": 0.4},
    }
    findings = {
        "findings": [
            {"id": "f", "asset_id": "db", "cve_id": "CVE-1", "base_score": 10.0}
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    # 10 * 1.0 * (0.5+0.4) = 9.0
    assert payload["results"][0]["priority_score"] == 9.0
    assert payload["results"][0]["exposure_factor"] == 0.9
