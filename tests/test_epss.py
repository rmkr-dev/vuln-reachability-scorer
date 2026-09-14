import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.models import Asset, Finding
from vuln_reachability_scorer.scoring import EPSS_WEIGHT, epss_factor, score_findings


def test_epss_factor_range():
    assert epss_factor(0.0) == 1.0
    assert epss_factor(1.0) == 1.0 + EPSS_WEIGHT
    assert epss_factor(0.5) == 1.0 + EPSS_WEIGHT * 0.5
    with pytest.raises(ValueError):
        epss_factor(1.5)


def test_epss_omitted_is_noop():
    assets = [Asset(id="a", name="A", criticality=1.0, ingress=True)]
    plain = Finding(id="f1", asset_id="a", cve_id="CVE-1", base_score=8.0)
    zero = Finding(id="f2", asset_id="a", cve_id="CVE-2", base_score=8.0, epss=0.0)
    scored = {s.finding.id: s for s in score_findings([plain, zero], assets, [])}
    assert scored["f1"].priority_score == 8.0
    assert scored["f2"].priority_score == 8.0
    assert scored["f1"].finding.epss is None
    assert any("EPSS" in n for n in scored["f2"].notes)


def test_epss_boosts_and_clamps():
    assets = [Asset(id="a", name="A", criticality=1.0, ingress=True)]
    mid = Finding(id="f1", asset_id="a", cve_id="CVE-1", base_score=8.0, epss=0.5)
    hot = Finding(id="f2", asset_id="a", cve_id="CVE-2", base_score=9.5, epss=1.0)
    scored = {s.finding.id: s for s in score_findings([mid, hot], assets, [])}
    assert scored["f1"].priority_score == round(8.0 * (1.0 + EPSS_WEIGHT * 0.5), 2)
    assert scored["f2"].priority_score == 10.0
    assert any("EPSS 1.00" in n for n in scored["f2"].notes)


def test_epss_after_kev():
    assets = [Asset(id="a", name="A", criticality=1.0, ingress=True)]
    finding = Finding(
        id="f", asset_id="a", cve_id="CVE-1", base_score=8.0, kev=True, epss=0.5
    )
    scored = score_findings([finding], assets, [])[0]
    # 8.0 * 1.15 = 9.2; * 1.10 = 10.12 -> 10.0
    assert scored.priority_score == 10.0
    assert any("KEV" in n for n in scored.notes)
    assert any("EPSS" in n for n in scored.notes)


def test_epss_from_dict_and_bounds():
    f = Finding.from_dict(
        {
            "id": "f",
            "asset_id": "a",
            "base_score": 1.0,
            "cve_id": "CVE-X",
            "epss": 0.73,
        }
    )
    assert f.epss == 0.73
    with pytest.raises(ValueError):
        Finding(id="x", asset_id="a", cve_id="CVE-1", base_score=1.0, epss=1.2)


def test_cli_json_includes_epss(tmp_path: Path, capsys):
    topo = {"assets": [{"id": "a", "ingress": True, "criticality": 1.0}], "edges": []}
    findings = {
        "findings": [
            {
                "id": "f",
                "asset_id": "a",
                "cve_id": "CVE-1",
                "base_score": 5.0,
                "epss": 0.4,
            }
        ]
    }
    t = tmp_path / "t.json"
    f = tmp_path / "f.json"
    t.write_text(json.dumps(topo), encoding="utf-8")
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert main(["-t", str(t), "-f", str(f), "--format", "json", "--explain"]) == 0
    payload = json.loads(capsys.readouterr().out)
    row = payload["results"][0]
    assert row["epss"] == 0.4
    assert "EPSS 0.40" in row["explain"]
