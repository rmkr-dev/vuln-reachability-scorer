from vuln_reachability_scorer.models import Asset, Finding
from vuln_reachability_scorer.scoring import KEV_FACTOR, score_findings


def test_kev_multiplies_and_clamps():
    assets = [Asset(id="a", name="A", criticality=1.0, ingress=True)]
    plain = Finding(id="f1", asset_id="a", cve_id="CVE-1", base_score=9.0, kev=False)
    kev = Finding(id="f2", asset_id="a", cve_id="CVE-2", base_score=9.0, kev=True)
    scored = {s.finding.id: s for s in score_findings([plain, kev], assets, [])}
    assert scored["f1"].priority_score == 9.0
    assert scored["f2"].priority_score == min(10.0, round(9.0 * KEV_FACTOR, 2))
    assert any("KEV" in n for n in scored["f2"].notes)


def test_kev_from_dict():
    f = Finding.from_dict(
        {"id": "f", "asset_id": "a", "base_score": 1.0, "kev": True, "cve_id": "CVE-X"}
    )
    assert f.kev is True
