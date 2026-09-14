import pytest

from vuln_reachability_scorer.models import Asset, Edge, Finding


def test_asset_from_dict_defaults():
    a = Asset.from_dict({"id": "web-1", "name": "Web"})
    assert a.id == "web-1"
    assert a.criticality == 0.5
    assert a.kind == "host"
    assert a.ingress is False


def test_asset_rejects_bad_criticality():
    with pytest.raises(ValueError):
        Asset(id="x", name="x", criticality=1.5)


def test_finding_base_score_bounds():
    with pytest.raises(ValueError):
        Finding(id="f1", asset_id="a", cve_id="CVE-1", base_score=11.0)


def test_edge_from_dict():
    e = Edge.from_dict(
        {"source": "inet", "target": "lb", "internet_facing": True, "protocol": "https"}
    )
    assert e.internet_facing is True
    assert e.protocol == "https"
