import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.loaders import load_findings, load_topology
from vuln_reachability_scorer.models import Finding


def test_missing_file_message(tmp_path: Path, capsys):
    missing = tmp_path / "nope.json"
    rc = main(["-t", str(missing), "-f", str(tmp_path / "also-nope.json")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error:" in err
    assert "topology file not found" in err
    assert "nope.json" in err


def test_empty_file_message(tmp_path: Path):
    p = tmp_path / "empty.json"
    p.write_text("  \n", encoding="utf-8")
    with pytest.raises(ValueError, match="topology file is empty"):
        load_topology(p)


def test_invalid_json_includes_line(tmp_path: Path, capsys):
    t = tmp_path / "t.json"
    t.write_text("{not json", encoding="utf-8")
    f = tmp_path / "f.json"
    f.write_text("[]", encoding="utf-8")
    rc = main(["-t", str(t), "-f", str(f)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not valid JSON" in err
    assert "line " in err


def test_finding_missing_fields_indexed(tmp_path: Path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps([{"id": "f1"}]), encoding="utf-8")
    with pytest.raises(ValueError, match=r"findings\[0\].*missing required field"):
        load_findings(p)


def test_asset_not_object_indexed(tmp_path: Path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"assets": ["web"], "edges": []}), encoding="utf-8")
    with pytest.raises(ValueError, match=r"topology.assets\[0\].*must be an object"):
        load_topology(p)


def test_directory_rejected(tmp_path: Path, capsys):
    rc = main(["-t", str(tmp_path), "-f", str(tmp_path / "f.json")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "directory" in err


def test_finding_from_dict_lists_all_missing():
    with pytest.raises(ValueError, match="id, asset_id, base_score"):
        Finding.from_dict({})
