"""Config extends / composition."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.config import ConfigError, load_config


def test_extends_overlay(tmp_path: Path):
    base = tmp_path / "base.toml"
    base.write_text('topology = "t.json"\nformat = "table"\nsummary = true\n', encoding="utf-8")
    child = tmp_path / "child.toml"
    child.write_text('extends = "base.toml"\nformat = "json"\nlimit = 3\n', encoding="utf-8")
    cfg = load_config(child)
    assert Path(cfg["topology"]) == (tmp_path / "t.json").resolve()
    assert cfg["format"] == "json"  # overlay wins
    assert cfg["summary"] is True
    assert cfg["limit"] == 3


def test_extends_cycle(tmp_path: Path):
    a = tmp_path / "a.toml"
    b = tmp_path / "b.toml"
    a.write_text('extends = "b.toml"\nformat = "json"\n', encoding="utf-8")
    b.write_text('extends = "a.toml"\nformat = "table"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="extends cycle"):
        load_config(a)


def test_extends_must_be_string(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"extends": ["x.toml"]}), encoding="utf-8")
    with pytest.raises(ConfigError, match="extends must be a non-empty string"):
        load_config(p)


def test_example_extends_runs():
    root = Path(__file__).resolve().parents[1]
    rc = main(["--config", str(root / "examples" / "vrscore-triage.toml"), "--format", "json", "--limit", "1"])
    assert rc == 0

def test_extends_max_depth(tmp_path: Path):
    from vuln_reachability_scorer.config import MAX_EXTENDS_DEPTH

    prev = None
    for i in range(MAX_EXTENDS_DEPTH + 2):
        f = tmp_path / f"c{i}.toml"
        if prev is None:
            f.write_text('format = "json"\n', encoding="utf-8")
        else:
            f.write_text(
                f'extends = "{prev.name}"\nformat = "json"\n',
                encoding="utf-8",
            )
        prev = f
    with pytest.raises(ConfigError, match="max depth"):
        load_config(prev)


def test_extends_hop_window_across_files(tmp_path: Path):
    """min_hops in base + max_hops in overlay must still validate (merged)."""
    base = tmp_path / "base.toml"
    base.write_text("min_hops = 5\n", encoding="utf-8")
    child = tmp_path / "child.toml"
    child.write_text('extends = "base.toml"\nmax_hops = 2\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="min_hops cannot exceed max_hops"):
        load_config(child)


def test_extends_target_missing(tmp_path: Path):
    child = tmp_path / "child.toml"
    child.write_text('extends = "missing.toml"\nformat = "json"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="extends target not found"):
        load_config(child)


def test_extends_hop_window_valid_split(tmp_path: Path):
    base = tmp_path / "base.toml"
    base.write_text("min_hops = 1\n", encoding="utf-8")
    child = tmp_path / "child.toml"
    child.write_text('extends = "base.toml"\nmax_hops = 3\n', encoding="utf-8")
    cfg = load_config(child)
    assert cfg["min_hops"] == 1
    assert cfg["max_hops"] == 3


def test_extends_list_replace_not_concat(tmp_path: Path):
    base = tmp_path / "base.toml"
    base.write_text('band = ["critical", "high"]\n', encoding="utf-8")
    child = tmp_path / "child.toml"
    child.write_text('extends = "base.toml"\nband = ["medium"]\n', encoding="utf-8")
    cfg = load_config(child)
    assert cfg["band"] == ["medium"]


def test_extends_json_from_toml(tmp_path: Path):
    base = tmp_path / "base.toml"
    base.write_text('topology = "t.json"\nsummary = true\n', encoding="utf-8")
    child = tmp_path / "child.json"
    child.write_text(
        json.dumps({"extends": "base.toml", "format": "json", "limit": 2}),
        encoding="utf-8",
    )
    cfg = load_config(child)
    assert Path(cfg["topology"]) == (tmp_path / "t.json").resolve()
    assert cfg["summary"] is True
    assert cfg["format"] == "json"
    assert cfg["limit"] == 2


def test_extends_depth_at_max_succeeds(tmp_path: Path):
    from vuln_reachability_scorer.config import MAX_EXTENDS_DEPTH

    prev = None
    tip = None
    for i in range(MAX_EXTENDS_DEPTH):
        f = tmp_path / f"d{i}.toml"
        if prev is None:
            f.write_text('format = "json"\n', encoding="utf-8")
        else:
            f.write_text(f'extends = "{prev.name}"\nlimit = {i}\n', encoding="utf-8")
        prev = f
        tip = f
    cfg = load_config(tip)
    assert cfg["format"] == "json"
    assert cfg["limit"] == MAX_EXTENDS_DEPTH - 1


def test_extends_paths_resolve_against_defining_file(tmp_path: Path):
    """Paths from a base in another directory must not resolve against the leaf."""
    estate = tmp_path / "estate"
    overlays = tmp_path / "overlays"
    estate.mkdir()
    overlays.mkdir()
    (estate / "topology.json").write_text("{}", encoding="utf-8")
    (estate / "findings.json").write_text("{}", encoding="utf-8")
    (estate / "base.toml").write_text(
        'topology = "topology.json"\nfindings = "findings.json"\n',
        encoding="utf-8",
    )
    (overlays / "ci.toml").write_text(
        'extends = "../estate/base.toml"\nformat = "sarif"\n',
        encoding="utf-8",
    )
    cfg = load_config(overlays / "ci.toml")
    assert Path(cfg["topology"]) == (estate / "topology.json").resolve()
    assert Path(cfg["findings"]) == (estate / "findings.json").resolve()
    assert cfg["format"] == "sarif"


def test_example_overlay_subdir_extends_base():
    root = Path(__file__).resolve().parents[1]
    overlay = root / "examples" / "overlays" / "vrscore-ci.toml"
    cfg = load_config(overlay)
    assert Path(cfg["topology"]) == (root / "examples" / "topology.json").resolve()
    assert cfg["format"] == "sarif"
    assert cfg["fail_under"] == 7.0
    rc = main(["--config", str(overlay), "--limit", "2"])
    # fail_under may trip; accept 0 or 1
    assert rc in (0, 1)


def test_extends_absolute_path(tmp_path: Path):
    base = tmp_path / "base.toml"
    base.write_text('format = "table"\nsummary = true\n', encoding="utf-8")
    child = tmp_path / "child.toml"
    child.write_text(f'extends = "{base.resolve()}"\nformat = "json"\n', encoding="utf-8")
    cfg = load_config(child)
    assert cfg["format"] == "json"
    assert cfg["summary"] is True


def test_extends_findings_list_replace_cross_dir(tmp_path: Path):
    estate = tmp_path / "estate"
    overlays = tmp_path / "overlays"
    estate.mkdir()
    overlays.mkdir()
    (estate / "base.toml").write_text(
        'findings = "shared.json"\ntopology = "topology.json"\n',
        encoding="utf-8",
    )
    (overlays / "team.toml").write_text(
        'extends = "../estate/base.toml"\n'
        'findings = ["a.json", "b.json"]\n',
        encoding="utf-8",
    )
    cfg = load_config(overlays / "team.toml")
    assert Path(cfg["topology"]) == (estate / "topology.json").resolve()
    assert cfg["findings"] == [
        str((overlays / "a.json").resolve()),
        str((overlays / "b.json").resolve()),
    ]


def test_extends_target_is_directory(tmp_path: Path):
    (tmp_path / "subdir").mkdir()
    child = tmp_path / "child.toml"
    child.write_text('extends = "subdir"\nformat = "json"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="extends target is a directory"):
        load_config(child)


def test_example_medium_band_replace():
    root = Path(__file__).resolve().parents[1]
    cfg = load_config(root / "examples" / "vrscore-medium.toml")
    assert cfg["band"] == ["medium"]
    assert cfg.get("explain") is True  # from triage
    rc = main(["--config", str(root / "examples" / "vrscore-medium.toml"), "--limit", "5"])
    assert rc == 0


def test_extends_whitespace_rejected(tmp_path: Path):
    p = tmp_path / "bad.toml"
    p.write_text('extends = "   "\nformat = "json"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="extends must be a non-empty string"):
        load_config(p)


def test_extends_output_resolves_against_defining_file(tmp_path: Path):
    estate = tmp_path / "estate"
    overlays = tmp_path / "overlays"
    estate.mkdir()
    overlays.mkdir()
    (estate / "base.toml").write_text(
        'topology = "topology.json"\noutput = "scores.json"\n',
        encoding="utf-8",
    )
    (overlays / "ci.toml").write_text(
        'extends = "../estate/base.toml"\nformat = "json"\n',
        encoding="utf-8",
    )
    cfg = load_config(overlays / "ci.toml")
    assert Path(cfg["output"]) == (estate / "scores.json").resolve()
    # overlay can replace output rooted at overlay dir
    (overlays / "ci2.toml").write_text(
        'extends = "../estate/base.toml"\noutput = "local.sarif"\n',
        encoding="utf-8",
    )
    cfg2 = load_config(overlays / "ci2.toml")
    assert Path(cfg2["output"]) == (overlays / "local.sarif").resolve()


def test_extends_self_cycle(tmp_path: Path):
    a = tmp_path / "a.toml"
    a.write_text('extends = "a.toml"\nformat = "json"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="extends cycle"):
        load_config(a)


def test_example_strict_ci_overlay():
    root = Path(__file__).resolve().parents[1]
    cfg = load_config(root / "examples" / "overlays" / "vrscore-strict-ci.toml")
    assert cfg["strict"] is True
    assert cfg["format"] == "sarif"
    assert cfg.get("fail_under") == 7.0


def test_example_exclude_extends_base():
    root = Path(__file__).resolve().parents[1]
    cfg = load_config(root / "examples" / "vrscore-exclude.toml")
    assert Path(cfg["topology"]) == (root / "examples" / "topology.json").resolve()
    assert cfg["exclude_asset"] == ["batch-worker"]
    assert cfg["exclude_tag"] == ["dmz"]
    rc = main(["--config", str(root / "examples" / "vrscore-exclude.toml"), "--limit", "5"])
    assert rc == 0


def test_example_multi_extends_base():
    root = Path(__file__).resolve().parents[1]
    cfg = load_config(root / "examples" / "vrscore-multi.toml")
    assert Path(cfg["topology"]) == (root / "examples" / "topology.json").resolve()
    assert len(cfg["findings"]) == 2
    rc = main(["--config", str(root / "examples" / "vrscore-multi.toml"), "--limit", "5"])
    assert rc == 0


def test_example_tag_focus_overlay():
    root = Path(__file__).resolve().parents[1]
    cfg = load_config(root / "examples" / "vrscore-tag-focus.toml")
    assert cfg["tag"] == ["pii", "identity"]
    assert cfg.get("explain") is True  # from triage
    assert cfg["band"] == ["critical", "high"]
    rc = main(["--config", str(root / "examples" / "vrscore-tag-focus.toml"), "--limit", "5"])
    assert rc == 0


def test_extends_toml_from_json(tmp_path: Path):
    base = tmp_path / "base.json"
    base.write_text(
        json.dumps({"topology": "t.json", "summary": True, "format": "table"}),
        encoding="utf-8",
    )
    child = tmp_path / "child.toml"
    child.write_text(
        'extends = "base.json"\nformat = "json"\nlimit = 4\n',
        encoding="utf-8",
    )
    cfg = load_config(child)
    assert Path(cfg["topology"]) == (tmp_path / "t.json").resolve()
    assert cfg["summary"] is True
    assert cfg["format"] == "json"
    assert cfg["limit"] == 4


def test_extends_boolean_rejected(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"extends": True, "format": "json"}), encoding="utf-8")
    with pytest.raises(ConfigError, match="extends must be a non-empty string"):
        load_config(p)


def test_extends_integer_rejected(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"extends": 1, "format": "json"}), encoding="utf-8")
    with pytest.raises(ConfigError, match="extends must be a non-empty string"):
        load_config(p)


def test_example_epss_overlay():
    root = Path(__file__).resolve().parents[1]
    cfg = load_config(root / "examples" / "vrscore-epss.toml")
    assert cfg["min_epss"] == 0.5
    assert cfg["band"] == ["critical", "high"]
    assert cfg.get("explain") is True
    rc = main(["--config", str(root / "examples" / "vrscore-epss.toml"), "--limit", "5"])
    assert rc == 0
