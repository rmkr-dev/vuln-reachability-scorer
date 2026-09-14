"""Config validation edge cases — types, parse errors, CLI exit 2."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_reachability_scorer.cli import main
from vuln_reachability_scorer.config import (
    ConfigError,
    apply_config_defaults,
    load_config,
    merge_list_defaults,
    resolve_path_defaults,
)
from vuln_reachability_scorer.cli import build_parser


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_invalid_json(tmp_path: Path):
    p = _write(tmp_path / "bad.json", '{"topology": ')
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_config(p)


def test_invalid_toml(tmp_path: Path):
    p = _write(tmp_path / "bad.toml", "topology = [\n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(p)


def test_root_must_be_object(tmp_path: Path):
    p = _write(tmp_path / "arr.json", "[1, 2]")
    with pytest.raises(ConfigError, match="root must be a table"):
        load_config(p)


def test_cannot_read_missing(tmp_path: Path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.json")


def test_bool_type_errors(tmp_path: Path):
    for key in ("explain", "strict", "quiet", "dedupe", "stats", "summary"):
        p = _write(tmp_path / f"{key}.json", json.dumps({key: 1}))
        with pytest.raises(ConfigError, match=f"{key} must be a boolean"):
            load_config(p)


def test_list_must_be_strings(tmp_path: Path):
    p = _write(tmp_path / "band.json", json.dumps({"band": ["high", 1]}))
    with pytest.raises(ConfigError, match="band must be a list of strings"):
        load_config(p)


def test_empty_path_rejected(tmp_path: Path):
    p = _write(tmp_path / "empty.json", json.dumps({"topology": "  "}))
    with pytest.raises(ConfigError, match="topology must be a non-empty string"):
        load_config(p)


def test_findings_empty_rejected(tmp_path: Path):
    p = _write(tmp_path / "fempty.json", json.dumps({"findings": []}))
    with pytest.raises(ConfigError, match="findings must be a non-empty"):
        load_config(p)
    p2 = _write(tmp_path / "fblank.json", json.dumps({"findings": ""}))
    with pytest.raises(ConfigError, match="findings must be a non-empty"):
        load_config(p2)


def test_limit_must_be_int_not_bool(tmp_path: Path):
    p = _write(tmp_path / "lim.json", json.dumps({"limit": True}))
    with pytest.raises(ConfigError, match="limit must be an integer"):
        load_config(p)
    p2 = _write(tmp_path / "limf.json", json.dumps({"limit": 1.5}))
    with pytest.raises(ConfigError, match="limit must be an integer"):
        load_config(p2)


def test_numeric_keys_reject_bool_and_string(tmp_path: Path):
    p = _write(tmp_path / "mp.json", json.dumps({"min_priority": True}))
    with pytest.raises(ConfigError, match="min_priority must be a number"):
        load_config(p)
    p2 = _write(tmp_path / "mp2.json", json.dumps({"fail_under": "7"}))
    with pytest.raises(ConfigError, match="fail_under must be a number"):
        load_config(p2)


def test_format_and_sort_must_be_string(tmp_path: Path):
    p = _write(tmp_path / "fmt.json", json.dumps({"format": 1}))
    with pytest.raises(ConfigError, match="format must be a string"):
        load_config(p)
    p2 = _write(tmp_path / "sort.json", json.dumps({"sort": ["hops"]}))
    with pytest.raises(ConfigError, match="sort must be a string"):
        load_config(p2)


def test_null_values_skipped(tmp_path: Path):
    p = _write(
        tmp_path / "nulls.json",
        json.dumps({"topology": "t.json", "explain": None, "limit": None}),
    )
    cfg = load_config(p)
    assert cfg == {"topology": "t.json"}


def test_resolve_and_merge_list_defaults(tmp_path: Path):
    defaults = {
        "topology": "t.json",
        "findings": ["a.json", "b.json"],
        "band": ["high"],
        "output": "out.json",
    }
    resolved = resolve_path_defaults(defaults, config_dir=tmp_path)
    assert resolved["topology"] == (tmp_path / "t.json").resolve()
    assert resolved["findings"] == [
        (tmp_path / "a.json").resolve(),
        (tmp_path / "b.json").resolve(),
    ]
    assert resolved["output"] == (tmp_path / "out.json").resolve()

    parser = build_parser()
    apply_config_defaults(parser, {"summary": True, "band": ["critical"]}, config_dir=tmp_path)
    args = parser.parse_args([])
    assert args.summary is True
    # list keys not set via set_defaults
    assert getattr(args, "band", None) is None
    merge_list_defaults(args, {"band": ["critical"], "tag": ["pii"]})
    assert args.band == ["critical"]
    assert args.tag == ["pii"]
    # CLI wins: do not overwrite existing list
    args.band = ["low"]
    merge_list_defaults(args, {"band": ["critical"]})
    assert args.band == ["low"]


def test_cli_bad_config_exit_2(tmp_path: Path, capsys):
    p = _write(tmp_path / "bad.json", '{"nope": true}')
    rc = main(["--config", str(p)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "unknown key" in err
