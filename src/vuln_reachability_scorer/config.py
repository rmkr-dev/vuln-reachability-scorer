"""Load optional CLI defaults from a JSON or TOML config file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Maps config file keys → argparse destination names.
# Lists are stored as lists; booleans as bool; paths as strings (CLI coerces).
CONFIG_KEYS: dict[str, type | tuple[type, ...]] = {
    "topology": (str,),
    "findings": (str,),
    "format": (str,),
    "output": (str,),
    "min_priority": (int, float),
    "limit": (int,),
    "explain": (bool,),
    "strict": (bool,),
    "asset_report": (bool,),
    "summary": (bool,),
    "fail_under": (int, float),
    "show_title": (bool,),
    "only_kev": (bool,),
    "only_reachable": (bool,),
    "max_hops": (int,),
    "band": (list,),
    "min_epss": (int, float),
    "asset": (list,),
    "cve": (list,),
    "quiet": (bool,),
    "min_base": (int, float),
    "sort": (str,),
    "dedupe": (bool,),
    "tag": (list,),
}

_LIST_KEYS = {"band", "asset", "cve", "tag"}
_PATH_KEYS = {"topology", "findings", "output"}
_BOOL_KEYS = {
    "explain",
    "strict",
    "asset_report",
    "summary",
    "show_title",
    "only_kev",
    "only_reachable",
    "quiet",
    "dedupe",
}


class ConfigError(ValueError):
    """Invalid config file contents or unsupported format."""


def _load_raw(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"config: cannot read {path}: {exc}") from exc

    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(
                f"config: invalid JSON in {path}: {exc.msg} (line {exc.lineno} col {exc.colno})"
            ) from exc
    elif suffix == ".toml":
        import tomllib

        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"config: invalid TOML in {path}: {exc}") from exc
    else:
        raise ConfigError(
            f"config: unsupported format for {path} (use .json or .toml)"
        )

    if not isinstance(data, dict):
        raise ConfigError(f"config: root must be a table/object in {path}")
    return data


def _validate_and_normalize(data: dict[str, Any], path: Path) -> dict[str, Any]:
    unknown = sorted(k for k in data if k not in CONFIG_KEYS)
    if unknown:
        raise ConfigError(
            f"config: unknown key(s) in {path}: {', '.join(unknown)}"
        )

    out: dict[str, Any] = {}
    for key, value in data.items():
        if value is None:
            continue
        if key in _BOOL_KEYS:
            if not isinstance(value, bool):
                raise ConfigError(f"config: {key} must be a boolean in {path}")
            out[key] = value
        elif key in _LIST_KEYS:
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ConfigError(
                    f"config: {key} must be a list of strings in {path}"
                )
            out[key] = list(value)
        elif key in _PATH_KEYS:
            if not isinstance(value, str) or not value.strip():
                raise ConfigError(f"config: {key} must be a non-empty string in {path}")
            out[key] = value
        elif key == "format":
            if not isinstance(value, str):
                raise ConfigError(f"config: format must be a string in {path}")
            out[key] = value
        elif key == "sort":
            if not isinstance(value, str):
                raise ConfigError(f"config: sort must be a string in {path}")
            out[key] = value
        elif key in ("min_priority", "fail_under", "min_epss", "min_base"):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ConfigError(f"config: {key} must be a number in {path}")
            out[key] = float(value)
        elif key in ("limit", "max_hops"):
            if not isinstance(value, int) or isinstance(value, bool):
                raise ConfigError(f"config: {key} must be an integer in {path}")
            out[key] = value
        else:
            out[key] = value
    return out


def load_config(path: Path) -> dict[str, Any]:
    """Load and validate a config file; return argparse-ready defaults."""
    raw = _load_raw(path)
    return _validate_and_normalize(raw, path)


def resolve_path_defaults(
    defaults: dict[str, Any], config_dir: Path | None = None
) -> dict[str, Any]:
    """Copy defaults; resolve relative path values against ``config_dir``."""
    resolved = dict(defaults)
    if config_dir is not None:
        for key in _PATH_KEYS:
            if key in resolved and isinstance(resolved[key], str):
                p = Path(resolved[key])
                if not p.is_absolute():
                    resolved[key] = str((config_dir / p).resolve())
    for key in _PATH_KEYS:
        if key in resolved:
            resolved[key] = Path(resolved[key])
    return resolved


def apply_config_defaults(parser, defaults: dict[str, Any], config_dir: Path | None = None) -> None:
    """Set argparse defaults from config (skips append-list keys; see merge_list_defaults)."""
    resolved = resolve_path_defaults(defaults, config_dir)
    scalar = {k: v for k, v in resolved.items() if k not in _LIST_KEYS}
    parser.set_defaults(**scalar)


def merge_list_defaults(args: Any, defaults: dict[str, Any]) -> None:
    """Apply list-valued config keys only when the CLI did not pass the flag."""
    for key in _LIST_KEYS:
        if key not in defaults:
            continue
        if getattr(args, key, None) is None:
            setattr(args, key, list(defaults[key]))
