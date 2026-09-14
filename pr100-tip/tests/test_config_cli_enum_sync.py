"""Keep config ALLOWED_* sets aligned with argparse choices."""

from vuln_reachability_scorer.cli import build_parser
from vuln_reachability_scorer import config as cfg


def _choices(action_dest: str) -> set[str]:
    parser = build_parser()
    for action in parser._actions:
        if action.dest == action_dest and action.choices is not None:
            return set(action.choices)
    raise AssertionError(f"no choices for {action_dest}")


def test_format_sort_band_sync():
    assert cfg.ALLOWED_FORMATS == _choices("format")
    assert cfg.ALLOWED_SORTS == _choices("sort")
    assert cfg.ALLOWED_BANDS == _choices("band")
