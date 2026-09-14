"""Smoke-test the shipped examples/ against the scorer."""

from pathlib import Path

import pytest

from vuln_reachability_scorer.cli import main

ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY = ROOT / "examples" / "topology.json"
FINDINGS = ROOT / "examples" / "findings.json"


@pytest.mark.skipif(not TOPOLOGY.exists(), reason="examples not present")
def test_examples_table(capsys):
    assert main(["-t", str(TOPOLOGY), "-f", str(FINDINGS)]) == 0
    out = capsys.readouterr().out
    assert "PRIORITY" in out
    assert "CVE-2021-44228" in out


@pytest.mark.skipif(not TOPOLOGY.exists(), reason="examples not present")
def test_examples_json(capsys):
    assert main(["-t", str(TOPOLOGY), "-f", str(FINDINGS), "--format", "json"]) == 0
    # Ensure valid JSON and non-empty results
    import json

    payload = json.loads(capsys.readouterr().out)
    assert len(payload["results"]) >= 1
