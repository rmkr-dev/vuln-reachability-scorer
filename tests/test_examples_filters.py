from pathlib import Path
import json

from vuln_reachability_scorer.cli import main

ROOT = Path(__file__).resolve().parents[1]
TOPO = ROOT / "examples" / "topology.json"
FIND = ROOT / "examples" / "findings.json"


def test_examples_dedupe_and_tag(capsys):
    # --dedupe is per (cve, asset); same CVE on two assets yields two rows
    assert (
        main(
            [
                "-t",
                str(TOPO),
                "-f",
                str(FIND),
                "--format",
                "json",
                "--dedupe",
                "--cve",
                "CVE-2021-44228",
            ]
        )
        == 0
    )
    rows = json.loads(capsys.readouterr().out)["results"]
    assert len(rows) == 2
    assert {r["asset_id"] for r in rows} == {"web-app", "edge-lb"}

    assert main(["-t", str(TOPO), "-f", str(FIND), "--format", "json", "--tag", "pii"]) == 0
    ids = [r["asset_id"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert ids
    assert all(a == "db-primary" for a in ids)


def test_examples_min_base(capsys):
    assert main(["-t", str(TOPO), "-f", str(FIND), "--format", "json", "--min-base", "9"]) == 0
    rows = json.loads(capsys.readouterr().out)["results"]
    assert rows
    assert all(r["base_score"] >= 9.0 for r in rows)
