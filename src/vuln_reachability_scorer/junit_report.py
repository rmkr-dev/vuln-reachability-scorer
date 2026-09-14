"""JUnit XML report for CI consumers."""

from __future__ import annotations

import html
from xml.etree.ElementTree import Element, SubElement, tostring

from vuln_reachability_scorer.models import ScoredFinding


def to_junit(scored: list[ScoredFinding], *, suite_name: str = "vrscore") -> str:
    """Render scored findings as a JUnit XML testsuite.

    Each finding is a testcase. Failures are emitted when priority_score >= 7.0
    so CI can surface high-priority items without requiring --fail-under.
    """
    suite = Element(
        "testsuite",
        {
            "name": suite_name,
            "tests": str(len(scored)),
            "failures": str(sum(1 for s in scored if s.priority_score >= 7.0)),
        },
    )
    for s in scored:
        name = s.finding.cve_id or s.finding.id
        case = SubElement(
            suite,
            "testcase",
            {
                "classname": s.finding.asset_id,
                "name": name,
                "time": "0",
            },
        )
        props = SubElement(case, "properties")
        for key, val in (
            ("priority_score", f"{s.priority_score:.2f}"),
            ("base_score", f"{s.finding.base_score:.1f}"),
            ("hop_distance", "" if s.hop_distance is None else str(s.hop_distance)),
            ("kev", "true" if s.finding.kev else "false"),
        ):
            SubElement(props, "property", {"name": key, "value": val})
        if s.priority_score >= 7.0:
            msg = (
                f"priority {s.priority_score:.2f} on {s.finding.asset_id} "
                f"(base={s.finding.base_score:.1f})"
            )
            fail = SubElement(case, "failure", {"message": msg, "type": "priority"})
            fail.text = html.escape(msg)
    xml = tostring(suite, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml + "\n"
