from vuln_reachability_scorer.summary import format_summary_line, summarize


def test_summarize_empty():
    stats = summarize([])
    assert stats["count"] == 0
    assert stats["max_priority"] == 0.0
    assert stats["kev_count"] == 0
    assert stats["epss_count"] == 0
    assert "n=0" in format_summary_line(stats)
