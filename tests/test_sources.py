"""Declared sources: `confirmed_by` names source ids, corroboration is counted by independent
root (a source that repeats another counts once with it), and trust 4-5 needs at least two
independent sources, so circular reporting cannot raise a ceiling."""
from pathlib import Path

import yaml
from cti_report_lint.validate import validate_report

BODY = ("\n# Incident\n\nWho: the actor. What: ransomware. When: 2026-09-20. "
        "Where: finance sector.\nWhy: financial. How: phishing attachment.\n")


def report(tmp_path: Path, fm: dict) -> dict:
    p = tmp_path / "r.md"
    p.write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---" + BODY)
    return validate_report(p)


def finding(trust, confirmed, **kw):
    return dict({"finding_type": "PRIMARY", "trust_score": trust, "source_reliability": "B",
                 "confirmed_by": confirmed}, **kw)


SOURCES = [{"id": "edr", "reliability": "A"},
           {"id": "proxy", "reliability": "B"},
           {"id": "vendor-feed", "reliability": "B"},
           {"id": "vendor-blog", "reliability": "C", "derived_from": "vendor-feed"},
           {"id": "news", "reliability": "D", "derived_from": "vendor-blog"}]


def issues(res, needle=""):
    return [i for i in res["issues"] if needle in i]


def test_two_independent_sources_support_trust_four(tmp_path):
    res = report(tmp_path, {"date": "2026-09-21", "sources": SOURCES,
                            "findings": [finding(4, ["edr", "proxy"])]})
    assert res["verified_ok"], res["issues"]
    assert res["findings_graded"][0]["independent_sources"] == 2


def test_circular_reporting_counts_once_and_cannot_support_trust_four(tmp_path):
    res = report(tmp_path, {"date": "2026-09-21", "sources": SOURCES,
                            "findings": [finding(4, ["vendor-feed", "vendor-blog", "news"])]})
    found = issues(res, "independent")
    assert found and "1 independent" in found[0] and "vendor-feed" in found[0]
    assert res["findings_graded"][0]["independent_sources"] == 1


def test_trust_three_needs_no_second_source(tmp_path):
    res = report(tmp_path, {"date": "2026-09-21", "sources": SOURCES,
                            "findings": [finding(3, ["vendor-blog"])]})
    assert not issues(res, "independent")


def test_an_unknown_source_id_blocks(tmp_path):
    res = report(tmp_path, {"date": "2026-09-21", "sources": SOURCES,
                            "findings": [finding(3, ["edr", "edrr"])]})
    assert any("'edrr' is not a declared source" in i for i in res["issues"])


def test_an_unknown_upstream_and_a_cycle_block(tmp_path):
    bad = [{"id": "a", "reliability": "B", "derived_from": "b"},
           {"id": "b", "reliability": "B", "derived_from": "a"},
           {"id": "c", "reliability": "B", "derived_from": "nowhere"}]
    res = report(tmp_path, {"date": "2026-09-21", "sources": bad,
                            "findings": [finding(3, ["a"])]})
    assert any("cycle" in i for i in res["issues"])
    assert any("'nowhere'" in i for i in res["issues"])


def test_a_malformed_source_blocks(tmp_path):
    res = report(tmp_path, {"date": "2026-09-21",
                            "sources": [{"id": "x", "reliability": "Z"}, {"reliability": "A"},
                                        {"id": "x", "reliability": "A"}],
                            "findings": [finding(3, ["x"])]})
    text = " ".join(res["issues"])
    assert "reliability 'Z'" in text and "needs an id" in text and "declared twice" in text


def test_without_sources_confirmed_by_stays_free_text(tmp_path):
    res = report(tmp_path, {"date": "2026-09-21",
                            "findings": [finding(4, ["EDR process tree", "proxy logs"])]})
    assert res["verified_ok"], res["issues"]
    assert res["findings_graded"][0].get("independent_sources") is None
