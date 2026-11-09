"""Every judgment issue is reported at each place it occurs, with its file line and the text,
and the JSON result carries line, column, problem and text for each."""
from pathlib import Path

from cti_report_lint import standards as A
from cti_report_lint.validate import validate_report

FM = """---
date: 2026-09-21
findings:
  - finding_type: PRIMARY
    trust_score: 4
    source_reliability: B
    confirmed_by: [EDR]
    likelihood: very likely
---
"""
BODY = ("# Incident\n\nWho: the actor. What: ransomware. When: 2026-09-20. Where: finance sector.\n"
        "Why: financial. How: phishing attachment.\n\n")


def run(tmp_path: Path, prose: str) -> dict:
    p = tmp_path / "r.md"
    p.write_text(FM + BODY + prose + "\n", encoding="utf-8")
    return validate_report(p)


def judgment(res: dict) -> list:
    return [i for i in res["issues"] if i.startswith("judgment:")]


def test_each_occurrence_is_reported_with_its_line(tmp_path):
    prose = ("It is likely to very likely a campaign.\n"
             "Second paragraph.\n"
             "We assess with 90% confidence that it spread.\n"
             "Recovery is guaranteed.\n"
             "Another range: unlikely or likely.\n")
    issues = judgment(run(tmp_path, prose))
    assert any("hedged" in i and "line 15" in i and "likely to very likely" in i for i in issues)
    assert any("bare percentage" in i and "line 17" in i and "90%" in i for i in issues)
    assert any("absolute" in i and "line 18" in i and "guaranteed" in i for i in issues)
    assert any("hedged" in i and "line 19" in i for i in issues)


def test_json_result_carries_line_column_problem_and_text(tmp_path):
    res = run(tmp_path, "Filler.\nRecovery is guaranteed.\n")
    loc = res["judgment_locations"]
    assert loc and loc[0]["line"] == 16 and loc[0]["column"] == 13
    assert loc[0]["text"].lower() == "guaranteed" and "absolute" in loc[0]["problem"]


def test_a_negated_absolute_and_an_attributed_percentage_have_no_location(tmp_path):
    res = run(tmp_path, "Recovery is not guaranteed.\nVendor X reports 90% of incidents start by email.\n")
    assert res["judgment_locations"] == []


def test_lint_judgment_is_unchanged_and_agrees_with_the_locations():
    text = "It is likely to very likely.\nWe assess with 90% confidence.\nIt is impossible."
    kinds = [p.split(" ")[0] for p in A.lint_judgment(text)]
    assert kinds == ["hedged", "bare", "0/100"]
    assert {p for _, p, _ in A.judgment_locations(text)} == set(A.lint_judgment(text))


def test_a_percentage_split_across_a_line_break_is_located():
    locs = A.judgment_locations("We assess with 90 per\ncent confidence that it spread.")
    assert locs and "bare percentage" in locs[0][1]


def test_judgment_locations_is_linear():
    import time

    def took(n):
        t0 = time.monotonic()
        A.judgment_locations("We assess 90% likely to very likely impossible. " * (n // 48))
        return time.monotonic() - t0
    small, big = took(50_000), took(200_000)
    assert big < 8 * small + 0.5, (small, big)
