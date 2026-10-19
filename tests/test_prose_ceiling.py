"""The likelihood ceiling reads the prose, not only the `likelihood:` a finding declares: a
band term (or its ICD 203 synonym) in the body that is stronger than every declared finding's
evidence allows is an issue, with its line."""
from pathlib import Path

import pytest
from cti_report_lint import standards
from cti_report_lint.validate import validate_report

FM = """---
date: 2026-09-21
findings:
  - finding_type: ANECDOTAL
    trust_score: 2
    source_reliability: D
    confirmed_by: []
    likelihood: roughly even chance
---
"""
BODY = ("# Incident\n\nWho: the actor. What: ransomware. When: 2026-09-20. Where: finance sector.\n"
        "Why: financial. How: phishing attachment.\n\n")


def run(tmp_path: Path, prose: str, fm: str = FM) -> dict:
    p = tmp_path / "r.md"
    p.write_text(fm + BODY + prose + "\n", encoding="utf-8")
    return validate_report(p)


def prose_issues(res: dict) -> list:
    return [i for i in res["issues"] if "exceeds the strongest evidence ceiling" in i]


@pytest.mark.parametrize("prose", [
    "The actor is almost certain to be behind the intrusion.",
    "The actor is almost certainly behind the intrusion.",
    "It is very likely that the loader came from the same group.",
    "It is highly probable that the loader came from the same group.",
    "Reinfection is likely.",
    "Reinfection is probable.",
    "The group probably reused the loader.",
    "It is nearly certain that data left the network.",
    "It is highly likely that data left the network.",
])
def test_a_term_above_every_ceiling_is_an_issue(tmp_path, prose):
    res = run(tmp_path, prose)
    assert prose_issues(res) and not res["verified_ok"]


def test_the_issue_names_the_term_and_its_file_line(tmp_path):
    issue = prose_issues(run(tmp_path, "Line one.\nThe actor is almost certainly behind it."))[0]
    assert "almost certainly" in issue and "line 16" in issue and "roughly even chance" in issue


@pytest.mark.parametrize("prose", [
    "It is roughly even chance that the actor reuses the loader.",
    "Reinfection is unlikely.",
    "There is almost no chance the backup was touched.",
    "Reinfection is not likely.",
    "Attribution isn't likely without more telemetry.",
    'The vendor report says the actor is "almost certain" to return.',
    "According to Vendor X, the group is very likely state-sponsored.",
    "Vendor X attributes the campaign, calling it almost certain.",
    "The likelihood scale runs from almost no chance to almost certain.",
])
def test_terms_at_or_below_the_ceiling_negated_or_attributed_are_not_issues(tmp_path, prose):
    assert not prose_issues(run(tmp_path, prose))


def test_the_strongest_finding_sets_the_ceiling(tmp_path):
    fm = FM.replace("likelihood: roughly even chance", "likelihood: roughly even chance\n"
                    "  - finding_type: PRIMARY\n    trust_score: 4\n    source_reliability: B\n"
                    "    confirmed_by: [EDR]\n    likelihood: very likely")
    assert not prose_issues(run(tmp_path, "It is very likely the loader is theirs.", fm))
    assert prose_issues(run(tmp_path, "The actor is almost certain to return.", fm))


def test_no_graded_finding_means_the_prose_check_is_not_run(tmp_path):
    fm = "---\ndate: 2026-09-21\n---\n"
    res = run(tmp_path, "The actor is almost certain to return.", fm)
    assert not prose_issues(res)
    assert any("findings: none declared" in i for i in res["issues"])


def test_the_shipped_after_example_still_passes():
    root = Path(__file__).resolve().parents[1]
    assert validate_report(root / "examples" / "incident-report-after.md")["verified_ok"]


def test_prose_terms_is_linear():
    import time

    def took(n):
        t0 = time.monotonic()
        standards.prose_terms("almost certain likely. " * (n // 23))
        return time.monotonic() - t0
    small, big = took(50_000), took(200_000)
    assert big < 8 * small + 0.5, (small, big)


# Band terms split by a line wrap or extra spaces are still read.
WRAPPED_FM = ("---\nfindings:\n  - {finding_type: PRIMARY, trust_score: 3, source_reliability: B, "
      "confirmed_by: [edr]}\n---\n")
WRAPPED_BODY = "Who: actor. What: malware. When: 2026-09-20. Where: finance sector. Why: money. How: phishing.\n"


@pytest.mark.parametrize("prose", ["We think the host is very\nlikely compromised.",
                                   "It is almost\n   certain the actor returns.",
                                   "A highly   likely breach."])
def test_a_band_term_split_by_a_line_wrap_or_spaces_is_read(tmp_path, prose):
    p = tmp_path / "r.md"
    p.write_text(WRAPPED_FM + WRAPPED_BODY + prose + "\n")
    issues = [i for i in validate_report(p)["issues"] if "exceeds the strongest" in i]
    assert issues and "line 6" in issues[0]          # the line where the term starts


def test_a_wrapped_hedge_is_flagged(tmp_path):
    p = tmp_path / "r.md"
    p.write_text(WRAPPED_FM + WRAPPED_BODY + "It was likely to very\nlikely hit.\n")
    assert any("hedged" in i for i in validate_report(p)["issues"])
