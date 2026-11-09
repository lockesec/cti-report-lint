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
    return [i for i in res["issues"] if " exceeds the " in i and "judgment:" in i]


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


TWO = """---
date: 2026-01-01
findings:
  - id: weak
    finding_type: ANECDOTAL
    trust_score: 2
    source_reliability: D
  - id: strong
    finding_type: PRIMARY
    trust_score: 5
    source_reliability: A
    confirmed_by: [a, b]
---
# Report
"""


@pytest.mark.parametrize("prose", ["The actor is almost certainly behind it [weak].",
                                   "The actor is almost certainly behind it. [weak]"])
def test_a_strong_claim_is_read_against_the_weak_finding_it_cites(tmp_path, prose):
    issue = prose_issues(run(tmp_path, prose, TWO))
    assert issue and "the finding it cites" in issue[0]


def test_the_same_claim_citing_the_strong_finding_passes_the_ceiling(tmp_path):
    assert not prose_issues(run(tmp_path, "The actor is almost certainly behind it [strong].", TWO))


def test_a_cited_id_nobody_declared_is_an_issue(tmp_path):
    assert any("no finding declares" in i for i in run(tmp_path, "It is very likely [ghost].", TWO)["issues"])


def test_an_uncited_term_keeps_today_s_reading_and_is_counted(tmp_path):
    res = run(tmp_path, "The actor is almost certainly behind it.", TWO)
    assert not prose_issues(res) and [u["said"] for u in res["uncited_judgments"]] == ["almost certainly"]


def test_require_citations_blocks_an_uncited_term(tmp_path):
    p = tmp_path / "r.md"
    p.write_text(TWO + "\nThe actor is almost certainly behind it.\n")
    res = validate_report(p, require_citations=True)
    assert any("cites no finding" in i for i in res["issues"])


def test_a_markdown_link_is_not_a_citation(tmp_path):
    res = run(tmp_path, "The actor is almost certainly behind it, per [weak](http://x.example).", TWO)
    assert not any("no finding declares" in i for i in res["issues"])


def test_a_citation_in_the_next_sentence_does_not_count(tmp_path):
    res = run(tmp_path, "It is almost certain. The tool is old [weak].", TWO)
    assert res["uncited_judgments"]


@pytest.mark.parametrize("bad", ["1x", "two words", "[x]"])
def test_a_malformed_finding_id_is_an_issue(tmp_path, bad):
    fm = TWO.replace("id: weak", f"id: {bad!r}")
    assert any("must be letters" in i for i in run(tmp_path, "Fine.", fm)["issues"])


def test_a_repeated_finding_id_is_an_issue(tmp_path):
    fm = TWO.replace("id: strong", "id: weak")
    assert any("used twice" in i for i in run(tmp_path, "Fine.", fm)["issues"])


@pytest.mark.parametrize("before", ["# Threat reports\n\n", "# Threat reports\n", "## According to the vendor\n",
                                    "Per the vendor\n\n", "- according to the vendor\n- "])
def test_a_heading_or_list_item_does_not_attribute_the_sentence_after_it(before):
    assert [t[2] for t in standards.prose_terms(before + "The actor is almost certainly behind it.")]


@pytest.mark.parametrize("prose", ["According to the vendor the actor is almost\ncertainly behind it.",
                                   "The vendor reports the actor is\nvery likely behind it."])
def test_a_wrapped_attributed_sentence_stays_attributed(prose):
    assert not standards.prose_terms(prose)


@pytest.mark.parametrize("prose", ["We assess with high confidence that the actor did it.",
                                   "We attribute this with a high level of confidence to the group.",
                                   "We are highly confident the actor did it.",
                                   "We assess with moderate confidence that the actor did it.",
                                   "We attribute this activity to the group."])
def test_confidence_wording_is_a_judgment_that_needs_evidence(prose):
    assert standards.confidence_terms(prose)


@pytest.mark.parametrize("prose", ["We assess with low confidence that the actor did it.",
                                   "We lack high confidence in this.", "There is no high confidence here.",
                                   "This is without moderate confidence.",
                                   "According to the vendor, it was attributed with high confidence."])
def test_low_denied_or_someone_else_s_confidence_is_not(prose):
    assert not standards.confidence_terms(prose)


def test_confidence_has_no_ceiling_but_needs_a_citation_when_required(tmp_path):
    prose = "We assess with high confidence that the actor is X."
    assert not prose_issues(run(tmp_path, prose))
    p = tmp_path / "r2.md"
    p.write_text(TWO + "\n" + prose + "\n")
    assert any("cites no finding" in i for i in validate_report(p, require_citations=True)["issues"])


def test_a_plain_report_asks_for_evidence_behind_high_confidence(tmp_path):
    p = tmp_path / "plain.md"
    p.write_text("# Note\n\nWe assess with high confidence that the actor is X.\n")
    assert any("needs evidence: 'high confidence'" in i for i in validate_report(p)["issues"])


def _cites(text, needle="very likely"):
    return standards.citation_index(text)(text.index(needle))


@pytest.mark.parametrize("text", [
    "Host seen at the firewall. [F1] The group is very likely the same actor.",
    "It is very likely X <!-- [F1] -->.",
    "It is very likely X `[F1]`.", "It is very likely X [F1][1].", "It is very likely X.\n\n[F1]\n",
    "It is very likely X.\n[F1]: https://example.invalid\n", "# Heading [F1]\nIt is very likely X.",
    "```\n[F1]\n```\nIt is very likely X.", "It is very likely X [F1](http://example.invalid)."])
def test_these_are_not_a_citation_of_the_sentence(text):
    assert _cites(text) == []


@pytest.mark.parametrize("text", ["It is very likely X [F1].", "It is very likely X. [F1]", "It is very likely X.[F1]",
                                  "It is very likely [F1] that X.", "Per triage [F1] host 192.0.2.1 is very likely owned."])
def test_these_are(text):
    assert _cites(text) == ["F1"]


def test_citation_lookup_stays_fast_on_a_large_report():
    import time
    text = "It is very likely X and also likely Y [F1]. " * 8000
    t0 = time.monotonic()
    at = standards.citation_index(text)
    for off, _t, _s in standards.prose_terms(text):
        at(off)
    assert time.monotonic() - t0 < 5


def test_a_wrapped_line_starting_with_a_hash_number_does_not_split_a_sentence():
    assert not standards.prose_terms("The vendor reports in ticket\n#4521 that it is very likely X.")
