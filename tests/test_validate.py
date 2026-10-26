"""The report gate, in both directions: a clean, well-evidenced report passes,
and each failure mode (judgment malpractice, thin coverage, over-reaching
likelihood, open conflict, damaged frontmatter, missing findings) blocks it.
All fixtures are synthetic."""
from __future__ import annotations

import pytest

from cti_report_lint.validate import validate_report

# answers all of 5W1H, clean judgment language, one well-graded finding
CLEAN = """---
title: Test report
date: 2026-09-01
findings:
  - finding_type: PRIMARY
    trust_score: 5
    source_reliability: A
    confirmed_by: []
    likelihood: almost certain
---
The tracked actor (who) deployed a Rust ransomware payload (what) first seen
2026-02 (when) against the finance sector in one region (where) for
financial motivation (why) via a phishing initial-access vector (how).
Attribution is very likely based on shared tooling (moderate confidence).
"""

BODY = """
# Report
Who: GROUP-A. What: package compromise. When: 2026-05-11. Where: a public
package registry. Why: credential theft. How: CI cache poisoning.
It is likely that the actor continues operations.
"""


def _write(tmp_path, text, name="report.md"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def _report(tmp_path, name, fm):
    return _write(tmp_path, f"---\n{fm}\n---\n{BODY}", name)


# ── the five checks ─────────────────────────────────────────────────────

def test_clean_report_passes(tmp_path):
    r = validate_report(_write(tmp_path, CLEAN))
    assert r["verified_ok"] is True, r["issues"]
    assert r["coverage_5w1h"] == 6
    assert r["findings_graded"][0]["strength"] == pytest.approx(9.0)


def test_bare_percentage_blocks(tmp_path):
    bad = CLEAN.replace("very likely based on shared tooling",
                        "73% based on shared tooling")
    r = validate_report(_write(tmp_path, bad))
    assert r["verified_ok"] is False
    assert any("bare percentage" in i for i in r["issues"])


def test_thin_coverage_blocks(tmp_path):
    thin = CLEAN.replace(
        CLEAN.split("---\n", 2)[2], "A new ransomware strain was observed.\n")
    r = validate_report(_write(tmp_path, thin))
    assert r["verified_ok"] is False
    assert any("5W1H" in i for i in r["issues"])


def test_min_5w1h_threshold_is_configurable(tmp_path):
    thin = CLEAN.replace(
        CLEAN.split("---\n", 2)[2], "A new ransomware strain was observed.\n")
    p = _write(tmp_path, thin)
    assert validate_report(p)["verified_ok"] is False
    assert validate_report(p, min_5w1h=2)["verified_ok"] is True


def test_likelihood_exceeding_evidence_ceiling_blocks(tmp_path):
    over = CLEAN.replace(
        "finding_type: PRIMARY\n    trust_score: 5\n    source_reliability: A",
        "finding_type: ANECDOTAL\n    trust_score: 2\n    source_reliability: F")
    r = validate_report(_write(tmp_path, over))
    assert r["verified_ok"] is False
    assert ("findings[0]: likelihood 'almost certain' exceeds evidence ceiling "
            "'roughly even chance' (ANECDOTAL/trust2)") in r["issues"]


def test_open_conflict_blocks(tmp_path):
    with_conflict = CLEAN.replace("---\ntitle: Test report\n", """---
title: Test report
conflicts:
  - ctype: VALUE_MISMATCH
    subject: attribution
    a: {source: vendorX, value: GROUP-A, trust_score: 4}
    b: {source: vendorY, value: GROUP-B, trust_score: 4}
""", 1)
    r = validate_report(_write(tmp_path, with_conflict))
    assert r["verified_ok"] is False
    assert any("OPEN CRITICAL" in i for i in r["issues"])


def test_auto_resolved_conflict_does_not_block(tmp_path):
    with_conflict = CLEAN.replace("---\ntitle: Test report\n", """---
title: Test report
conflicts:
  - ctype: VALUE_MISMATCH
    subject: impact
    a: {source: forum post, value: rce, trust_score: 1}
    b: {source: vendor advisory, value: infoleak, trust_score: 5}
""", 1)
    r = validate_report(_write(tmp_path, with_conflict))
    assert r["verified_ok"] is True, r["issues"]
    assert r["conflicts"][0]["open"] is False


def test_malformed_conflict_blocks(tmp_path):
    bad = CLEAN.replace("---\ntitle: Test report\n", """---
title: Test report
conflicts:
  - ctype: VALUE_MISMATCH
    subject: impact
    a: {source: forum post, value: rce}
""", 1)
    r = validate_report(_write(tmp_path, bad))
    assert r["verified_ok"] is False
    assert any(i.startswith("conflicts[0]: malformed") for i in r["issues"])


def test_partial_grade_finding_blocks(tmp_path):
    bad = CLEAN.replace(
        "finding_type: PRIMARY\n    trust_score: 5\n    source_reliability: A\n"
        "    confirmed_by: []\n    likelihood: almost certain",
        "finding_type: PRIMARY")
    r = validate_report(_write(tmp_path, bad))
    assert r["verified_ok"] is False
    assert any("partial" in i for i in r["issues"])


# ── findings are required (default), with an optional ratchet date ───────

def test_default_requires_findings_on_every_report(tmp_path):
    """No ratchet date (the default): an old report without findings is
    blocked too, because checks 3-5 would evaluate nothing."""
    r = validate_report(_report(tmp_path, "old.md", "scan_date: 2020-01-01"))
    assert r["verified_ok"] is False
    assert r["findings_grandfathered"] is False
    assert any(i.startswith("findings: none declared") for i in r["issues"])


def test_report_after_cutoff_without_findings_is_blocked(tmp_path):
    r = validate_report(_report(tmp_path, "new.md", "scan_date: 2026-09-01"),
                        findings_required_from="2026-08-15")
    assert r["verified_ok"] is False
    assert any("ratchet" in i for i in r["issues"]), r["issues"]


def test_report_before_cutoff_passes_but_is_marked(tmp_path):
    r = validate_report(_report(tmp_path, "old.md", "scan_date: 2026-08-01"),
                        findings_required_from="2026-08-15")
    assert r["verified_ok"] is True
    assert r["findings_grandfathered"] is True


def test_undated_report_fails_closed(tmp_path):
    r = validate_report(_report(tmp_path, "undated.md", "title: no date"),
                        findings_required_from="2026-08-15")
    assert r["verified_ok"] is False
    assert r["report_date"] is None


def test_declared_findings_satisfy_the_ratchet(tmp_path):
    fm = ("scan_date: 2026-09-01\n"
          "findings:\n"
          "  - finding_type: CONFIRMED\n"
          "    trust_score: 5\n"
          "    source_reliability: A\n"
          "    confirmed_by: [vendor-a.example, vendor-b.example]\n")
    r = validate_report(_report(tmp_path, "good.md", fm),
                        findings_required_from="2026-08-15")
    assert r["findings_grandfathered"] is False
    assert not any("ratchet" in i for i in r["issues"]), r["issues"]


def test_frontmatter_date_beats_filename(tmp_path):
    p = _report(tmp_path, "2026-01-01-x.md", "scan_date: 2026-09-01")
    assert validate_report(p, findings_required_from="2026-08-15")["verified_ok"] is False


def test_filename_date_used_when_frontmatter_has_none(tmp_path):
    p = _report(tmp_path, "2026-08-01-x.md", "title: dateless frontmatter")
    r = validate_report(p, findings_required_from="2026-08-15")
    assert r["report_date"] == "2026-08-01"
    assert r["findings_grandfathered"] is True


@pytest.mark.parametrize("boundary,expect_blocked", [
    ("2026-08-14", False),   # the day before: grandfathered
    ("2026-08-15", True),    # the cutoff day itself binds
    ("2026-08-16", True),
])
def test_cutoff_boundary_is_inclusive(tmp_path, boundary, expect_blocked):
    r = validate_report(_report(tmp_path, "b.md", f"scan_date: {boundary}"),
                        findings_required_from="2026-08-15")
    assert (r["verified_ok"] is False) is expect_blocked


# ── damaged frontmatter is not absent frontmatter ───────────────────────

_INTACT = """---
title: Control report
findings:
  - {finding_type: PRIMARY, trust_score: 5, source_reliability: A, confirmed_by: []}
conflicts:
  - ctype: VALUE_MISMATCH
    subject: "GROUP-A first-seen date"
    a: {source: vendor-a.example, value: "2026-05-11", trust_score: 5}
    b: {source: vendor-b.example, value: "2026-05-12", trust_score: 4}
---""" + BODY

# The only difference is the closing brace on the `a:` line.
_DAMAGED = _INTACT.replace(
    'a: {source: vendor-a.example, value: "2026-05-11", trust_score: 5}',
    'a: {source: vendor-a.example, value: "2026-05-11", trust_score: 5')


def test_fixtures_differ():
    assert _INTACT != _DAMAGED


def test_intact_conflict_still_blocks(tmp_path):
    """Positive control: a real OPEN conflict is detected."""
    r = validate_report(_write(tmp_path, _INTACT, "good.md"))
    assert r["verified_ok"] is False
    assert any("OPEN" in i and "VALUE_MISMATCH" in i for i in r["issues"])


def test_damaged_frontmatter_blocks(tmp_path):
    """Negative control: one deleted brace must NOT buy a pass."""
    r = validate_report(_write(tmp_path, _DAMAGED, "broken.md"))
    assert r["verified_ok"] is False
    assert any("UNPARSEABLE" in i for i in r["issues"]), r["issues"]


def test_damaged_frontmatter_does_not_fabricate_body_metrics(tmp_path):
    """The body is still readable when the frontmatter is not; reporting 0/6
    would be a made-up measurement."""
    r = validate_report(_write(tmp_path, _DAMAGED, "broken.md"))
    assert r["coverage_5w1h"] == 6


def test_absent_frontmatter_is_not_treated_as_damaged(tmp_path):
    r = validate_report(_write(tmp_path, "# Report\nBody.\n", "bare.md"))
    assert not any("UNPARSEABLE" in i for i in r["issues"])


def test_unterminated_block_is_damage_not_absence(tmp_path):
    r = validate_report(
        _write(tmp_path, "---\ntitle: x\nconflicts: []\n", "unterminated.md"))
    assert r["verified_ok"] is False
    assert any("UNPARSEABLE" in i for i in r["issues"])


def test_non_mapping_frontmatter_is_damage(tmp_path):
    r = validate_report(_write(tmp_path, "---\n- just\n- a list\n---\n" + BODY))
    assert any("UNPARSEABLE" in i for i in r["issues"])


# ── false PASS cases ────────────────────────────────────────────────────
# Each case is a false PASS that adversarial review reproduced.

GOOD = ("  - finding_type: PRIMARY\n    trust_score: 5\n    source_reliability: A\n"
        "    confirmed_by: []\n")


def _fm(findings, extra=""):
    return f"date: 2026-09-01\nfindings:\n{findings}{extra}"


def test_a_findings_list_of_one_empty_mapping_blocks(tmp_path):
    r = validate_report(_report(tmp_path, "r.md", "date: 2026-09-01\nfindings: [{}]"))
    assert r["verified_ok"] is False
    assert any("no grading fields" in i for i in r["issues"])


def test_an_empty_mapping_beside_a_good_finding_still_blocks(tmp_path):
    r = validate_report(_report(tmp_path, "r.md", _fm(GOOD + "  - {}\n")))
    assert r["verified_ok"] is False


def test_findings_that_is_not_a_list_blocks(tmp_path):
    r = validate_report(_report(tmp_path, "r.md", "date: 2026-09-01\nfindings: {a: 1}"))
    assert r["verified_ok"] is False and any("must be a list" in i for i in r["issues"])


def test_a_duplicate_conflicts_key_cannot_erase_an_open_critical(tmp_path):
    fm = _fm(GOOD, "\nconflicts:\n  - ctype: VALUE_MISMATCH\n    subject: impact\n"
                   "    a: {source: vendor, value: RCE, trust_score: 5}\n"
                   "    b: {source: cert, value: DoS, trust_score: 4}\n"
                   "conflicts: []")
    r = validate_report(_report(tmp_path, "r.md", fm))
    assert r["verified_ok"] is False
    assert any("UNPARSEABLE" in i for i in r["issues"])


def test_a_duplicate_nested_key_is_refused(tmp_path):
    dup = GOOD.replace("    trust_score: 5\n", "    trust_score: 1\n    trust_score: 5\n")
    r = validate_report(_report(tmp_path, "r.md", _fm(dup)))
    assert r["verified_ok"] is False


@pytest.mark.parametrize("term", ["certain", "Almost Certain", "probably", ""])
def test_an_unknown_likelihood_term_blocks(tmp_path, term):
    r = validate_report(_report(tmp_path, "r.md", _fm(GOOD + f"    likelihood: '{term}'\n")))
    assert r["verified_ok"] is False


@pytest.mark.parametrize("rel", ["AB", "''", "a b", "G"])
def test_source_reliability_needs_exactly_one_grade(tmp_path, rel):
    r = validate_report(_report(tmp_path, "r.md", _fm(GOOD.replace("source_reliability: A",
                                                                   f"source_reliability: {rel}"))))
    assert r["verified_ok"] is False


@pytest.mark.parametrize("t", ["true", "3.9", "'5'", "0", "6"])
def test_trust_score_must_be_an_integer_1_to_5(tmp_path, t):
    r = validate_report(_report(tmp_path, "r.md", _fm(GOOD.replace("trust_score: 5",
                                                                   f"trust_score: {t}"))))
    assert r["verified_ok"] is False


@pytest.mark.parametrize("pair", [(-5, 999), (0, 5), (5, 6)])
def test_conflict_trust_outside_1_to_5_cannot_auto_resolve(tmp_path, pair):
    a, b = pair
    fm = _fm(GOOD, f"conflicts:\n  - ctype: VALUE_MISMATCH\n    subject: x\n"
                   f"    a: {{source: s1, value: v1, trust_score: {a}}}\n"
                   f"    b: {{source: s2, value: v2, trust_score: {b}}}\n")
    r = validate_report(_report(tmp_path, "r.md", fm))
    assert r["verified_ok"] is False and any("malformed" in i for i in r["issues"])


def test_conflicts_that_is_not_a_list_blocks(tmp_path):
    r = validate_report(_report(tmp_path, "r.md", _fm(GOOD, "conflicts: {a: 1}\n")))
    assert r["verified_ok"] is False


@pytest.mark.parametrize("d", ["2026-02-30", "2026-00-00", "2026-13-01",
                               "'2026-02-30'", "'2026-00-00'"])
def test_an_impossible_declared_date_blocks(tmp_path, d):
    """Unquoted, YAML's own timestamp resolver rejects it (the frontmatter is
    UNPARSEABLE); quoted, it is a string and the date check must catch it."""
    r = validate_report(_report(tmp_path, "r.md", _fm(GOOD).replace("2026-09-01", d)))
    assert r["verified_ok"] is False
    assert any("not a real" in i or "UNPARSEABLE" in i for i in r["issues"])


def test_an_impossible_date_cannot_buy_a_grandfather_exemption(tmp_path):
    """'2026-00-00' sorts before any ratchet; it must count as undated, not old.
    Quoted, so YAML hands it over as a string and the date check is what runs."""
    r = validate_report(_report(tmp_path, "r.md", "date: '2026-00-00'"),
                        findings_required_from="2026-06-01")
    assert r["findings_grandfathered"] is False and r["verified_ok"] is False


# ── a UTF-8 byte-order mark must not hide the frontmatter ───────────────

OPEN_CONFLICT_FM = """---
date: 2026-12-01
findings:
  - finding_type: PRIMARY
    trust_score: 5
    source_reliability: A
    confirmed_by: []
conflicts:
  - ctype: VALUE_MISMATCH
    subject: vector
    a: {source: EDR, value: phishing, trust_score: 5}
    b: {source: IT, value: RDP, trust_score: 5}
---
"""


def test_bom_does_not_hide_an_open_conflict(tmp_path):
    body = CLEAN.split("---\n", 2)[2]
    p = tmp_path / "2026-01-01-bom.md"
    p.write_bytes(b"\xef\xbb\xbf" + (OPEN_CONFLICT_FM + body).encode())
    r = validate_report(p, findings_required_from="2026-10-01")
    assert not r["verified_ok"]
    assert r["report_date"] == "2026-12-01"
    assert any("OPEN CRITICAL" in i for i in r["issues"])


def test_bom_variant_of_a_clean_report_passes_the_same(tmp_path):
    plain, bom = tmp_path / "plain.md", tmp_path / "bom.md"
    plain.write_text(CLEAN)
    bom.write_bytes(b"\xef\xbb\xbf" + CLEAN.encode())
    a, b = validate_report(plain), validate_report(bom)
    assert a["verified_ok"] and a["findings_graded"]
    assert {k: v for k, v in a.items() if k != "file"} == \
        {k: v for k, v in b.items() if k != "file"}


def test_empty_report_blocks(tmp_path):
    p = tmp_path / "empty.md"
    p.write_text("")
    r = validate_report(p)
    assert not r["verified_ok"] and r["issues"]


@pytest.mark.parametrize("bad", ["2026-99-99", "2026-02-30", "soon"])
def test_library_rejects_an_impossible_ratchet_date(tmp_path, bad):
    p = tmp_path / "r.md"
    p.write_text(CLEAN)
    with pytest.raises(ValueError):
        validate_report(p, findings_required_from=bad)
