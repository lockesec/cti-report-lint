"""Inputs that once read as a pass, a crash or a silent miss: frontmatter that does not start on
line 1, YAML dates in conflict subjects, malformed reference files, unclosed HTML comments, an
email followed by a hyphen, and a CVE claim with a version number inside the sentence."""
from __future__ import annotations

import json
import time

import pytest

from cti_report_lint import identifiers as I
from cti_report_lint import redact as R
from cti_report_lint.cli import main
from cti_report_lint.validate import validate_report

BLOCKED_BODY = """---
findings:
  - {finding_type: ANECDOTAL, trust_score: 2, source_reliability: D, confirmed_by: [], likelihood: almost certain}
conflicts:
  - ctype: VALUE_MISMATCH
    subject: attribution
    a: {source: vendorX, value: GROUP-A, trust_score: 5}
    b: {source: vendorY, value: GROUP-B, trust_score: 5}
---
The tracked actor (who) almost certainly deployed a ransomware payload (what) first seen
2026-02 (when) against the finance sector (where) for financial motivation
(why) via a phishing initial-access vector (how).
"""

PASSING = """---
date: 2026-09-01
findings:
  - {finding_type: PRIMARY, trust_score: 5, source_reliability: A, confirmed_by: []}
---
The tracked actor (who) deployed a ransomware payload (what) first seen
2026-02 (when) against the finance sector (where) for financial motivation
(why) via a phishing initial-access vector (how).
"""


def _write(tmp_path, text, name="report.md"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ── frontmatter that does not start on line 1 ───────────────────────────

@pytest.mark.parametrize("lead", ["\n", " ", "\n\n", "<!-- draft -->\n", "﻿\n"])
def test_frontmatter_after_a_leading_line_is_not_read_as_absent(tmp_path, lead):
    # dated before the ratchet by its file name, so "no findings" would be grandfathered
    p = _write(tmp_path, lead + BLOCKED_BODY, name="2020-01-01-x.md")
    assert main(["check", str(p), "--findings-required-from", "2025-01-01"]) == 1
    r = validate_report(p, findings_required_from="2025-01-01")
    assert r["verified_ok"] is False
    assert any("line 1" in i for i in r["issues"]), r["issues"]


def test_the_same_report_on_line_1_still_blocks_on_its_evidence(tmp_path):
    p = _write(tmp_path, BLOCKED_BODY, name="2020-01-01-x.md")
    r = validate_report(p, findings_required_from="2025-01-01")
    assert r["verified_ok"] is False
    assert any("OPEN CRITICAL" in i for i in r["issues"])


def test_a_horizontal_rule_in_prose_is_not_frontmatter(tmp_path):
    text = PASSING + "\n---\n\nMore prose after a rule.\n"
    assert validate_report(_write(tmp_path, text))["verified_ok"] is True


def test_skeleton_refuses_misplaced_frontmatter(tmp_path, capsys):
    p = _write(tmp_path, "\n" + BLOCKED_BODY)
    assert main(["skeleton", str(p)]) == 2


# ── --json never crashes on a report that plain `check` can grade ───────

def test_json_output_survives_a_yaml_date_subject(tmp_path, capsys):
    text = PASSING.replace("---\nThe", """conflicts:
  - ctype: VALUE_MISMATCH
    subject: 2026-01-01
    a: {source: x, value: one, trust_score: 2}
    b: {source: y, value: two, trust_score: 2}
    resolution: {status: RESOLVED, note: re-graded}
---
The""", 1)
    p = _write(tmp_path, text)
    plain = main(["check", str(p)])
    capsys.readouterr()
    assert main(["check", "--json", str(p)]) == plain
    out = json.loads(capsys.readouterr().out)
    assert out["verified_ok"] is (plain == 0)


# ── malformed reference files are NOT EVALUABLE (exit 2), never "blocked" ─

@pytest.mark.parametrize("flag,doc", [
    ("--attack-json", {"objects": [1]}),
    ("--attack-json", {"objects": [{"type": "attack-pattern", "external_references": [5]}]}),
    ("--kev-json", {"vulnerabilities": [{"cveID": ["x"]}], "catalogVersion": {}}),
])
def test_malformed_reference_file_exits_2(tmp_path, flag, doc):
    ref = tmp_path / "ref.json"
    ref.write_text(json.dumps(doc), encoding="utf-8")
    assert main(["check", str(_write(tmp_path, PASSING)), flag, str(ref)]) == 2


# ── skeleton on a non-list findings value ───────────────────────────────

@pytest.mark.parametrize("value", ["5", "{a: 1}", "yes"])
def test_skeleton_on_a_scalar_findings_value_exits_2(tmp_path, value):
    p = _write(tmp_path, f"---\nfindings: {value}\n---\nIt is likely.\n")
    assert main(["skeleton", str(p)]) == 2


# ── an unclosed HTML comment is linear, not quadratic ───────────────────

def _check_seconds(tmp_path, n):
    text = PASSING.replace("(how).", "(how) [F1].") + "<!--" * n
    p = _write(tmp_path, text, name=f"r{n}.md")
    t = time.perf_counter()
    validate_report(p)
    return time.perf_counter() - t


def test_unclosed_html_comments_scale_linearly(tmp_path):
    small, big = _check_seconds(tmp_path, 4000), _check_seconds(tmp_path, 16000)
    # 4x the input: linear is ~4x the time, quadratic ~16x; allow noise above linear
    assert big < max(small, 0.02) * 8, (small, big)


# ── an email followed by a hyphen is still redacted ─────────────────────

@pytest.mark.parametrize("text,email", [
    ("The jane@example.com-owned account", "jane@example.com"),
    ("ask ops@corp.example.org-side first", "ops@corp.example.org"),
])
def test_email_before_a_hyphen_is_redacted(text, email):
    spans = [(text[a:b], k) for a, b, k in R.find_spans(text)]
    assert (email, "EMAIL") in spans


def test_a_hyphenated_domain_is_still_one_email():
    text = "mail a@mail.co-op.example now"
    assert [(text[a:b], k) for a, b, k in R.find_spans(text)] == [("a@mail.co-op.example", "EMAIL")]


# ── a KEV claim with a version number or score inside its sentence ──────

KEV = I.KevRef(version="t", ids=set())


@pytest.mark.parametrize("sentence", [
    "CVE-2024-12345 in FooServer 2.1 is actively exploited in the wild.",
    "We saw CVE-2024-11111 (CVSS 9.8) being exploited in attacks.",
])
def test_kev_claim_across_a_decimal_point_is_checked(sentence):
    assert I.check(sentence, None, KEV), sentence


def test_two_sentences_still_split():
    text = "CVE-2024-12345 was patched. Other bugs are actively exploited in the wild."
    assert I.check(text, None, KEV) == []


# ── false positives a reader would hit on day one ───────────────────────

def test_a_plain_source_key_is_not_a_misspelling_of_sources(tmp_path):
    text = PASSING.replace("date: 2026-09-01\n", "date: 2026-09-01\nsource: vendor blog\n", 1)
    r = validate_report(_write(tmp_path, text))
    assert not any("'source'" in i for i in r["issues"]), r["issues"]


def test_a_source_key_shaped_like_sources_still_blocks(tmp_path):
    text = PASSING.replace("date: 2026-09-01\n",
                           "date: 2026-09-01\nsource:\n  - {id: s1, root: vendor}\n", 1)
    r = validate_report(_write(tmp_path, text))
    assert any("'source'" in i and "'sources'" in i for i in r["issues"]), r["issues"]


@pytest.mark.parametrize("sentence", [
    "Make sure 50% of hosts are patched.",
    "Certain hosts showed 40% CPU.",
    "The risk assessment covered 80% of servers.",
    "An estimated 30% of the fleet runs the old agent.",
])
def test_ordinary_sentences_with_a_percentage_are_not_judgments(tmp_path, sentence):
    r = validate_report(_write(tmp_path, PASSING + "\n" + sentence + "\n"))
    assert not any("bare percentage" in i or "percent" in i.lower() and "judgment" in i
                   for i in r["issues"]), r["issues"]


@pytest.mark.parametrize("sentence", [
    "We assess with 90% confidence that the actor is GROUP-A.",
    "We are sure at 80% that this was staged.",
    "We estimate a 70% chance of reuse.",
    "The probability of reuse is 60%.",
])
def test_judgment_sentences_with_a_percentage_still_block(tmp_path, sentence):
    r = validate_report(_write(tmp_path, PASSING + "\n" + sentence + "\n"))
    assert r["verified_ok"] is False, (sentence, r["issues"])
