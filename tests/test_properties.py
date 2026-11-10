"""Property tests written from the documentation, not from the code.

They check the documented tables and limits (likelihood bands, evidence ceiling,
strength formula, conflict severity, exit codes), the citation rules, the judgment
wording rules, and the redact/restore round trip. Both sides of each documented
limit are pinned, as is every value of a documented list.

Needs Hypothesis, a test dependency only: `pip install .[test]`. The file skips itself
without it.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import itertools
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path

import pytest

pytest.importorskip("hypothesis")
from hypothesis import example, given, settings, strategies as st  # noqa: E402

from cti_report_lint import cli, redact as R, standards  # noqa: E402
from cti_report_lint.findings import strength  # noqa: E402
from cti_report_lint.validate import validate_report  # noqa: E402

PROFILE = dict(derandomize=True, database=None, deadline=None, max_examples=30)


def prop(**kw):
    return settings(**{**PROFILE, **kw})


BANDS = ["almost no chance", "very unlikely", "unlikely", "roughly even chance",
         "likely", "very likely", "almost certain"]
TYPES = ["CONFIRMED", "PRIMARY", "DERIVED", "ANECDOTAL", "CONTESTED"]
# index into BANDS of the strongest term a trust score allows (rules.md); 1 allows none
TRUST_CEIL = {5: 6, 4: 5, 3: 4, 2: 3, 1: None}
WORDS = ["alpha", "bravo", "cobalt", "delta", "ember", "fjord", "garnet", "harbor",
         "ivory", "juniper", "kiln", "lantern", "meadow", "nickel", "orchid"]


def ceiling_index(ftype, trust):
    """Strongest allowed band index per rules.md, or None for 'no single judgment'."""
    if ftype == "CONTESTED":
        return None
    base = TRUST_CEIL[trust]
    if base is None:
        return None
    if ftype == "ANECDOTAL":
        return min(base, 3)
    return base


@pytest.fixture(scope="module", autouse=True)
def home_and_work(tmp_path_factory):
    """HOME points at a temp dir for the whole module; work files go under tmp."""
    home = tmp_path_factory.mktemp("home")
    work = tmp_path_factory.mktemp("work")
    mp = pytest.MonkeyPatch()
    mp.setenv("HOME", str(home))
    mp.setenv("USERPROFILE", str(home))
    yield work
    mp.undo()


_counter = itertools.count()


@pytest.fixture(scope="module")
def work(home_and_work):
    return home_and_work


def newdir(work):
    d = work / ("c%d" % next(_counter))
    d.mkdir()
    return d


def fm_text(findings=None, sources=None, conflicts=None, date="2026-09-21", extra=""):
    lines = []
    if date:
        lines.append("date: %s" % date)
    if findings is not None:
        lines.append("findings: " + json.dumps(findings))
    if sources is not None:
        lines.append("sources: " + json.dumps(sources))
    if conflicts is not None:
        lines.append("conflicts: " + json.dumps(conflicts))
    if extra:
        lines.append(extra)
    return "---\n" + "\n".join(lines) + "\n---\n"


def run(work, fm, body, name="r.md", **kw):
    d = newdir(work)
    p = d / name
    p.write_text(fm + body, encoding="utf-8")
    kw.setdefault("min_5w1h", 0)
    return validate_report(p, **kw)


def finding(ftype="PRIMARY", trust=3, rel="B", **more):
    d = {"finding_type": ftype, "trust_score": trust, "source_reliability": rel}
    d.update(more)
    return d


def cli_run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


# ------------------------------------------------------------- likelihood bands
@given(st.floats(1.0, 99.0, allow_nan=False))
@prop()
def test_band_term_never_weakens_as_percent_rises(p):
    a = BANDS.index(standards.likelihood_term(p))
    b = BANDS.index(standards.likelihood_term(min(99.0, p + 5.0)))
    assert a <= b


# interiors and both sides of each documented edge (rules.md: ICD 203 bands)
@pytest.mark.parametrize("pct,term", [
    (1, "almost no chance"), (3, "almost no chance"), (4.9, "almost no chance"),
    (5.1, "very unlikely"), (12, "very unlikely"), (19.9, "very unlikely"),
    (20.1, "unlikely"), (30, "unlikely"), (44.9, "unlikely"),
    (45.1, "roughly even chance"), (50, "roughly even chance"), (54.9, "roughly even chance"),
    (55.1, "likely"), (65, "likely"), (79.9, "likely"),
    (80.1, "very likely"), (88, "very likely"), (94.9, "very likely"),
    (95.1, "almost certain"), (97, "almost certain"), (99, "almost certain"),
])
def test_band_table(pct, term):
    assert standards.likelihood_term(pct) == term


# ------------------------------------------------------------- evidence ceiling
@pytest.mark.parametrize("ftype", ["CONFIRMED", "PRIMARY", "DERIVED"])
@pytest.mark.parametrize("trust", [1, 2, 3, 4, 5])
def test_ceiling_follows_trust_for_unlowered_types(ftype, trust):
    ci = ceiling_index(ftype, trust)
    got = standards.ceiling_for(ftype, trust)
    assert got == (None if ci is None else BANDS[ci])


@pytest.mark.parametrize("trust", [1, 2, 3, 4, 5])
def test_anecdotal_tops_out_at_even_chance_and_contested_allows_none(trust):
    ci = ceiling_index("ANECDOTAL", trust)
    got = standards.ceiling_for("ANECDOTAL", trust)
    assert got == (None if ci is None else BANDS[ci])
    assert standards.ceiling_for("CONTESTED", trust) is None


def test_primary_trust_2_is_still_even_chance():
    assert standards.ceiling_for("PRIMARY", 2) == "roughly even chance"


@pytest.mark.parametrize("ftype", TYPES)
@pytest.mark.parametrize("trust", [1, 2, 3, 4, 5])
def test_exceeds_ceiling_both_sides_of_the_limit(ftype, trust):
    ci = ceiling_index(ftype, trust)
    for i, term in enumerate(BANDS):
        want = True if ci is None else i > ci
        assert standards.exceeds_ceiling(term, ftype, trust) is want, (term, ftype, trust)


@pytest.mark.parametrize("ftype", TYPES)
@pytest.mark.parametrize("trust", [1, 2, 3, 4, 5])
def test_declared_likelihood_blocks_only_above_ceiling(work, ftype, trust):
    ci = ceiling_index(ftype, trust)
    for i, term in enumerate(BANDS):
        r = run(work, fm_text([finding(ftype, trust, confirmed_by=["x"], likelihood=term)]),
                "A plain statement.\n")
        blocked = not r["verified_ok"]
        assert blocked == (True if ci is None else i > ci), (ftype, trust, term, r["issues"])


def test_likelihood_outside_the_seven_terms_blocks_and_is_named(work):
    r = run(work, fm_text([finding("PRIMARY", 5, likelihood="probably maybe")]), "Text.\n")
    assert not r["verified_ok"]
    assert any("probably maybe" in i for i in r["issues"])


# ------------------------------------------------------------- strength (reported)
BASE = {"CONFIRMED": 8, "PRIMARY": 7, "DERIVED": 4, "ANECDOTAL": 2}


@given(st.sampled_from(sorted(BASE)), st.integers(1, 5), st.integers(0, 12))
@example("DERIVED", 3, 3).via("doc: bonus cap 1.5 reached at 3")
@example("DERIVED", 3, 2).via("doc: one below the cap")
@example("DERIVED", 3, 4).via("doc: one above the cap")
@example("CONFIRMED", 5, 0).via("doc: total capped at 10, exactly")
@example("CONFIRMED", 5, 5).via("doc: total capped at 10")
@example("CONFIRMED", 4, 1).via("doc: 8 + 1.6 + 0.5")
@prop()
def test_strength_formula(ftype, trust, conf):
    want = min(10.0, BASE[ftype] + 0.4 * trust + min(0.5 * conf, 1.5))
    assert strength(ftype, trust, conf) == pytest.approx(want)


@given(st.integers(1, 5), st.integers(0, 12))
@prop()
def test_contested_strength_is_always_zero(trust, conf):
    assert strength("CONTESTED", trust, conf) == 0.0


# ------------------------------------------------------------- conflict severity
def sev_expected(a, b):
    lo, hi = min(a, b), max(a, b)
    if lo >= 4:
        return "CRITICAL"
    if lo >= 3 and hi < 4:
        return "HIGH"
    if hi >= 4 and lo <= 2:
        return "MINOR"
    return "NOTABLE"


def conflict(ta, tb, ctype="VALUE_MISMATCH", **more):
    c = {"ctype": ctype, "subject": "initial access vector",
         "a": {"source": "EDR telemetry", "value": "phishing attachment", "trust_score": ta},
         "b": {"source": "customer IT", "value": "exposed RDP", "trust_score": tb}}
    c.update(more)
    return c


@pytest.mark.parametrize("ta,tb", [(a, b) for a in range(1, 6) for b in range(1, 6)])
def test_conflict_severity_table_and_what_blocks(work, ta, tb):
    r = run(work, fm_text([finding()], conflicts=[conflict(ta, tb)]), "Text.\n")
    want = sev_expected(ta, tb)
    seen = [m.group(1) for i in r["issues"] if (m := re.search(r"OPEN (\w+)", i))]
    if want == "MINOR":
        assert r["verified_ok"] and seen == []
    else:
        assert not r["verified_ok"] and seen == [want], r["issues"]


@pytest.mark.parametrize("ctype", ["VALUE_MISMATCH", "TIME_IMPOSSIBLE", "EXISTENCE_DISPUTE"])
def test_each_documented_conflict_type_is_read(work, ctype):
    r = run(work, fm_text([finding()], conflicts=[conflict(5, 5, ctype)]), "Text.\n")
    assert not r["verified_ok"] and any("OPEN CRITICAL" in i and ctype in i for i in r["issues"])


@pytest.mark.parametrize("ta,tb", [(5, 5), (3, 3), (3, 4), (2, 3)])
def test_human_decision_clears_a_blocking_conflict(work, ta, tb):
    dec = {"by": "tier-2 lead", "winner": "a", "note": "firewall export shows RDP closed"}
    r = run(work, fm_text([finding()], conflicts=[conflict(ta, tb, resolved_by=dec)]), "Text.\n")
    assert r["verified_ok"], r["issues"]
    c = r["conflicts"][0]
    assert c["decided_by"] == "tier-2 lead"
    assert c["decision_note"] == "firewall export shows RDP closed"
    assert c["winner"] is not None


@pytest.mark.parametrize("winner", ["a", "b", "neither"])
def test_each_documented_winner_is_accepted(work, winner):
    dec = {"by": "lead", "winner": winner, "note": "reason"}
    r = run(work, fm_text([finding()], conflicts=[conflict(5, 5, resolved_by=dec)]), "Text.\n")
    assert r["verified_ok"], r["issues"]


@pytest.mark.parametrize("dec", [
    {"by": "", "winner": "a", "note": "reason"},
    {"by": "lead", "winner": "a", "note": ""},
    {"by": "lead", "winner": "c", "note": "reason"},
    {"winner": "a", "note": "reason"},
])
def test_incomplete_decision_still_blocks(work, dec):
    r = run(work, fm_text([finding()], conflicts=[conflict(5, 5, resolved_by=dec)]), "Text.\n")
    assert not r["verified_ok"]


def test_conflict_value_written_as_date_or_number_is_kept_as_text(work):
    c = conflict(5, 2)
    raw = ("---\ndate: 2026-09-21\nfindings: " + json.dumps([finding()]) + "\nconflicts:\n"
           "  - ctype: VALUE_MISMATCH\n    subject: first seen\n"
           "    a: {source: edr, value: 2026-09-20, trust_score: 5}\n"
           "    b: {source: customer, value: 42, trust_score: 2}\n---\n")
    r = run(work, raw, "Text.\n")
    assert r["verified_ok"], r["issues"]


# ------------------------------------------------------------- finding grades
@pytest.mark.parametrize("ftype", TYPES)
def test_every_documented_type_is_accepted(work, ftype):
    r = run(work, fm_text([finding(ftype, 3, confirmed_by=["x"])]), "Text.\n")
    assert r["verified_ok"], r["issues"]


@pytest.mark.parametrize("trust", [1, 2, 3, 4, 5])
def test_trust_inside_1_to_5_is_accepted(work, trust):
    assert run(work, fm_text([finding(trust=trust)]), "Text.\n")["verified_ok"]


@pytest.mark.parametrize("trust", [0, 6, -1, 10])
def test_trust_outside_1_to_5_blocks(work, trust):
    assert not run(work, fm_text([finding(trust=trust)]), "Text.\n")["verified_ok"]


@pytest.mark.parametrize("rel", list("ABCDEF"))
def test_reliability_letters_a_to_f_accepted(work, rel):
    assert run(work, fm_text([finding(rel=rel)]), "Text.\n")["verified_ok"]


@pytest.mark.parametrize("rel", ["G", "Z", "0", "AA"])
def test_reliability_outside_a_to_f_blocks(work, rel):
    assert not run(work, fm_text([finding(rel=rel)]), "Text.\n")["verified_ok"]


@pytest.mark.parametrize("bad", [
    {}, {"finding_type": "PRIMARY"}, {"finding_type": "PRIMARY", "trust_score": 3},
    {"trust_score": 3, "source_reliability": "B"},
    finding("RUMOR", 3), finding(confirmed_by="edr"), finding(confirmed_by={"a": 1}),
])
def test_partial_unknown_or_malformed_finding_blocks(work, bad):
    assert not run(work, fm_text([bad]), "Text.\n")["verified_ok"]


def test_confirmed_by_is_optional_and_a_list_is_accepted(work):
    assert run(work, fm_text([finding()]), "Text.\n")["verified_ok"]
    assert run(work, fm_text([finding(confirmed_by=["a", "b"])]), "Text.\n")["verified_ok"]
    assert run(work, fm_text([finding(confirmed_by=[])]), "Text.\n")["verified_ok"]


# ------------------------------------------------------------- findings required, ratchet
def test_report_with_no_findings_is_blocked_by_default(work):
    r = run(work, fm_text(None), "Plain prose only.\n")
    assert not r["verified_ok"] and r["findings_grandfathered"] is False


@pytest.mark.parametrize("date,grandfathered", [
    ("2026-09-30", True), ("2025-01-01", True),
    ("2026-10-01", False), ("2026-10-02", False),
])
def test_ratchet_date_both_sides(work, date, grandfathered):
    r = run(work, fm_text(None, date=date), "Plain prose only.\n",
            findings_required_from="2026-10-01")
    assert r["findings_grandfathered"] is grandfathered
    assert r["verified_ok"] is grandfathered


def test_ratchet_reads_the_file_name_date_and_treats_undated_as_new(work):
    r = run(work, fm_text(None, date=""), "Plain.\n", name="2026-09-01-report.md",
            findings_required_from="2026-10-01")
    assert r["verified_ok"] and r["findings_grandfathered"] is True
    r = run(work, fm_text(None, date=""), "Plain.\n", name="report.md",
            findings_required_from="2026-10-01")
    assert not r["verified_ok"] and r["findings_grandfathered"] is False


def test_ratchet_prefers_the_declared_date_over_the_file_name(work):
    r = run(work, fm_text(None, date="2026-11-01"), "Plain.\n", name="2026-09-01-report.md",
            findings_required_from="2026-10-01")
    assert not r["verified_ok"]


@pytest.mark.parametrize("bad", ["2026-13-01", "2026-02-30", "yesterday", "2026/10/01"])
def test_ratchet_with_a_bad_date_raises_value_error(work, bad):
    with pytest.raises(ValueError):
        run(work, fm_text([finding()]), "Text.\n", findings_required_from=bad)


# ------------------------------------------------------------- frontmatter damage
def test_duplicate_keys_cannot_erase_an_open_conflict(work):
    fm = ("---\ndate: 2026-09-21\nfindings: " + json.dumps([finding()]) +
          "\nconflicts: " + json.dumps([conflict(5, 5)]) + "\nconflicts: []\n---\n")
    r = run(work, fm, "Text.\n")
    assert not r["verified_ok"]


def test_duplicate_keys_nested_also_block(work):
    fm = ("---\ndate: 2026-09-21\nfindings:\n  - finding_type: PRIMARY\n    trust_score: 3\n"
          "    trust_score: 5\n    source_reliability: B\n---\n")
    assert not run(work, fm, "Text.\n")["verified_ok"]


def test_unparseable_frontmatter_blocks_with_a_reason(work):
    r = run(work, "---\nfindings: [unclosed\n---\n", "Text.\n")
    assert not r["verified_ok"] and r["issues"]


# ------------------------------------------------------------- declared sources
def srcs(*items):
    return [dict(zip(("id", "reliability", "derived_from"), it)) if len(it) == 3
            else {"id": it[0], "reliability": it[1]} for it in items]


def test_blog_restating_a_feed_is_not_a_second_confirmation(work):
    s = srcs(("edr", "A"), ("feed", "B"), ("blog", "C", "feed"))
    # trust 4 needs two independent roots: edr and feed
    ok = run(work, fm_text([finding("PRIMARY", 4, confirmed_by=["edr", "feed"])], sources=s), "T.\n")
    assert ok["verified_ok"], ok["issues"]
    ok = run(work, fm_text([finding("PRIMARY", 4, confirmed_by=["edr", "blog"])], sources=s), "T.\n")
    assert ok["verified_ok"], ok["issues"]
    bad = run(work, fm_text([finding("PRIMARY", 4, confirmed_by=["feed", "blog"])], sources=s), "T.\n")
    assert not bad["verified_ok"]


@pytest.mark.parametrize("trust,needs_two", [(1, False), (2, False), (3, False), (4, True), (5, True)])
def test_trust_4_and_5_need_two_independent_sources(work, trust, needs_two):
    s = srcs(("edr", "A"), ("feed", "B"))
    one = run(work, fm_text([finding("PRIMARY", trust, confirmed_by=["edr"])], sources=s), "T.\n")
    two = run(work, fm_text([finding("PRIMARY", trust, confirmed_by=["edr", "feed"])], sources=s), "T.\n")
    assert one["verified_ok"] is (not needs_two)
    assert two["verified_ok"], two["issues"]


def test_with_sources_declared_every_confirmed_by_entry_must_be_declared(work):
    s = srcs(("edr", "A"))
    r = run(work, fm_text([finding("PRIMARY", 3, confirmed_by=["edr", "ghost"])], sources=s), "T.\n")
    assert not r["verified_ok"]
    r = run(work, fm_text([finding("PRIMARY", 3, confirmed_by=["free text"])]), "T.\n")
    assert r["verified_ok"]


def test_unknown_upstream_and_cycles_block(work):
    unknown = srcs(("a", "A", "ghost"))
    cycle = srcs(("a", "A", "b"), ("b", "A", "a"))
    for s in (unknown, cycle):
        r = run(work, fm_text([finding("PRIMARY", 3, confirmed_by=["a"])], sources=s), "T.\n")
        assert not r["verified_ok"], s


@st.composite
def forests(draw):
    n = draw(st.integers(1, 7))
    ids = ["s%d" % i for i in range(n)]
    parent = {}
    items = []
    for i in range(n):
        if i and draw(st.booleans()):
            parent[ids[i]] = ids[draw(st.integers(0, i - 1))]
        d = {"id": ids[i], "reliability": draw(st.sampled_from(list("ABCDEF")))}
        if ids[i] in parent:
            d["derived_from"] = parent[ids[i]]
        items.append(d)
    return items, parent


def root_of(parent, i):
    while i in parent:
        i = parent[i]
    return i


@given(forests(), st.data())
@prop(max_examples=40)
def test_strength_bonus_counts_independent_roots(work, forest, data):
    items, parent = forest
    cited = data.draw(st.lists(st.sampled_from([x["id"] for x in items]), min_size=0, max_size=7))
    roots = {root_of(parent, c) for c in cited}
    r = run(work, fm_text([finding("DERIVED", 3, confirmed_by=cited)], sources=items), "T.\n")
    want = 4 + 0.4 * 3 + min(0.5 * len(roots), 1.5)
    assert r["verified_ok"], r["issues"]
    assert r["findings_graded"][0]["strength"] == pytest.approx(want, abs=0.051)


# ------------------------------------------------------------- judgment wording
def lint(s):
    return standards.lint_judgment(s)


CONNECTORS = [" to ", " or ", " / ", " - ", " – ", " — "]


@given(st.sampled_from(BANDS), st.sampled_from(BANDS), st.sampled_from(CONNECTORS))
@example("likely", "very likely", " to ").via("doc: 'likely to very likely'")
@example("likely", "very likely", " or ").via("doc: connector or")
@example("likely", "very likely", " / ").via("doc: connector slash")
@example("likely", "very likely", " - ").via("doc: connector hyphen")
@example("likely", "very likely", " – ").via("doc: connector en dash")
@example("likely", "very likely", " — ").via("doc: connector em dash")
@prop(max_examples=60)
def test_two_band_terms_joined_form_a_hedged_range(a, b, joiner):
    if a == b:
        b = BANDS[(BANDS.index(a) + 1) % len(BANDS)]
    assert lint("The access is %s%s%s from the vendor." % (a, joiner, b))


@pytest.mark.parametrize("s", [
    "The access is very likely from the vendor.",
    "It is likely. It is very likely.",
    "We assess it is unlikely.",
])
def test_single_terms_are_not_a_hedge(s):
    assert lint(s) == []


@pytest.mark.parametrize("word", ["we assess", "confidence", "confident", "probability"])
@pytest.mark.parametrize("pct", [1, 5, 20, 50, 70, 95, 99])
def test_bare_percentage_in_a_judgment_sentence_is_flagged(word, pct):
    assert lint("Our %s is that it recurs at %d%%." % (word, pct))
    assert lint("Our %s is that it recurs at %d percent." % (word, pct))


@pytest.mark.parametrize("template", ["We are %d%% sure it recurs.", "I am %d percent certain it recurs.",
                                      "It recurs; we're about %d%% sure."])
@pytest.mark.parametrize("pct", [1, 50, 99])
def test_being_n_percent_sure_is_a_judgment(template, pct):
    assert lint(template % pct)


@given(st.integers(1, 99), st.sampled_from(WORDS))
@prop()
def test_percentage_in_a_plain_factual_sentence_is_not_flagged(n, w):
    assert lint("The %s proxy blocked %d%% of requests on 2026-09-21." % (w, n)) == []


def test_attributed_percentage_is_not_the_authors_judgment():
    assert lint("According to the vendor, the probability of reuse is 70%.") == []


@pytest.mark.parametrize("s", [
    "This is 0% likely.", "This is 100% likely.", "A 100.0% match.", "Recovery is guaranteed.",
    "This is impossible.", "We are absolutely certain.", "There is no chance whatsoever.",
    "The actor certainly used it.", "The actor definitely used it.",
    "The actor undoubtedly used it.", "The actor used it without a doubt.",
    "We are absolutely\ncertain.", "We are absolutely   certain.", "There is no chance\nwhatsoever.",
    "The actor used it without a\ndoubt.",
    "Recovery can't be guaranteed.", "Recovery is not-guaranteed.", "Recovery is not at all guaranteed.",
    "The impossible happened.",
])
def test_absolute_language_is_flagged(s):
    assert lint(s)


@pytest.mark.parametrize("s", [
    "Recovery is not guaranteed.", "Recovery is never guaranteed.", "Recovery isn't guaranteed.",
    "Recovery isn’t guaranteed.",
    "The actor almost certainly used it.", "The EDR raised an impossible travel alert.",
    "The EDR raised an impossible-travel alert.",
    "The attack was blocked by 3 controls on 2026-09-21.",
])
def test_documented_exemptions_are_not_flagged(s):
    assert lint(s) == []


@given(st.lists(st.sampled_from(WORDS), max_size=15))
@prop()
def test_neutral_words_are_never_flagged(ws):
    assert lint(" ".join(ws) + ".") == []


@given(st.text(max_size=150))
@prop()
def test_locations_and_problems_agree(t):
    locs = standards.judgment_locations(t)
    probs = lint(t)
    assert len(set(probs)) == len(probs)
    assert set(probs) == {p for _, p, _ in locs}
    for off, _, _ in locs:
        assert 0 <= off <= len(t)


def test_problem_order_is_fixed_whatever_the_sentence_order():
    s1 = "The access is likely to very likely from the vendor."
    s2 = "We are absolutely certain."
    s3 = "Our confidence is 70%."
    for a, b, c in itertools.permutations([s1, s2, s3]):
        assert lint(a + " " + b + " " + c) == lint(s1 + " " + s2 + " " + s3)


# ------------------------------------------------------------- prose band terms and ceiling
@pytest.mark.parametrize("term", BANDS)
def test_prose_terms_finds_each_band_once_with_its_offset(term):
    t = "Our review found the intrusion is %s linked to the vendor." % term
    got = standards.prose_terms(t)
    assert [g[1] for g in got] == [term]
    off, _, words = got[0]
    assert t[off:off + len(words)].lower() == term


@pytest.mark.parametrize("phrase,term", [
    ("probable", "likely"), ("highly probable", "very likely"), ("nearly certain", "almost certain"),
    ("VERY LIKELY", "very likely"),
])
def test_synonyms_and_case_map_to_the_band(phrase, term):
    got = standards.prose_terms("The intrusion is %s linked to the vendor." % phrase)
    assert [g[1] for g in got] == [term]


@pytest.mark.parametrize("t", [
    "The intrusion is not likely to have involved the vendor.",
    'The vendor wrote "very likely" in the ticket.',
    "According to the vendor, the intrusion is very likely linked.",
    "The vendor reports the intrusion is likely linked.",
])
def test_negated_quoted_and_attributed_terms_are_skipped(t):
    assert standards.prose_terms(t) == []


def prose_blocks(work, findings, sentence, **kw):
    r = run(work, fm_text(findings), sentence + "\n", **kw)
    return r


@pytest.mark.parametrize("ftype", ["PRIMARY", "ANECDOTAL", "CONTESTED"])
@pytest.mark.parametrize("trust", [1, 2, 3, 4, 5])
def test_prose_term_is_held_to_the_strongest_declared_finding(work, ftype, trust):
    ci = ceiling_index(ftype, trust)
    for i, term in enumerate(BANDS):
        r = prose_blocks(work, [finding(ftype, trust)],
                         "The intrusion is %s linked to the vendor." % term)
        assert r["verified_ok"] is (False if ci is None else i <= ci), (ftype, trust, term)


def test_strongest_of_several_findings_sets_the_prose_limit(work):
    fs = [finding("PRIMARY", 2), finding("PRIMARY", 4)]
    ok = prose_blocks(work, fs, "The intrusion is very likely linked to the vendor.")
    bad = prose_blocks(work, fs, "The intrusion is almost certain to be linked to the vendor.")
    assert ok["verified_ok"] and not bad["verified_ok"]


# ------------------------------------------------------------- citations
F2 = [finding("PRIMARY", 5, id="F1"), finding("PRIMARY", 2, id="F2")]
VL = "The intrusion is very likely linked to the vendor."


@pytest.mark.parametrize("cite,ok", [
    ("The intrusion is very likely [F2] linked to the vendor.", False),
    ("The intrusion is very likely [F1] linked to the vendor.", True),
    (VL + " [F2]", False),
    (VL + " [F1]", True),
    (VL + " [F1] [F2]", True),
    ("The intrusion is very likely [F2] [F1] linked to the vendor.", True),
    (VL + " [F9]", False),
])
def test_citation_holds_a_term_to_the_cited_ceiling(work, cite, ok):
    r = run(work, fm_text(F2), cite + "\n")
    assert r["verified_ok"] is ok, r["issues"]
    assert r["uncited_judgments"] == []


@pytest.mark.parametrize("term_idx", range(7))
def test_cited_ceiling_has_a_sharp_edge(work, term_idx):
    r = run(work, fm_text(F2), "The intrusion is %s linked to the vendor. [F2]\n" % BANDS[term_idx])
    assert r["verified_ok"] is (term_idx <= 3)


@pytest.mark.parametrize("body", [
    VL + "\n[F2]\n",
    "`[F2]` " + VL + "\n",
    VL + " `[F2]`\n",
    VL + " <!-- [F2] -->\n",
    VL + "\n\n[F2]: https://example.com/x\n",
    VL + " [F2](https://example.com/x)\n",
    VL + " [F2][ref]\n\n[ref]: https://example.com/x\n",
    VL + "\n\n```\n[F2]\n```\n",
])
def test_things_that_are_not_citations_leave_the_term_uncited(work, body):
    r = run(work, fm_text(F2), body)
    assert r["verified_ok"], r["issues"]
    assert len(r["uncited_judgments"]) == 1


def test_require_citations_blocks_the_uncited_and_passes_the_cited(work):
    assert not run(work, fm_text(F2), VL + "\n", require_citations=True)["verified_ok"]
    assert run(work, fm_text(F2), VL + " [F1]\n", require_citations=True)["verified_ok"]


# ------------------------------------------------------------- confidence wording
@pytest.mark.parametrize("s", [
    "We assess with high confidence that the actor returned.",
    "We assess with moderate confidence that the actor returned.",
    "We attribute the delay to patching.",
])
def test_confidence_wording_needs_evidence_on_a_report_with_no_findings(work, s):
    r = run(work, fm_text(None), s + "\n")
    assert any("needs evidence" in i for i in r["issues"]), r["issues"]


@pytest.mark.parametrize("s", [
    "We assess with low confidence that the actor returned.",
    "The vendor reports it has high confidence in the link.",
])
def test_low_and_someone_elses_confidence_are_not_read(work, s):
    r = run(work, fm_text(None), s + "\n")
    assert not any("needs evidence" in i for i in r["issues"]), r["issues"]


@pytest.mark.parametrize("s", [
    "We assess with high confidence that the actor returned.",
    "We assess with moderate confidence that the actor returned.",
    "We attribute the delay to patching.",
])
def test_confidence_has_no_ceiling_and_counts_as_uncited_when_required(work, s):
    weak = [finding("ANECDOTAL", 1, id="W1")]
    assert run(work, fm_text(weak), s + "\n")["verified_ok"]
    assert not run(work, fm_text(weak), s + "\n", require_citations=True)["verified_ok"]
    assert run(work, fm_text(weak), s + " [W1]\n", require_citations=True)["verified_ok"]


# ------------------------------------------------------------- 5W1H threshold
EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_coverage_threshold_both_sides_and_default(work):
    # examples/incident-report-before.md answers 2 of 6 (usage.md, README)
    p = EXAMPLES / "incident-report-before.md"
    if not p.exists():
        pytest.skip("examples not present in an installed copy")
    r2 = validate_report(p, min_5w1h=2)
    r3 = validate_report(p, min_5w1h=3)
    rd = validate_report(p)
    assert r2["coverage_5w1h"] == 2
    assert not any("5W1H" in i for i in r2["issues"])
    assert any("5W1H" in i for i in r3["issues"])
    assert any("5W1H" in i for i in rd["issues"])
    after = validate_report(EXAMPLES / "incident-report-after.md")
    assert after["coverage_5w1h"] == 6 and after["verified_ok"]


@given(st.text(max_size=80), st.text(max_size=80))
@prop()
def test_appending_text_never_loses_an_answered_dimension(a, b):
    ca = standards.coverage_5w1h(a)["answered"]
    cab = standards.coverage_5w1h(a + "\n" + b)["answered"]
    assert set(ca) == {"who", "what", "when", "where", "why", "how"}
    for k, v in ca.items():
        assert cab[k] or not v


# ------------------------------------------------------------- identifiers
BASE_FM = fm_text([finding()])


@pytest.mark.parametrize("cve,bad", [
    ("CVE-2021-44228", False), ("CVE-1999-0001", False), ("CVE-2026-12345", False),
    ("CVE-2021-1234", False), ("CVE-2021-123456789", False),
    ("CVE-2021-123", True), ("CVE-2021-12", True), ("CVE-2021-1", True),
    ("CVE-1998-1234", True), ("CVE-1990-12345", True),
])
def test_cve_shape_limits_are_checked_without_any_file(work, cve, bad):
    r = run(work, BASE_FM, "The loader exploits %s on the host.\n" % cve)
    assert (not r["verified_ok"]) is bad, r["issues"]


def test_without_reference_files_ids_are_counted_not_checked_and_still_pass(work):
    r = run(work, BASE_FM, "Seen: T1059 and CVE-2021-44228.\n")
    assert r["verified_ok"]
    assert r["identifiers"]["attack"]["checked"] is False
    assert r["identifiers"]["kev"]["checked"] is False


def stix(path, objs):
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--" + str(uuid.uuid4()),
                                "spec_version": "2.0", "objects": objs}), encoding="utf-8")


def tech(tid, name, **kw):
    d = {"type": "attack-pattern", "id": "attack-pattern--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, tid)),
         "name": name, "external_references": [{"source_name": "mitre-attack", "external_id": tid}]}
    d.update(kw)
    return d


@pytest.fixture(scope="module")
def refs(home_and_work):
    d = home_and_work / "refs"
    d.mkdir()
    phish = tech("T1566", "Phishing")
    old = tech("T1111", "Old Technique", revoked=True)
    objs = [tech("T1059", "Command and Scripting Interpreter"),
            tech("T1059.001", "PowerShell", x_mitre_is_subtechnique=True),
            phish, old, tech("T1222", "Deprecated Technique", x_mitre_deprecated=True),
            {"type": "relationship", "id": "relationship--" + str(uuid.uuid4()),
             "relationship_type": "revoked-by", "source_ref": old["id"], "target_ref": phish["id"]}]
    stix(d / "attack.json", objs)
    (d / "kev.json").write_text(json.dumps({
        "title": "KEV", "catalogVersion": "2026.10.01", "count": 1,
        "vulnerabilities": [{"cveID": "CVE-2021-44228"}]}), encoding="utf-8")
    (d / "bad.json").write_text("{\"hello\": 1}", encoding="utf-8")
    return d


def check_json(work, body, refs_dir, attack=True, kev=True, extra=()):
    p = newdir(work) / "r.md"
    p.write_text(BASE_FM + body, encoding="utf-8")
    argv = ["check", str(p), "--min-5w1h", "0", "--json"]
    if attack:
        argv += ["--attack-json", str(refs_dir / "attack.json")]
    if kev:
        argv += ["--kev-json", str(refs_dir / "kev.json")]
    code, out, _ = cli_run(argv + list(extra))
    return code, json.loads(out) if out.strip().startswith("{") else None


@pytest.mark.parametrize("text,ok", [
    ("Used T1059 Command and Scripting Interpreter.", True),
    ("Used T1059.", True),
    ("T1059.001 Command and Scripting Interpreter: PowerShell ran.", True),
    ("T1566 Phishing was seen.", True),
    ("Used T9999 here.", False),
    ("Used T1111 here.", False),
    ("Used T1222 here.", False),
    ("Used T1059 Phishing here.", False),
])
def test_attack_ids_unknown_revoked_deprecated_and_mismatched(work, refs, text, ok):
    code, res = check_json(work, text + "\n", refs, kev=False)
    assert res["identifiers"]["attack"]["checked"] is True
    assert (code == 0) is ok, res["issues"]
    assert res["verified_ok"] is ok


def test_revoked_technique_names_its_replacement(work, refs):
    _, res = check_json(work, "Used T1111 here.\n", refs, kev=False)
    assert any("T1566" in i or "Phishing" in i for i in res["issues"])


@pytest.mark.parametrize("text,ok", [
    ("CVE-2021-44228 is exploited in the wild.", True),
    ("CVE-2022-12345 is exploited in the wild.", False),
    ("CVE-2022-12345 is actively exploited.", False),
    ("CVE-2022-12345 is weaponized.", False),
    ("According to the vendor, CVE-2022-12345 is exploited in the wild.", True),
    ("There is no evidence CVE-2022-12345 is exploited in the wild.", True),
    ("CVE-2022-12345 is not known to be exploited in the wild.", True),
    ("Patched or not, CVE-2022-12345 is exploited in the wild.", True),
    ("CVE-2022-12345 was patched last year.", True),
    ("No patch exists. CVE-2022-12345 is exploited in the wild.", False),
])
def test_kev_exploitation_claims(work, refs, text, ok):
    code, res = check_json(work, text + "\n", refs, attack=False)
    assert res["identifiers"]["kev"]["checked"] is True
    assert (code == 0) is ok, res["issues"]


def test_kev_negation_is_per_clause_split_at_semicolons(work, refs):
    code, _ = check_json(work, "Nothing else is known; CVE-2022-12345 is exploited in the wild.\n",
                         refs, attack=False)
    assert code == 1


def test_reference_file_problems_and_require_references_are_exit_2(work, refs):
    p = newdir(work) / "r.md"
    p.write_text(BASE_FM + "Text.\n", encoding="utf-8")
    assert cli_run(["check", str(p), "--min-5w1h", "0", "--attack-json", str(refs / "bad.json")])[0] == 2
    assert cli_run(["check", str(p), "--min-5w1h", "0", "--kev-json", str(refs / "attack.json")])[0] == 2
    assert cli_run(["check", str(p), "--min-5w1h", "0", "--attack-json", str(refs / "nope.json")])[0] == 2
    assert cli_run(["check", str(p), "--min-5w1h", "0", "--require-references"])[0] == 2
    assert cli_run(["check", str(p), "--min-5w1h", "0", "--require-references",
                    "--attack-json", str(refs / "attack.json")])[0] == 2
    assert cli_run(["check", str(p), "--min-5w1h", "0", "--require-references",
                    "--attack-json", str(refs / "attack.json"),
                    "--kev-json", str(refs / "kev.json")])[0] == 0
    assert cli_run(["check", str(p), "--min-5w1h", "0"])[0] == 0


# ------------------------------------------------------------- check exit codes
def test_check_exit_codes_pass_block_not_evaluable_usage(work):
    d = newdir(work)
    good, blocked, bad_utf8 = d / "g.md", d / "b.md", d / "u.md"
    good.write_text(BASE_FM + "Text.\n", encoding="utf-8")
    blocked.write_text("No findings declared at all.\n", encoding="utf-8")
    bad_utf8.write_bytes(BASE_FM.encode() + b"\xff\xfe text\n")
    assert cli_run(["check", str(good), "--min-5w1h", "0"])[0] == 0
    assert cli_run(["check", str(blocked), "--min-5w1h", "0"])[0] == 1
    assert cli_run(["check", str(d / "missing.md")])[0] == 2
    assert cli_run(["check", str(d)])[0] == 2
    assert cli_run(["check", str(bad_utf8)])[0] == 2
    assert cli_run(["check"])[0] == 64
    assert cli_run(["check", str(good), "--no-such-option"])[0] == 64


def test_json_output_matches_the_documented_fields(work):
    d = newdir(work)
    p = d / "g.md"
    p.write_text(BASE_FM + "Text.\n", encoding="utf-8")
    code, out, _ = cli_run(["check", str(p), "--min-5w1h", "0", "--json"])
    res = json.loads(out)
    assert code == 0 and res["verified_ok"] is True
    assert {"issues", "findings_grandfathered", "identifiers", "uncited_judgments"} <= set(res)


# ------------------------------------------------------------- skeleton
def test_skeleton_lists_each_judgment_at_the_weakest_grade_and_writes_nothing(work):
    yaml = pytest.importorskip("yaml")
    d = newdir(work)
    p = d / "plain.md"
    body = ("The intrusion is very likely linked to the vendor.\n"
            "The loader is likely reused. The actor is unlikely to return.\n")
    p.write_text(body, encoding="utf-8")
    before = p.read_bytes()
    code, out, _ = cli_run(["skeleton", str(p)])
    assert code == 0 and p.read_bytes() == before
    lines = out.strip().splitlines()
    assert lines[0] == "---" and lines[-1] == "---"
    data = yaml.safe_load("\n".join(lines[1:-1]))
    assert len(data["findings"]) == 3
    for f in data["findings"]:
        assert (f["finding_type"], f["trust_score"], f["source_reliability"]) == ("ANECDOTAL", 1, "F")
        assert not f.get("confirmed_by")
    # the starter block keeps the report blocking
    p2 = d / "filled.md"
    p2.write_text(out + body, encoding="utf-8")
    assert cli_run(["check", str(p2), "--min-5w1h", "0"])[0] == 1


def test_skeleton_with_existing_frontmatter_prints_only_the_findings_lines(work):
    d = newdir(work)
    p = d / "fm.md"
    p.write_text("---\ndate: 2026-09-21\n---\nThe intrusion is very likely linked to the vendor.\n",
                 encoding="utf-8")
    code, out, _ = cli_run(["skeleton", str(p)])
    assert code == 0 and out.lstrip().startswith("findings:") and "---" not in out


# ------------------------------------------------------------- redaction: builders (independent)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(version, payload):
    raw = bytes([version]) + payload
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    n = int.from_bytes(raw, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + s


CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _poly(v):
    g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    c = 1
    for x in v:
        b = c >> 25
        c = (c & 0x1ffffff) << 5 ^ x
        for i in range(5):
            c ^= g[i] if (b >> i) & 1 else 0
    return c


def bech(witver, prog, m=False):
    acc = bits = 0
    out = []
    for b in prog:
        acc = acc << 8 | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    d = [witver] + out
    hrp = [ord(x) >> 5 for x in "bc"] + [0] + [ord(x) & 31 for x in "bc"]
    pm = _poly(hrp + d + [0] * 6) ^ (0x2bc830a3 if m else 1)
    return "bc1" + "".join(CH[x] for x in d + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def iban_with_check(cc, bban):
    n = int("".join(str(int(c, 36)) for c in bban + cc + "00"))
    return cc + "%02d" % (98 - n % 97) + bban


def values(m):
    return list(m.values())


# ------------------------------------------------------------- redaction: round trip
@given(st.text(max_size=300))
@prop()
def test_round_trip_is_exact_for_any_text(t):
    out, m = R.redact(t)
    assert R.restore(out, m) == t


TOKENS = ["a@b.example", "192.0.2.7", "https://x.example/p?q=1", "2001:db8::1", "\r\n", "\r", "\n",
          "_", "*", "`", "[", "]", "key=", "key:", "\u200b", "\u00ad", "+1 202 555 0143",
          "[EMAIL_1#abcdef]", "[IPV4_2]", "\u2060", "\ufeff", "john@[192.0.2.1]", "fe80::1%eth0"]


@given(st.lists(st.sampled_from(TOKENS + WORDS), max_size=14), st.sampled_from([" ", "", "\n", "\r\n"]))
@prop(max_examples=80)
def test_round_trip_exact_for_mixed_tokens_and_line_endings(parts, sep):
    t = sep.join(parts)
    out, m = R.redact(t)
    assert R.restore(out, m) == t


@given(st.lists(st.sampled_from(WORDS), max_size=10))
@prop()
def test_text_without_personal_data_is_unchanged_with_an_empty_map(ws):
    t = " ".join(ws)
    out, m = R.redact(t)
    assert out == t and m == {} and R.map_nonce(m) is None


PH = re.compile(r"\[([A-Z0-9]+)_(\d+)#([0-9a-f]{6})\]")


@given(st.sampled_from(WORDS), st.sampled_from(WORDS))
@prop()
def test_email_is_one_numbered_placeholder_with_a_six_hex_nonce(a, b):
    e = "%s.%s@%s.example" % (a, b, b)
    t = "write to %s today, again %s." % (e, e)
    out, m = R.redact(t)
    assert e not in out and values(m) == [e]
    (k,) = m
    mt = PH.fullmatch(k)
    assert mt and mt.group(1) == "EMAIL" and mt.group(2) == "1"
    assert out.count(k) == 2
    assert R.map_nonce(m) == mt.group(3) and mt.group(3) not in t
    assert R.restore(out, m) == t


@given(st.tuples(*[st.integers(0, 255)] * 4))
@example((0, 0, 0, 0)).via("doc: octet lower edge")
@example((255, 255, 255, 255)).via("doc: octet upper edge")
@prop(max_examples=60)
def test_ipv4_is_redacted_as_ipv4(o):
    ip = ".".join(map(str, o))
    t = "host %s seen" % ip
    out, m = R.redact(t)
    assert ip not in out and values(m) == [ip] and PH.search(out).group(1) == "IPV4"
    assert R.restore(out, m) == t


@given(st.lists(st.integers(0, 0xffff), min_size=8, max_size=8))
@prop()
def test_full_ipv6_is_redacted_as_ipv6(g):
    ip = ":".join("%x" % x for x in g)
    out, m = R.redact("host %s seen" % ip)
    assert ip not in out and values(m) == [ip] and PH.search(out).group(1) == "IPV6"


@pytest.mark.parametrize("ip", ["2001:db8::1", "2001:db8::/32", "fe80::1%eth0", "::1", "a::b",
                                "fade::cafe", "dead::beef", "[IPv6:2001:db8::1]"])
def test_ipv6_forms_in_the_docs_are_redacted(ip):
    out, m = R.redact("host %s seen" % ip)
    assert out != "host %s seen" % ip and m
    assert R.restore(out, m) == "host %s seen" % ip


@pytest.mark.parametrize("keep", ["13:47", "13:47:05", "00:1a:2b:3c:4d:5e", "AA-BB-CC-DD-EE-FF",
                                  "a bare :: in prose"])
def test_clock_times_mac_addresses_and_bare_double_colon_survive(keep):
    t = "seen at %s today" % keep
    out, m = R.redact(t)
    assert out == t and m == {}


def test_windows_interface_name_with_a_space_leaves_the_tail_in_clear():
    out, m = R.redact("x fe80::1%Ethernet 2 y")
    assert out.endswith(" 2 y") and "fe80::1%Ethernet" in values(m)


@pytest.mark.parametrize("scheme", ["http", "https", "ftp", "sftp", "hxxp", "hxxps", "HXXPS", "HxxP"])
def test_documented_url_schemes_are_redacted(scheme):
    url = scheme + "://host.example/a/b?q=1"
    out, m = R.redact("see %s ok" % url)
    assert url not in out and url in values(m)


def test_www_form_is_redacted():
    out, m = R.redact("see www.host.example/a ok")
    assert "www.host.example/a" not in out and m


@pytest.mark.parametrize("url", ["ftps://host.example/a", "file:///var/log/x", "ssh://host.example/a"])
def test_other_schemes_stay_in_clear(url):
    t = "see %s ok" % url
    assert R.redact(t)[0] == t


@given(st.sampled_from(WORDS), st.sampled_from(WORDS))
@prop()
def test_url_holding_an_email_is_one_span(h, u):
    e = "%s@%s.example" % (u, h)
    url = "https://%s.example/p?mail=%s" % (h, e)
    out, m = R.redact("see %s ok" % url)
    assert values(m) == [url] and e not in out


@pytest.mark.parametrize("trail", [".", ",", ";", ":", "!", "?", "*", "_"])
def test_trailing_punctuation_stays_out_of_the_url(trail):
    out, m = R.redact("see https://host.example/a/b%s" % trail)
    assert values(m) == ["https://host.example/a/b"] and out.endswith(trail)


@pytest.mark.parametrize("keep", [
    "192[.]0[.]2[.]1", "192.0.2[.]1", "john(at)example.com", "john [at] example.com",
    '"john doe"@example.com', "x@localhost", "john@example",
    "2026-09-21", "21.09.2026", "CVE-2021-44228", "CWE-79", "CAPEC-66",
    "GHSA-abcd-efgh-ijkl", "OSV-2021-1234", "EDB-ID-50592", "KB5005565",
])
def test_documented_clear_text_is_left_alone(keep):
    t = "indicator %s seen" % keep
    out, _ = R.redact(t)
    assert keep in out


@pytest.mark.parametrize("keep", ["CVE-2021-44228", "KB5005565", "2026-09-21", "21.09.2026"])
def test_dates_and_ids_never_hide_a_phone_number_next_to_them(keep):
    t = "%s +44 20 7946 0958" % keep
    out, m = R.redact(t)
    assert keep in out and "+44 20 7946 0958" not in out and R.restore(out, m) == t


@pytest.mark.parametrize("addr", ["john@[192.0.2.1]", "john@[IPv6:2001:db8::1]"])
def test_address_literal_email_is_redacted_whole(addr):
    out, m = R.redact("x %s y" % addr)
    assert addr in values(m) and out.startswith("x [") and "john" not in out


@pytest.mark.parametrize("addr", ["john@[IPv6:", "john@[IPv6:fe80::1%eth0]", "john@[192.0.2.1:25]", "john@[::1]"])
def test_non_standard_address_literals_keep_the_local_part(addr):
    t = "x %s y" % addr
    out, m = R.redact(t)
    assert "john@" in out and R.restore(out, m) == t


# IBAN and Bitcoin: standard published examples, and checksummed values built here
@pytest.mark.parametrize("iban", ["GB82WEST12345698765432", "DE89370400440532013000"])
def test_published_example_ibans_are_redacted_compact_grouped_and_lowercase(iban):
    groups = [iban[i:i + 4] for i in range(0, len(iban), 4)]
    for form in (iban, " ".join(groups), "-".join(groups), iban.lower(), " ".join(groups).lower()):
        t = "acct %s end" % form
        out, m = R.redact(t)
        assert form in values(m), form
        assert R.restore(out, m) == t


@pytest.mark.parametrize("iban", ["GB82WEST12345698765432", "DE89370400440532013000"])
def test_iban_with_wrong_check_digits_is_not_an_iban(iban):
    bad = iban[:2] + ("%02d" % ((int(iban[2:4]) + 1) % 100)) + iban[4:]
    out, m = R.redact("acct %s end" % bad)
    assert bad not in values(m)


@pytest.mark.parametrize("iban", ["GB82-WEST-1234-5698-7654 32", "GB82 WEST-1234 5698-7654 32"])
def test_iban_groups_joined_by_a_mix_are_not_redacted_whole(iban):
    assert iban not in values(R.redact("acct %s end" % iban)[1])


@given(st.text("0123456789", min_size=10, max_size=10))
@prop()
def test_built_gb_iban_is_redacted_and_one_bad_check_is_not(digits):
    ib = iban_with_check("GB", "NWBK" + "601613" + digits[:8])
    assert ib in values(R.redact("acct %s end" % ib)[1])
    bad = ib[:2] + ("%02d" % ((int(ib[2:4]) % 97) + 1)) + ib[4:]
    assert bad not in values(R.redact("acct %s end" % bad)[1])


@pytest.mark.parametrize("addr", [
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
])
def test_published_bitcoin_addresses_are_redacted(addr):
    t = "pay %s now" % addr
    out, m = R.redact(t)
    assert addr not in out and addr in values(m) and R.restore(out, m) == t


@given(st.binary(min_size=20, max_size=20), st.sampled_from([0, 5]))
@prop()
def test_base58check_address_is_redacted_and_a_changed_last_char_is_not(h, ver):
    a = b58check(ver, h)
    assert a in values(R.redact("pay %s now" % a)[1])
    bad = a[:-1] + ("2" if a[-1] != "2" else "3")
    assert bad not in values(R.redact("pay %s now" % bad)[1])


@given(st.binary(min_size=20, max_size=20))
@prop()
def test_bech32_address_is_redacted(h):
    a = bech(0, h)
    out, m = R.redact("pay %s now" % a)
    assert a in values(m) and R.restore(out, m) == "pay %s now" % a


@given(st.binary(min_size=32, max_size=32))
@prop()
def test_bech32m_address_is_redacted(k):
    a = bech(1, k, True)
    assert a in values(R.redact("pay %s now" % a)[1])


@given(st.binary(min_size=20, max_size=20), st.sampled_from(["_%s_", "*%s*", "`%s`", "(%s)", "[%s]", "key: %s", "key=%s"]))
@prop()
def test_value_next_to_markdown_brackets_and_keys_is_found(h, fmt):
    a = b58check(0, h)
    t = fmt % a
    out, m = R.redact(t)
    assert a not in out and R.restore(out, m) == t


@pytest.mark.parametrize("phone", ["+44 20 7946 0958", "+1 202-555-0143"])
def test_international_phone_numbers_are_redacted(phone):
    out, m = R.redact("call %s now" % phone)
    assert phone not in out and m


def test_phone_number_run_into_an_extension_keeps_the_extension():
    out, m = R.redact("call +44 20 7946 0958x123 now")
    assert "x123" in out


# ------------------------------------------------------------- invisible characters
def _cp(*ranges):
    out = []
    for r in ranges:
        lo, hi = (r, r) if isinstance(r, int) else r
        out += [lo, hi] if lo != hi else [lo]
    return out


# every documented range, both ends
INVISIBLE = _cp(0x00AD, 0x061C, 0x180E, (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064),
                (0x2066, 0x206F), 0xFEFF, (0xFFF9, 0xFFFB), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3),
                (0x1D173, 0x1D17A), 0xE0001, (0xE0020, 0xE007F), 0x034F, (0xFE00, 0xFE0F),
                (0xE0100, 0xE01EF), (0x180B, 0x180D))


@pytest.mark.parametrize("cp", INVISIBLE)
def test_documented_invisible_character_inside_an_email_is_still_one_email(cp):
    e = "bob@exam%sple.com" % chr(cp)
    t = "x %s y" % e
    out, m = R.redact(t)
    assert values(m) == [e], hex(cp)
    assert R.restore(out, m) == t


@pytest.mark.parametrize("cp", [0x0600, 0x0605, 0x06DD, 0x070F, 0x0890, 0x0891, 0x08E2, 0x110BD, 0x110CD,
                                0x2800, 0x3000])
def test_documented_not_handled_characters_split_the_email(cp):
    e = "bob@exam%sple.com" % chr(cp)
    t = "x %s y" % e
    out, m = R.redact(t)
    assert e not in values(m)
    assert R.restore(out, m) == t


@given(st.sampled_from(WORDS), st.lists(st.sampled_from(INVISIBLE), min_size=1, max_size=4))
@prop()
def test_several_invisible_characters_in_one_email_restore_in_place(w, cps):
    e = "%s@%s.example" % (w, w)
    pos = len(e) // 2
    e2 = e[:pos] + "".join(chr(c) for c in cps) + e[pos:]
    out, m = R.redact("a " + e2 + " b")
    assert R.restore(out, m) == "a " + e2 + " b"


@pytest.mark.parametrize("cp", [0x115F, 0x1160, 0x3164, 0xFFA0])
def test_hangul_fillers_are_not_removed_and_still_round_trip(cp):
    t = "x bob@exam%sple.com y" % chr(cp)
    out, m = R.redact(t)
    assert R.restore(out, m) == t


# ------------------------------------------------------------- map behaviour
@given(st.sampled_from(WORDS), st.sampled_from(WORDS))
@prop()
def test_seeded_map_keeps_numbering_and_nonce_across_texts(a, b):
    if a == b:
        b = b + "x"
    o1, m = R.redact("mail %s@x.example" % a)
    o2, m2 = R.redact("mail %s@x.example and %s@x.example" % (a, b), dict(m))
    assert all(m2[k] == v for k, v in m.items())
    assert len(m2) == 2 and R.map_nonce(m2) == R.map_nonce(m)
    assert R.restore(o1, m2) == "mail %s@x.example" % a


@given(st.sampled_from(WORDS), st.integers(0, 999))
@prop()
def test_redacting_a_document_twice_with_one_map_is_refused(a, n):
    out, m = R.redact("mail %s%d@x.example" % (a, n))
    with pytest.raises(ValueError):
        R.redact(out, dict(m))


@given(st.sampled_from(WORDS), st.sampled_from(WORDS))
@prop()
def test_restore_refuses_a_missing_placeholder_and_another_maps_text(a, b):
    out, m = R.redact("mail %s@x.example and %s@y.example" % (a, b))
    k = next(iter(m))
    short = {kk: v for kk, v in m.items() if kk != k}
    with pytest.raises(KeyError):
        R.restore(out, short)
    o2, m2 = R.redact("mail %s@z.example" % a)
    if PH.search(o2).group(3) != PH.search(out).group(3):
        with pytest.raises(KeyError):
            R.restore(out, m2)


@pytest.mark.parametrize("bad", [{"nokey": "v"}, {"[EMAIL_1#abcdef]": 5}, {"[NOPE_1#abcdef]": "v"},
                                 {"[EMAIL_1#abcdef]": "v", "[EMAIL_2#123456]": "w"}])
def test_malformed_maps_raise_value_error(bad):
    with pytest.raises(ValueError):
        R.restore("text", bad)


def test_restore_is_one_non_recursive_pass():
    out, m = R.redact("a@b.example c@d.example")
    k1 = [k for k, v in m.items() if v == "a@b.example"][0]
    k2 = [k for k, v in m.items() if v == "c@d.example"][0]
    m2 = dict(m)
    m2[k1] = k2
    assert R.restore(out, m2) == k2 + " c@d.example"


def test_text_that_only_looks_like_a_placeholder_is_not_mistaken_for_one():
    t = "A report shows [EMAIL_1] and [URL_9#aaaaaa] beside a@b.example."
    out, m = R.redact(t)
    assert R.restore(out, m) == t


def test_the_same_address_written_two_ways_gets_two_placeholders():
    out, m = R.redact("seen 2001:db8::1 and 2001:0db8::1")
    assert sorted(values(m)) == ["2001:0db8::1", "2001:db8::1"]


# ------------------------------------------------------------- adversarial size
@pytest.mark.parametrize("make", [
    lambda: "1" * 65536, lambda: "a" * 65535 + "@", lambda: ":" * 65536, lambda: "a@" * 32768,
    lambda: "http://" * 9362, lambda: "[IPv6:" * 10922, lambda: "1." * 32768, lambda: "-" * 65536,
    lambda: "+1 " * 21845, lambda: "\u200b" * 65536, lambda: "a." * 32768 + "@x",
])
def test_64kb_adversarial_inputs_finish_and_round_trip(make):
    t = make()
    t0 = time.monotonic()
    out, m = R.redact(t)
    assert time.monotonic() - t0 < 20
    assert R.restore(out, m) == t


# ------------------------------------------------------------- redact and restore commands
def files(work):
    d = newdir(work)
    return d, d / "in.md", d / "map.json", d / "out.md"


@given(st.lists(st.sampled_from(TOKENS + WORDS), max_size=10),
       st.sampled_from(["\n", "\r\n", "\r"]))
@prop(max_examples=20)
def test_commands_round_trip_is_byte_exact_with_every_line_ending(work, parts, nl):
    d, src, mp, red = files(work)
    data = nl.join(parts).encode("utf-8")
    src.write_bytes(data)
    assert cli_run(["redact", str(src), "--map", str(mp), "-o", str(red)])[0] == 0
    back = d / "back.md"
    assert cli_run(["restore", str(red), "--map", str(mp), "-o", str(back)])[0] == 0
    assert back.read_bytes() == data


def test_redact_reports_span_counts_and_writes_map_and_output_at_mode_0600(work):
    d, src, mp, red = files(work)
    src.write_text("mail a@b.example and c@d.example\n", encoding="utf-8")
    code, out, err = cli_run(["redact", str(src), "--map", str(mp), "-o", str(red)])
    assert code == 0
    assert (out + err).strip() == "redacted 2 span(s) (2 new); map -> %s" % mp
    assert json.loads(mp.read_text()) and stat.S_IMODE(os.stat(mp).st_mode) == 0o600
    back = d / "back.md"
    cli_run(["restore", str(red), "--map", str(mp), "-o", str(back)])
    assert stat.S_IMODE(os.stat(back).st_mode) == 0o600
    # a second file on the same map adds only what is new
    src2 = d / "in2.md"
    src2.write_text("again a@b.example and e@f.example\n", encoding="utf-8")
    code, out, err = cli_run(["redact", str(src2), "--map", str(mp), "-o", str(d / "o2.md")])
    assert code == 0 and "(1 new)" in out + err
    assert len(json.loads(mp.read_text())) == 3


def test_redact_exit_codes(work):
    d, src, mp, red = files(work)
    src.write_text("mail a@b.example\n", encoding="utf-8")
    assert cli_run(["redact", str(d / "none.md"), "--map", str(mp), "-o", str(red)])[0] == 2
    assert cli_run(["redact", str(src), "--map", str(src), "-o", str(red)])[0] == 64
    assert cli_run(["redact", str(src), "--map", str(mp), "-o", str(src)])[0] == 64
    assert cli_run(["redact", str(src), "--map", str(red), "-o", str(red)])[0] == 64
    link = d / "hard.md"
    os.link(src, link)
    assert cli_run(["redact", str(src), "--map", str(mp), "-o", str(link)])[0] == 64
    assert cli_run(["redact", str(src), "--map", str(mp), "-o", str(red)])[0] == 0
    # redacting output that already carries this map's placeholders is refused
    assert cli_run(["redact", str(red), "--map", str(mp), "-o", str(d / "twice.md")])[0] == 1
    assert cli_run(["redact"])[0] == 64


def test_restore_exit_codes(work):
    d, src, mp, red = files(work)
    src.write_text("mail a@b.example and c@d.example\n", encoding="utf-8")
    cli_run(["redact", str(src), "--map", str(mp), "-o", str(red)])
    full = json.loads(mp.read_text())
    short = dict(list(full.items())[:1])
    sp = d / "short.json"
    sp.write_text(json.dumps(short), encoding="utf-8")
    assert cli_run(["restore", str(red), "--map", str(sp), "-o", str(d / "x.md")])[0] == 1
    assert not (d / "x.md").exists()
    assert cli_run(["restore", str(red), "--map", str(d / "none.json"), "-o", str(d / "y.md")])[0] == 2
    bad = d / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert cli_run(["restore", str(red), "--map", str(bad), "-o", str(d / "y.md")])[0] == 2
    dup = d / "dup.json"
    k = next(iter(full))
    dup.write_text('{"%s": "a", "%s": "b"}' % (k, k), encoding="utf-8")
    assert cli_run(["restore", str(red), "--map", str(dup), "-o", str(d / "y.md")])[0] == 2
    assert cli_run(["restore", str(red), "--map", str(mp), "-o", str(red)])[0] == 64
    assert cli_run(["restore", str(red), "--map", str(mp), "-o", str(d / "ok.md")])[0] == 0
    assert (d / "ok.md").read_bytes() == src.read_bytes()
