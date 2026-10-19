"""Analytic-standards behavior pins, in both directions.

Good analytic language must pass the lint and weak evidence must cap the
likelihood, but a well-evidenced strong judgment must NOT be capped, and a
report that answers 5W1H must NOT be flagged.
"""
from __future__ import annotations

import time

import pytest

from cti_report_lint import standards as A


# ── likelihood language ─────────────────────────────────────────────────

def test_band_table_is_icd_203():
    """The seven ICD 203 estimative-language bands (the same table as the
    MISP estimative-language taxonomy and cti-expert's handbook)."""
    assert A.LIKELIHOOD_BANDS == [
        ("almost no chance", 1, 5),
        ("very unlikely", 5, 20),
        ("unlikely", 20, 45),
        ("roughly even chance", 45, 55),
        ("likely", 55, 80),
        ("very likely", 80, 95),
        ("almost certain", 95, 99),
    ]


def test_term_bands_map_correctly():
    assert A.likelihood_term(3) == "almost no chance"
    assert A.likelihood_term(50) == "roughly even chance"
    assert A.likelihood_term(70) == "likely"
    assert A.likelihood_term(97) == "almost certain"


def test_zero_and_hundred_rejected():
    with pytest.raises(ValueError):
        A.likelihood_term(0)
    with pytest.raises(ValueError):
        A.likelihood_term(100)


# ── weak evidence caps likelihood ───────────────────────────────────────

def test_anecdotal_caps_at_roughly_even():
    assert A.ceiling_for("ANECDOTAL", 2) == "roughly even chance"
    assert A.ceiling_for("ANECDOTAL", 5) == "roughly even chance"   # type caps trust
    assert A.ceiling_for("ANECDOTAL", 1) is None
    # "almost certain" on a single unverified source overshoots
    assert A.exceeds_ceiling("almost certain", "ANECDOTAL", 1) is True


def test_contested_permits_no_single_judgment():
    assert A.ceiling_for("CONTESTED", 5) is None
    assert A.exceeds_ceiling("roughly even chance", "CONTESTED", 5) is True


def test_strong_evidence_is_NOT_capped():
    # the other direction: a PRIMARY finding CAN carry the top term
    assert A.ceiling_for("PRIMARY", 5) == "almost certain"
    assert A.exceeds_ceiling("almost certain", "PRIMARY", 5) is False
    assert A.exceeds_ceiling("very likely", "CONFIRMED", 5) is False


def test_high_likelihood_weak_evidence_is_expressible_below_ceiling():
    # "likely" needs trust 3; trust 2 supports "roughly even chance" at best
    assert A.exceeds_ceiling("likely", "DERIVED", 3) is False
    assert A.exceeds_ceiling("roughly even chance", "DERIVED", 2) is False
    assert A.exceeds_ceiling("likely", "DERIVED", 2) is True


@pytest.mark.parametrize("trust,term", [
    (5, "almost certain"), (4, "very likely"), (3, "likely"),
    (2, "roughly even chance"), (1, None),
])
def test_ceiling_per_trust_level_matches_cti_expert(trust, term):
    """cti-expert handbook/analytic-standards.md, "Mapping to the existing
    scales". Pinned per level so a one-notch drift cannot recur silently."""
    assert A.ceiling_for("DERIVED", trust) == term


def test_primary_or_confirmed_type_does_not_lift_the_trust_ceiling():
    # the evidence grade is the trust score; the type can only lower it
    assert A.ceiling_for("CONFIRMED", 3) == "likely"
    assert A.ceiling_for("PRIMARY", 2) == "roughly even chance"
    assert A.exceeds_ceiling("very likely", "CONFIRMED", 3) is True


# ── judgment lint: the three malpractices ───────────────────────────────

def test_lint_flags_hedged_range():
    assert any("hedged" in p for p in
               A.lint_judgment("This is likely to very likely a campaign."))


def test_lint_flags_bare_percentage():
    assert any("bare percentage" in p for p in
               A.lint_judgment("There is a 73% probability of attribution."))


def test_lint_flags_absolutes():
    assert any("absolute" in p for p in
               A.lint_judgment("Attribution is absolutely certain."))


def test_clean_judgment_passes_lint():
    good = ("Attribution to the tracked group is very likely based on shared "
            "tooling (moderate confidence: two corroborating vendor reports).")
    assert A.lint_judgment(good) == []


# ── the percentage rule is scoped to JUDGMENT sentences ──────────────────

def test_attributed_vendor_percentage_is_not_flagged():
    # sourced data at its real value; rewording it to clear a gate destroys data
    assert A.lint_judgment(
        "Vendor X reporting that identity-based attacks are ~90% of "
        "incidents this year.") == []


def test_own_judgment_percentage_STILL_flags():
    # the negative control: a scoping change that silences this is worse
    # than the false positive it fixed
    assert any("bare percentage" in p for p in A.lint_judgment(
        "We assess with 90% confidence that the actor is state-aligned."))


def test_judgment_percentage_flags_across_hard_wrap():
    # prose hard-wraps mid-sentence; a per-line scope would go blind
    assert any("bare percentage" in p for p in A.lint_judgment(
        "We assess with\n90% confidence that the tooling is shared."))


def test_attributed_judgment_is_exempt():
    assert A.lint_judgment(
        "Per vendor telemetry we estimate 60% coverage of the botnet.") == []


# ── 5W1H coverage overlay ───────────────────────────────────────────────

def test_coverage_detects_missing_dimensions():
    thin = "A new ransomware strain was observed."  # what + when only
    cov = A.coverage_5w1h(thin)
    assert "why" in cov["missing"]
    assert cov["score"] < 4


def test_coverage_full_report_scores_high():
    rich = ("The tracked actor (who) deployed a Rust ransomware payload (what) "
            "first seen 2026-02 (when) against the finance sector in one "
            "region (where) for financial motivation (why) via a phishing "
            "initial-access vector (how).")
    cov = A.coverage_5w1h(rich)
    assert cov["score"] == 6
    assert cov["missing"] == []


def test_effort_vs_answer_distinction():
    # a sweep can touch many sources and still answer nothing
    effort = ("Scanned 30 tier-1 feeds and staged 45 findings across malware "
              "and vulnerability categories on 2026-07-30.")
    cov = A.coverage_5w1h(effort)
    assert "why" in cov["missing"]
    assert cov["score"] < 4


# ── 0% / 100% (the percent forms, which a trailing \b once made dead) ────

@pytest.mark.parametrize("text", [
    "It is 100% certain the actor is FIN-X.",
    "There is a 0% chance this was an insider.",
    "Attribution confidence: 100 %.",
    "Attribution: 100%",
    "It is 100%confirmed.",
    "The actor is 100 percent the same group.",
])
def test_lint_flags_zero_and_hundred_percent(text):
    assert any("absolute" in p for p in A.lint_judgment(text)), text


@pytest.mark.parametrize("text", [
    "About 10% of hosts were affected.", "Traffic rose 1000% overnight.",
    "A 10.0% share of samples.", "Only 0.5% of mail was blocked.",
    "Recovery of the backups is not guaranteed.",
    "Lateral movement isn't impossible, but it is unlikely.",
])
def test_ordinary_percentages_and_negated_absolutes_do_not_flag(text):
    assert not any("absolute" in p for p in A.lint_judgment(text)), text


def test_empty_text_has_nothing_to_flag_but_is_not_evidence():
    # the lint alone finds nothing in nothing; the GATE must still block an
    # empty report (see test_validate: empty report blocks)
    assert A.lint_judgment("") == []


# ── self-reference is not attribution ───────────────────────────────────

@pytest.mark.parametrize("text", [
    "In this report we assess with 90% confidence that the actor is FIN-X.",
    "Our report estimates a 70% probability of reinfection.",
])
def test_self_reference_does_not_exempt_a_judgment_percentage(text):
    assert any("bare percentage" in p for p in A.lint_judgment(text)), text


def test_vendor_report_percentage_still_exempt():
    assert A.lint_judgment(
        "Vendor X reports 90% of incidents began with phishing, with high "
        "confidence in its sample.") == []


def test_percent_spelled_out_is_still_a_bare_percentage():
    assert any("bare percentage" in p for p in A.lint_judgment(
        "We assess with 90 percent confidence that the actor is FIN-X."))


# ── hedged ranges: adjacent band terms only ─────────────────────────────

@pytest.mark.parametrize("text", [
    "The actor is likely/very likely the same group.",
    "The actor is likely or very likely the same group.",
    "The actor is likely - very likely the same group.",
    "It is unlikely to roughly even chance that data left.",
])
def test_lint_flags_hedge_forms(text):
    assert any("hedged" in p for p in A.lint_judgment(text)), text


@pytest.mark.parametrize("text", [
    "Exploitation is likely to continue; reinfection is likely.",
    "The actor is likely to return, and a second wave is very likely.",
])
def test_two_separate_judgments_are_not_a_hedge(text):
    assert not any("hedged" in p for p in A.lint_judgment(text)), text


@pytest.mark.parametrize("text", [
    "likely " * 10000,
    "likely to " * 7000,
    "we assess " * 7000 + "90%",
])
def test_lint_is_linear(text):
    import time
    t0 = time.perf_counter()
    A.lint_judgment(text)
    assert time.perf_counter() - t0 < 1.0


# ── further standards cases ────────────────────────────────────────────

def _kinds(text):
    return [p.split(" ")[0] for p in A.lint_judgment(text)]


def _has(text, needle):
    return any(needle in p for p in A.lint_judgment(text))


def test_per_attribution_cue_exempts_a_sourced_percentage():
    assert not _has("Per Mandiant, we estimate 90% of intrusions start by phish.",
                    "bare percentage")
    assert not _has("We estimate 90% of intrusions start by phish, per Mandiant.",
                    "bare percentage")


def test_per_near_misses_still_flag():
    # "per" with nothing after it, or only inside another word, is no source
    assert _has("We estimate 90% of intrusions start by phish per.",
                "bare percentage")
    assert _has("We estimate 90% of intrusions start by phish, a super bet.",
                "bare percentage")
    assert _has("We assess 90% confidence, perhaps more.", "bare percentage")


@pytest.mark.parametrize("text", [
    "It is absolutely\ncertain.",
    "It is absolutely  certain.",
    "It is absolutely\t\ncertain.",
    "There is no chance\nwhatsoever.",
    "There is no  chance whatsoever.",
    "100\n%",
    "100\npercent certain",
    "100\nper cent certain",
])
def test_hard_wrapped_absolutes_are_flagged(text):
    assert _has(text, "absolute"), text


@pytest.mark.parametrize("text", [
    "It is not\nguaranteed.",
    "It is not  guaranteed.",
    "It isn't\nguaranteed.",
    "This is never\nabsolutely certain.",
    "It is not\nimpossible.",
])
def test_negated_absolutes_pass_across_whitespace(text):
    assert A.lint_judgment(text) == [], text


def test_negation_far_away_does_not_exempt():
    assert _has("It is not clear. Attribution is guaranteed.", "absolute")


def test_em_dash_joins_a_hedge_like_hyphen_and_en_dash():
    for sep in ("-", "–", "—"):
        assert _has(f"This is likely{sep}very likely a campaign.", "hedged"), sep


def test_100_point_zero_percent_is_absolute_like_100_percent():
    assert _has("Attribution is 100.0% certain.", "absolute")
    assert _has("Attribution is 0.0% likely.", "absolute")
    assert _has("Attribution is 100.00 percent certain.", "absolute")


def test_near_miss_decimals_are_not_absolute():
    for t in ("Reuse was 100.5% of baseline.", "A 0.05% drop.", "A 10.0% drop.",
              "A 1100.0% rise."):
        assert not _has(t, "absolute"), t


def test_impossible_travel_is_a_detection_name_not_a_claim():
    assert A.lint_judgment("The alert was an impossible travel detection.") == []
    assert A.lint_judgment("Impossible-travel alerts fired for the account.") == []
    assert _has("Such an intrusion is impossible.", "absolute")
    assert _has("It is impossible; travel was not involved.", "absolute")


def test_negation_across_a_long_whitespace_run():
    assert A.lint_judgment("It is not" + " " * 40 + "guaranteed.") == []


# ── per cent, absolutes and negation boundaries ──────────────────────────

@pytest.mark.parametrize("s", [
    "We assess with 90 per cent confidence.",
    "Probability is 85 per cent.",
    "Growth of 40% per year, we assess with 40% confidence.",
    "90% confidence per our analysis.",
])
def test_per_cent_is_not_attribution(s):
    assert any("bare percentage" in p for p in A.lint_judgment(s)), s


def test_per_source_stays_exempt():
    assert not any("bare percentage" in p for p in A.lint_judgment(
        "Per Mandiant, 90% of intrusions involved phishing, a high probability."))


def test_absolutes_linear():
    t0 = time.perf_counter()
    A._has_absolute("not guaranteed. " * 12500)
    assert time.perf_counter() - t0 < 0.15


@pytest.mark.parametrize("s,flag", [
    ("It is not guaranteed.", False),
    ("It isn’t guaranteed.", False),
    ("It isn't guaranteed.", False),
    ("That is knot guaranteed.", True),
    ("A cannot guaranteed.", True),
    ("It was never guaranteed.", False),
    ("nothing guaranteed", True),
])
def test_negation_boundary(s, flag):
    assert A._has_absolute(s) is flag, s


# ── found by the Mini Shai-Hulud case study's hurried first draft (2026-10-16) ──

@pytest.mark.parametrize("text", [
    "The compromise was certainly the work of TeamPCP.",
    "It was definitely the same group.", "This is undoubtedly state-backed.",
    "The actor is, without a doubt, the same.",
])
def test_unbanded_certainty_adverbs_are_absolute(text):
    assert any("absolute" in p for p in A.lint_judgment(text)), text


@pytest.mark.parametrize("text", [
    "The compromise was almost certainly the work of TeamPCP.",
    "It is nearly\ncertainly the same group.", "It was not definitely them.",
])
def test_the_top_band_and_a_negation_are_not_absolute(text):
    assert not any("absolute" in p for p in A.lint_judgment(text)), text


@pytest.mark.parametrize("text", ["We are 95% confident no repository was modified.",
                                  "I am 80 percent sure it is the same actor."])
def test_a_percentage_on_ones_own_confidence_is_bare(text):
    assert any("bare percentage" in p for p in A.lint_judgment(text)), text
