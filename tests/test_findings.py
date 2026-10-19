"""Finding-schema behavior pins, in both directions: a weak claim scores low,
AND a well-sourced claim is not suppressed."""
from __future__ import annotations

import pytest

from cti_report_lint import findings as S


def test_type_base_weights_match_cti_expert():
    # engine/finding-framework.md: 0, 2, 4, 7, 8
    assert S.TYPE_BASE == {"CONFIRMED": 8.0, "PRIMARY": 7.0, "DERIVED": 4.0,
                           "ANECDOTAL": 2.0, "CONTESTED": 0.0}


def test_contested_scores_zero_regardless_of_trust():
    assert S.strength("CONTESTED", 5, 3) == 0.0
    assert S.strength("CONTESTED", 1, 0) == 0.0


def test_anecdotal_unverified_scores_low():
    # ANECDOTAL/trust 1 -> 2.0 + 0.4 = 2.4
    assert S.strength("ANECDOTAL", 1, 0) == pytest.approx(2.4)
    assert S.strength("ANECDOTAL", 1, 0) < S.strength("PRIMARY", 5, 0)


def test_primary_trust5_is_load_bearing():
    # 7.0 + 2.0 = 9.0
    assert S.strength("PRIMARY", 5) == pytest.approx(9.0)


def test_confirmed_multi_source_reaches_cap():
    assert S.strength("CONFIRMED", 5, 5) == 10.0
    assert S.strength("CONFIRMED", 5, 2) == 10.0
    # below the cap the signal is not swallowed
    assert S.strength("CONFIRMED", 3, 0) == pytest.approx(9.2)


def test_confirmation_bonus_is_capped_at_1_5():
    """cti-expert: ConfirmationBonus max +1.5 (min(confirm_cnt * 0.5, 1.5))."""
    assert S.CONFIRMATION_BONUS_CAP == 1.5
    assert S.strength("DERIVED", 3, 6) == pytest.approx(6.7)
    assert S.strength("DERIVED", 3, 3) == S.strength("DERIVED", 3, 9)
    # a pile of confirmations must not lift DERIVED past PRIMARY
    assert S.strength("DERIVED", 3, 20) < S.strength("PRIMARY", 3, 0)


def test_ordering_is_monotone_by_type():
    base = [S.strength(t, 3, 0) for t in
            ("CONTESTED", "ANECDOTAL", "DERIVED", "PRIMARY", "CONFIRMED")]
    assert base == sorted(base), base


def test_bad_type_range_and_negative_confirmations_raise():
    with pytest.raises(ValueError):
        S.strength("RUMOR", 3, 0)
    with pytest.raises(ValueError):
        S.strength("PRIMARY", 9, 0)
    with pytest.raises(ValueError):
        S.strength("PRIMARY", 3, -1)


def test_validate_ungraded_is_not_an_error():
    assert S.validate_fields({"title": "x"}) == []


def test_validate_partial_grade_is_an_error():
    errs = S.validate_fields({"finding_type": "PRIMARY"})
    assert any("partial" in e for e in errs)


def test_validate_full_valid_grade_passes():
    assert S.validate_fields({
        "finding_type": "PRIMARY", "trust_score": 5,
        "source_reliability": "A", "confirmed_by": []}) == []


def test_validate_catches_bad_values():
    errs = S.validate_fields({
        "finding_type": "GOSSIP", "trust_score": 12,
        "source_reliability": "Z", "confirmed_by": "notalist"})
    assert len(errs) >= 4


def test_validate_tree_separates_graded_from_ungraded(tmp_path):
    (tmp_path / "graded.md").write_text(
        "---\nfinding_type: PRIMARY\ntrust_score: 5\n"
        "source_reliability: A\nconfirmed_by: []\n---\nbody\n",
        encoding="utf-8")
    (tmp_path / "plain.md").write_text(
        "---\ntitle: just a note\n---\nbody\n", encoding="utf-8")
    (tmp_path / "bad.md").write_text(
        "---\nfinding_type: PRIMARY\n---\nbody\n", encoding="utf-8")
    (tmp_path / "broken.md").write_text(
        "---\ntitle: [unclosed\n---\nbody\n", encoding="utf-8")
    r = S.validate_tree(tmp_path)
    assert len(r["graded"]) == 1
    assert r["graded"][0]["strength"] == pytest.approx(9.0)
    assert r["ungraded_count"] == 1
    assert len(r["invalid"]) == 1
    assert len(r["unparseable"]) == 1
    assert r["total_md"] == 4
