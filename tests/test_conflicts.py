"""Conflict-as-object behavior pins, in both directions: a dominant-source
conflict auto-resolves and does not block, and two strong disagreeing sources
do block (fail closed)."""
from __future__ import annotations

import pytest

from cti_report_lint import conflicts as C


def _mk(ta, tb, ctype="VALUE_MISMATCH"):
    return C.Conflict(
        ctype=ctype, subject="CVE-2024-12345 impact",
        a=C.Side("forum post", "remote code execution", ta),
        b=C.Side("vendor advisory", "information leak", tb,
                 source_reliability="A"))


def test_weak_source_vs_advisory_auto_resolves_to_advisory():
    c = _mk(1, 5)
    assert c.severity == "MINOR"
    assert c.resolution == "AUTO_RESOLVED"
    assert c.winner == "vendor advisory"
    assert c.is_open() is False


def test_auto_resolved_records_the_loser_not_discards():
    c = _mk(1, 5)
    assert c.a.value == "remote code execution"


def test_both_high_trust_is_critical_and_blocks():
    c = _mk(4, 5)
    assert c.severity == "CRITICAL"
    assert c.resolution == "HUMAN_REQUIRED"
    assert c.is_open() is True


def test_both_mid_trust_is_high_and_blocks():
    c = _mk(3, 3)
    assert c.severity == "HIGH"
    assert c.is_open() is True


def test_close_trust_is_notable_and_blocks():
    c = _mk(2, 3)
    assert c.severity == "NOTABLE"
    assert c.is_open() is True


def test_one_open_conflict_blocks_the_whole_claim():
    assert C.blocks_verified([_mk(1, 5), _mk(4, 4)]) is True


def test_all_auto_resolved_does_not_block():
    assert C.blocks_verified([_mk(1, 5), _mk(2, 4)]) is False


def test_no_conflicts_does_not_block():
    assert C.blocks_verified([]) is False


def test_unknown_conflict_type_raises():
    with pytest.raises(ValueError):
        C.Conflict(ctype="CONNECTION_PARADOX", subject="x",
                   a=C.Side("s1", "v1", 3), b=C.Side("s2", "v2", 3))


def test_adopted_types_are_exactly_three():
    assert C.CONFLICT_TYPES == (
        "VALUE_MISMATCH", "TIME_IMPOSSIBLE", "EXISTENCE_DISPUTE")


def test_from_dict_round_trips():
    d = {"ctype": "TIME_IMPOSSIBLE", "subject": "first_seen",
         "a": {"source": "vendorX", "value": "2024", "trust_score": 2},
         "b": {"source": "vendorY", "value": "2023", "trust_score": 4},
         "note": "checked"}
    c = C.from_dict(d)
    assert c.ctype == "TIME_IMPOSSIBLE"
    assert c.winner == "vendorY"
    assert c.severity == "MINOR"
    assert c.note == "checked"


# ── the severity table is cti-expert's grade_severity ───────────────────

@pytest.mark.parametrize("pair,sev", [
    ((1, 3), "NOTABLE"),   # a trust-3 claim does not silently beat trust 1
    ((3, 4), "NOTABLE"),
    ((3, 5), "NOTABLE"),
    ((4, 5), "CRITICAL"), ((4, 4), "CRITICAL"), ((5, 5), "CRITICAL"),
    ((3, 3), "HIGH"),
    ((2, 4), "MINOR"), ((1, 5), "MINOR"), ((2, 5), "MINOR"), ((1, 4), "MINOR"),
    ((2, 3), "NOTABLE"), ((1, 2), "NOTABLE"), ((1, 1), "NOTABLE"),
    ((2, 2), "NOTABLE"),
])
def test_severity_table_matches_upstream_grade_severity(pair, sev):
    """engine/conflict-resolver.md grade_severity, for two sides: both >=4
    CRITICAL; both >=3 with neither >=4 HIGH; one >=4 and one <=2 MINOR; else
    NOTABLE. Symmetric in the two sides."""
    ta, tb = pair
    assert _mk(ta, tb).severity == sev
    assert _mk(tb, ta).severity == sev


def test_only_minor_auto_resolves():
    for ta in range(1, 6):
        for tb in range(1, 6):
            c = _mk(ta, tb)
            assert (c.resolution == "AUTO_RESOLVED") == (c.severity == "MINOR"), (ta, tb)
