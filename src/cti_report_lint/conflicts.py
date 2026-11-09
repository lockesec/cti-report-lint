"""Contradictions between sources, as first-class objects.

Adapts cti-expert ``engine/conflict-resolver.md``
(https://github.com/7onez/cti-expert, MIT, see NOTICE): the conflict types,
the four severity levels, the ``grade_severity`` rule, and the idea that an
unresolved contradiction keeps its subject from reaching verified confidence.
Binding that rule to a report's exit code, and the code itself, are original
to this project.

Without this, whichever source is read last silently wins. Here a
contradiction becomes an object with a type, a severity keyed to BOTH sides'
trust, and a resolution state. A report that carries an OPEN conflict cannot
pass.

Three conflict types are adopted. cti-expert defines two more,
CONNECTION_PARADOX and LOCATION_IMPOSSIBLE, which belong to entity
investigations rather than report claims and are deliberately left out:

  VALUE_MISMATCH     two sources assert different values for one attribute
  TIME_IMPOSSIBLE    timeline claims that cannot both hold
  EXISTENCE_DISPUTE  one source asserts a thing exists, another denies it

Severity, keyed to both sides' trust score (1-5, see ``findings``):

  CRITICAL  both >= 4                     never auto-resolves: a human decides
  HIGH      both >= 3 and neither >= 4    human review
  MINOR     one >= 4 and the other <= 2   auto-resolves to the stronger side
  NOTABLE   anything else                 human review

Example: a vulnerability's impact described one way by an unverified forum
post (trust 1) and another way by the vendor advisory (trust 5) is a
VALUE_MISMATCH, graded MINOR, and auto-resolves to the advisory. The losing
side stays on the object, so a source that keeps embellishing becomes a
visible pattern instead of a silently overwritten one-off.
"""
from __future__ import annotations

import datetime

from dataclasses import dataclass

CONFLICT_TYPES = ("VALUE_MISMATCH", "TIME_IMPOSSIBLE", "EXISTENCE_DISPUTE")


@dataclass
class Side:
    """One party to a contradiction: a graded claim."""
    source: str
    value: str
    trust_score: int                        # 1-5
    source_reliability: str | None = None   # A-F, optional

    def __post_init__(self):
        # Out-of-range trust silently re-graded a conflict: (-5, 999) read as
        # MINOR and auto-resolved, clearing a block it should have held.
        if type(self.trust_score) is not int or not 1 <= self.trust_score <= 5:
            raise ValueError(f"trust_score {self.trust_score!r} must be an integer 1-5")
        for name in ("source", "value"):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"{name} must be a string")
        if self.source_reliability is not None and (
                not isinstance(self.source_reliability, str)
                or self.source_reliability.upper() not in set("ABCDEF")):
            raise ValueError(f"source_reliability {self.source_reliability!r} not one of A-F")


@dataclass
class Conflict:
    ctype: str
    subject: str              # what the two sides disagree ABOUT
    a: Side
    b: Side
    severity: str = ""
    resolution: str = "OPEN"  # OPEN | AUTO_RESOLVED | HUMAN_REQUIRED | HUMAN_RESOLVED
    winner: str | None = None
    note: str = ""
    # A person's decision on a conflict that needs one: {by, winner: a | b | neither, note}.
    # Both sides stay on the object; the decision is recorded, never inferred.
    resolved_by: dict | None = None

    def __post_init__(self):
        if self.ctype not in CONFLICT_TYPES:
            raise ValueError(f"unknown conflict type {self.ctype!r} "
                             f"(adopted: {CONFLICT_TYPES})")
        self._classify()
        if self.resolved_by is not None:
            self._apply_decision(self.resolved_by)

    def _apply_decision(self, rb) -> None:
        if not isinstance(rb, dict):
            raise TypeError("resolved_by must be a mapping {by, winner, note}")
        by, win, why = rb.get("by"), rb.get("winner"), rb.get("note")
        if not isinstance(by, str) or not by.strip():
            raise ValueError("resolved_by.by must name the person who decided")
        if win not in ("a", "b", "neither"):
            raise ValueError("resolved_by.winner must be a, b or neither")
        if not isinstance(why, str) or not why.strip():
            raise ValueError("resolved_by.note must say why")
        if self.resolution == "HUMAN_REQUIRED":
            self.resolution = "HUMAN_RESOLVED"
            self.winner = {"a": self.a.source, "b": self.b.source, "neither": None}[win]

    def _classify(self) -> None:
        """cti-expert's grade_severity ("Severity Grading" in
        engine/conflict-resolver.md), for two sides:
          both >= 4                     -> CRITICAL
          both >= 3 and neither >= 4    -> HIGH
          one >= 4 and one <= 2         -> MINOR (auto-resolve to the stronger)
          anything else                 -> NOTABLE
        So (1,3) is NOTABLE: a trust-3 claim does not silently beat a trust-1
        one. And (3,4) and (3,5) are NOTABLE, not HIGH."""
        ta, tb = int(self.a.trust_score), int(self.b.trust_score)
        lo, hi = min(ta, tb), max(ta, tb)
        if lo >= 4:
            self.severity = "CRITICAL"
            self.resolution = "HUMAN_REQUIRED"
        elif lo >= 3 and hi < 4:
            self.severity = "HIGH"
            self.resolution = "HUMAN_REQUIRED"
        elif hi >= 4 and lo <= 2:
            # A dominant winner over a weak loser is safe to auto-resolve,
            # but the loser is RECORDED on the object, never discarded.
            self.severity = "MINOR"
            self.resolution = "AUTO_RESOLVED"
            self.winner = self.a.source if ta > tb else self.b.source
        else:
            self.severity = "NOTABLE"
            self.resolution = "HUMAN_REQUIRED"

    def is_open(self) -> bool:
        """Open conflicts block a report. AUTO_RESOLVED does not."""
        return self.resolution not in ("AUTO_RESOLVED", "HUMAN_RESOLVED")


def blocks_verified(conflicts: list[Conflict]) -> bool:
    """True when ANY conflict is open (not auto-resolved). Fails closed: a
    human-required conflict blocks."""
    return any(c.is_open() for c in conflicts)


def _side(d: dict) -> Side:
    """A side as written. YAML reads an unquoted `value: 2025-07-08` as a date and `value: 317`
    as a number; both are what the analyst wrote, so they are kept as that text. A yes/no
    value stays an error: YAML turns `no` into False, which is never what was meant."""
    d = dict(d)
    v = d.get("value")
    if isinstance(v, (datetime.date, datetime.datetime)):
        d["value"] = v.isoformat()
    elif isinstance(v, (int, float)) and not isinstance(v, bool):
        d["value"] = str(v)
    return Side(**d)


def _text(v) -> str:
    """YAML reads `subject: 2026-01-01` as a date; the subject is always text."""
    return v if isinstance(v, str) else str(v)


def from_dict(d: dict) -> Conflict:
    """Build a Conflict from the frontmatter shape
    ``{ctype, subject, a: {source, value, trust_score}, b: {...}, note?}``."""
    if not isinstance(d, dict) or not isinstance(d.get("a"), dict) or not isinstance(d.get("b"), dict):
        raise TypeError("a conflict needs mappings a and b")
    return Conflict(
        ctype=d["ctype"], subject=_text(d.get("subject", "")),
        a=_side(d["a"]), b=_side(d["b"]), note=d.get("note", ""),
        resolved_by=d.get("resolved_by"))
