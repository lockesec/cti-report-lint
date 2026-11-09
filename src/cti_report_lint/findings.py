"""The typed-finding evidence schema.

Adapts cti-expert ``engine/finding-framework.md``
(https://github.com/7onez/cti-expert, MIT, see NOTICE): the five finding
types, their base weights, the 1-5 trust scale, the strength formula and its
confirmation cap. The A-F source-reliability letters follow the Admiralty
(NATO) source-grading system. The code is original to this project.

Every graded finding carries:

  finding_type        PRIMARY | DERIVED | CONFIRMED | CONTESTED | ANECDOTAL
  trust_score         1-5, rates the CONTENT of the claim
  source_reliability  A-F, rates the SOURCE. It is kept separate on purpose:
                      a reliable outlet can carry a weak claim.
  confirmed_by        list of independent corroborating sources

Strength = TypeBase + 0.4 * trust + min(0.5 * len(confirmed_by), 1.5),
capped at 10.

The sharp edge, kept deliberately: CONTESTED scores 0.0. A contradicted
claim contributes nothing, rather than averaging against good evidence.

Grading is incremental: a document with none of the finding fields is
"ungraded", not invalid. A document with only SOME of them is invalid, because
half a grade misleads more than none.
"""
from __future__ import annotations

from pathlib import Path

TYPE_BASE = {
    "CONFIRMED": 8.0,   # multiple independent primary sources agree
    "PRIMARY": 7.0,     # first-party or authoritative record
    "DERIVED": 4.0,     # the author's own inference from graded evidence
    "ANECDOTAL": 2.0,   # a single unverified report
    "CONTESTED": 0.0,   # actively contradicted; see strength()
}
TRUST_RANGE = (1, 5)
RELIABILITY = frozenset("ABCDEF")
STRENGTH_CAP = 10.0
# cti-expert caps the corroboration term itself ("ConfirmationBonus ... max
# +1.5"; its compute_strength uses min(confirm_cnt * 0.5, 1.5)). Without the
# cap, a pile of confirmations lifts a DERIVED finding past a PRIMARY one:
# DERIVED at trust 3 with 6 confirmations would read 8.2 instead of 6.7.
CONFIRMATION_BONUS_CAP = 1.5

FIELDS = ("finding_type", "trust_score", "source_reliability", "confirmed_by")


def strength(finding_type: str, trust_score: int,
             confirmations: int = 0) -> float:
    """TypeBase + 0.4*trust + min(0.5 per confirmation, 1.5), capped at 10.

    CONTESTED returns 0.0 unconditionally: a contradicted claim contributes
    nothing and must not average against good evidence.
    """
    ftype = finding_type.upper()
    if ftype not in TYPE_BASE:
        raise ValueError(f"unknown finding_type {finding_type!r} "
                         f"(one of {sorted(TYPE_BASE)})")
    if not (TRUST_RANGE[0] <= int(trust_score) <= TRUST_RANGE[1]):
        raise ValueError(f"trust_score {trust_score} outside "
                         f"{TRUST_RANGE[0]}-{TRUST_RANGE[1]}")
    if confirmations < 0:
        raise ValueError("confirmations cannot be negative")
    if ftype == "CONTESTED":
        return 0.0
    raw = (TYPE_BASE[ftype] + 0.4 * int(trust_score)
           + min(0.5 * confirmations, CONFIRMATION_BONUS_CAP))
    return min(raw, STRENGTH_CAP)


def validate_fields(fm: dict) -> list[str]:
    """Validate the finding fields present in one mapping.

    Returns error strings; an empty list means valid. The absence of ALL
    fields is not an error (an ungraded document). PARTIAL presence is.
    """
    present = [f for f in FIELDS if f in fm]
    if not present:
        return []
    errors = []
    missing = [f for f in FIELDS if f not in fm and f != "confirmed_by"]
    if missing:
        errors.append(f"partial grading: has {present}, missing {missing}")
    ftype = str(fm.get("finding_type", "")).upper()
    if "finding_type" in fm and ftype not in TYPE_BASE:
        errors.append(f"finding_type {fm['finding_type']!r} not in "
                      f"{sorted(TYPE_BASE)}")
    if "trust_score" in fm:
        t = fm["trust_score"]
        # Exactly an int. bool is an int subclass (True == 1), and int() would
        # quietly turn 3.9 into 3 or accept the string "5".
        if type(t) is not int:
            errors.append(f"trust_score {t!r} not an integer")
        elif not (TRUST_RANGE[0] <= t <= TRUST_RANGE[1]):
            errors.append(f"trust_score {t} outside 1-5")
    rel = fm.get("source_reliability")
    # Exact membership. A substring test let "AB" and "" through.
    if "source_reliability" in fm and (
            not isinstance(rel, str) or rel.upper() not in RELIABILITY):
        errors.append(f"source_reliability {rel!r} not one of A-F")
    cb = fm.get("confirmed_by", [])
    if cb is not None and not isinstance(cb, list):
        errors.append(f"confirmed_by must be a list, got {type(cb).__name__}")
    return errors


def _load_frontmatter(path: Path) -> dict | None:
    """Minimal frontmatter reader. Returns {} when there is no frontmatter and
    None when it is present but unparseable (damage is not absence)."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):      # unreadable is not "no evidence"
        return None
    from .validate import _split_frontmatter     # one splitter, so one set of rules
    text = text[1:] if text.startswith("\ufeff") else text
    try:
        return _split_frontmatter(text)[0]
    except Exception:
        return None


def validate_tree(root: Path) -> dict:
    """Grade every Markdown file under ``root`` whose frontmatter carries the
    finding fields at its top level. Ungraded files are counted, not errors;
    invalid and unparseable ones are listed."""
    graded, ungraded, invalid, unparseable = [], [], {}, []
    files = ([root] if root.is_file() else sorted(root.rglob("*.md")))
    for p in files:
        fm = _load_frontmatter(p)
        rel = str(p)
        if fm is None:
            unparseable.append(rel)
            continue
        errs = validate_fields(fm)
        if errs:
            invalid[rel] = errs
        elif any(f in fm for f in FIELDS):
            row = {"file": rel,
                   "strength": strength(fm["finding_type"],
                                        int(fm["trust_score"]),
                                        len(fm.get("confirmed_by") or []))}
            graded.append(row)
        else:
            ungraded.append(rel)
    return {"graded": graded, "ungraded_count": len(ungraded),
            "invalid": invalid, "unparseable": unparseable,
            "total_md": len(files)}
