"""Declared sources and independent corroboration.

A report may declare its sources once, in the frontmatter, and cite them by id:

    sources:
      - {id: vendor-feed, reliability: B}
      - {id: vendor-blog, reliability: C, derived_from: vendor-feed}
    findings:
      - {..., confirmed_by: [vendor-feed, vendor-blog]}

``derived_from`` names the source a source repeats. Corroboration is counted by ROOT: following
``derived_from`` to a source that repeats nothing, two citations with the same root are one
independent source. That is the circular-reporting problem (a blog restating a feed is not a
second confirmation), and it is the classic way a "very likely" gets inflated.

The tool never grades a source. It checks that what is declared is consistent: every id is
declared once with a reliability A-F, every ``derived_from`` names a declared source, and the
chains have no cycle.
"""
from __future__ import annotations

RELIABILITY = frozenset("ABCDEF")


def parse(raw) -> tuple[dict, list[str]]:
    """({id: source}, issues) for a ``sources:`` value."""
    issues: list[str] = []
    out: dict = {}
    if not isinstance(raw, list):
        return {}, [f"sources: must be a list, got {type(raw).__name__}"]
    for i, s in enumerate(raw):
        if not isinstance(s, dict) or not isinstance(s.get("id"), str) or not s["id"].strip():
            issues.append(f"sources[{i}]: needs an id")
            continue
        sid = s["id"]
        if sid in out:
            issues.append(f"sources[{i}]: '{sid}' is declared twice")
            continue
        rel = s.get("reliability")
        if not (isinstance(rel, str) and rel.upper() in RELIABILITY):
            issues.append(f"sources[{i}]: '{sid}' reliability {rel!r} is not one of A-F")
        out[sid] = s
    for sid, s in out.items():
        up = s.get("derived_from")
        if up is not None and not isinstance(up, str):
            issues.append(f"sources: '{sid}' derived_from must be a source id, got {up!r}")
        elif up is not None and up not in out:
            issues.append(f"sources: '{sid}' is derived_from '{up}', which is not a declared source")
    for sid in out:
        if root(out, sid) is None:
            issues.append(f"sources: '{sid}' sits on a derived_from cycle")
    return out, issues


def root(srcs: dict, sid: str) -> str | None:
    """The source ``sid`` ultimately repeats; None on a cycle. An unknown upstream ends the
    chain at the last declared source (the unknown id is reported by `parse`)."""
    seen = set()
    cur = sid
    while True:
        if cur in seen:
            return None
        seen.add(cur)
        up = srcs.get(cur, {}).get("derived_from")
        if not isinstance(up, str) or up not in srcs:
            return cur
        cur = up


def independent(srcs: dict, cited: list) -> tuple[list[str], list[str]]:
    """(distinct roots of the cited ids, cited ids that are not declared)."""
    # a cited entry that is not a string (a list, a mapping) can name no source
    unknown = [c for c in cited if not isinstance(c, str) or c not in srcs]
    roots = []
    for c in cited:
        if isinstance(c, str) and c in srcs:
            r = root(srcs, c)
            if r is not None and r not in roots:
                roots.append(r)
    return roots, unknown
