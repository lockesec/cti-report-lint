"""The report gate: one pass that composes every check.

Original to this project. cti-expert describes these rules as instructions for
an analyst or a model; it has no executable gate.

A report must clear six checks (the identifier check, 1b in the code, is the sixth):

  1. Judgment lint (``standards``): no hedged ranges, no bare percentages on
     the author's own judgments, no 0/100 absolutes.
  2. 5W1H coverage (``standards``): the report must ANSWER who, what, when,
     where, why and how, not just log effort. Default threshold: 4 of 6.
  3. Finding grades (``findings``): every entry under ``findings:`` in the
     frontmatter is validated and its strength computed.
  4. Likelihood ceiling (``standards`` + ``findings``): a finding's stated
     likelihood term may not exceed what its evidence grade allows.
  5. Conflict block (``conflicts``): any OPEN entry under ``conflicts:``
     blocks the report.

Checks 3-5 read their whole input from frontmatter. A report that declares no
findings would pass them while they evaluated nothing, so a report with no
``findings:`` is blocked. The optional ``findings_required_from`` date relaxes
that for older reports (see ``validate_report``).

Frontmatter this reads (all keys optional):

  date / scan_date: YYYY-MM-DD
  findings:  [{finding_type, trust_score, source_reliability, confirmed_by,
               likelihood?}]      # likelihood is one of the seven band terms
  conflicts: [{ctype, subject, a: {source, value, trust_score}, b: {...}}]
"""
from __future__ import annotations

import datetime
import re
from pathlib import Path

from . import conflicts as conflict
from . import findings as schema
from . import identifiers
from . import sources as source_model
from . import standards as analytic

DEFAULT_MIN_5W1H = 4

_FINDING_ID_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
# a "---" line whose next non-blank line is an evidence key: frontmatter, wherever it sits
_MISPLACED_FRONTMATTER = re.compile(
    r"(?m)^[ \t]*---[ \t]*\r?\n(?:[ \t]*\r?\n)*[ \t]*(?:findings|conflicts|sources|date)[ \t]*:")


def _split_frontmatter(text: str) -> tuple[dict | None, str]:
    """Three states, not two: damage is not absence.

    Returns {} for "no frontmatter" and None for "frontmatter present but
    unparseable". Collapsing those into {} would be a fail-open: checks 3-5
    read ``findings`` and ``conflicts`` from this dict, so one deleted brace in
    the YAML would make an OPEN CRITICAL conflict indistinguishable from "no
    conflicts declared", and a blocked report would pass.
    """
    if not text.startswith("---"):
        # A block that opens below line 1 (a blank line, a space, an HTML comment above it) is
        # still the author's evidence. Reading it as "none" would let the ratchet grandfather
        # a report whose open conflict should block it, so it counts as damage.
        return (None if _MISPLACED_FRONTMATTER.search(text) else {}), text
    end = text.find("\n---", 3)
    if end < 0:
        return None, text          # opened a block and never closed it
    body = text[end + 4:]
    try:
        from ._yaml import load_strict
        fm = load_strict(text[3:end])
    except Exception:
        return None, body          # malformed YAML or a duplicate key, NOT "no fields"
    if fm is None:
        return {}, body            # a genuinely empty block
    return (fm if isinstance(fm, dict) else None), body


def _real_date(s: str) -> str | None:
    """s if it is a real calendar date, else None ("2026-02-30" is not)."""
    try:
        datetime.date.fromisoformat(s)
    except ValueError:
        return None
    return s


def report_date(path: Path, fm: dict) -> str | None:
    """The report's date, preferring the DECLARED value over the filename.

    Order: frontmatter ``scan_date`` / ``date`` (what the author asserted),
    then a YYYY-MM-DD date in the file name, then None. None matters: an
    undated report is treated as new, so failing to find a date can never buy
    an exemption. A shape-valid but impossible date ("2026-00-00") is not a
    date either: it would otherwise sort before any ratchet and buy one.
    """
    for key in ("scan_date", "date"):
        v = fm.get(key)
        if v:
            m = _DATE_RE.search(str(v))
            if m and _real_date(m.group(1)):
                return m.group(1)
    m = _DATE_RE.search(path.name)
    return m.group(1) if m and _real_date(m.group(1)) else None


_READ_KEYS = ("findings", "conflicts", "sources", "date", "scan_date")
_SPELLINGS = {}
for _k in _READ_KEYS:
    for _form in (_k, _k.rstrip("s")):
        _SPELLINGS[_form.replace("_", "")] = _k


def _misspelled_keys(fm: dict) -> list[str]:
    """One issue per frontmatter key that is read by exact name and is written differently
    ("conflict", "Conflicts", "scan-date"). Such a key is ignored, and for ``conflicts`` an
    ignored key reads as "no conflicts declared": a block that clears itself."""
    out = []
    for k in fm:
        if not isinstance(k, str) or k in _READ_KEYS:
            continue
        want = _SPELLINGS.get(re.sub(r"[\s_-]+", "", k).lower())
        if want:
            out.append(f"frontmatter: key {k!r} is not read; the key is {want!r} "
                       f"(exact spelling, lower case), so what it holds was NOT checked")
    return out


_NO_FINDINGS = ("findings: none declared — checks 3-5 (evidence grade, likelihood ceiling, "
                "conflict block) did not run; `cti-report-lint skeleton FILE` prints a findings "
                "block to start from")


def _needs_evidence(text: str, body: str) -> list[str]:
    """One line per likelihood judgment in the prose, when no finding is declared to rest it
    on: what an analyst needs to grade first."""
    line0 = text[:len(text) - len(body)].count("\n")
    found = [(off, said) for off, _term, said in analytic.prose_terms(body)] + analytic.confidence_terms(body)
    return [f"needs evidence: '{said}' at line {line0 + body.count(chr(10), 0, off) + 1} is a "
            f"likelihood judgment with no declared finding behind it"
            for off, said in sorted(found)]


def validate_report(path: Path, *, min_5w1h: int = DEFAULT_MIN_5W1H,
                    findings_required_from: str | None = None,
                    attack=None, kev=None, require_citations: bool = False) -> dict:
    """Run every check on one report and return the result as a dict.

    ``findings_required_from`` (YYYY-MM-DD, default None) is a ratchet for
    teams adopting the tool on an existing corpus. With None, every report
    must declare findings. With a date, reports dated before it may omit
    findings: they pass, but the result marks them
    ``findings_grandfathered: True`` so the backlog stays countable. Undated
    reports are always treated as new.

    Raises OSError when the file cannot be read, UnicodeDecodeError (a
    ValueError) when it is not valid UTF-8, and ValueError when
    ``findings_required_from`` is not a real YYYY-MM-DD date.
    """
    if findings_required_from is not None and not (
            isinstance(findings_required_from, str)
            and _DATE_RE.fullmatch(findings_required_from)
            and _real_date(findings_required_from)):
        # "2026-99-99" sorts after every real date and would grandfather
        # every report
        raise ValueError(f"findings_required_from must be a real YYYY-MM-DD "
                         f"date, got {findings_required_from!r}")
    text = path.read_text(encoding="utf-8")
    # A UTF-8 byte-order mark (Windows editors write one) would put "\ufeff"
    # before "---", and the frontmatter, with its findings and conflicts,
    # would be read as body text.
    text = text[1:] if text.startswith("\ufeff") else text
    fm, body = _split_frontmatter(text)
    issues: list[str] = []

    # Unparseable frontmatter BLOCKS. Checks 3-5 read their whole input from
    # it, so carrying on with an empty dict would grade the report on an
    # empty evidence base and call that a pass. The body checks still run and
    # report their real results.
    fm_damaged = fm is None
    if fm_damaged and not text.startswith("---"):
        issues.append(
            "frontmatter: found below line 1 — it must open on the first line of the file, "
            "with nothing above its '---', so checks 3-5 did NOT run")
    elif fm_damaged:
        issues.append(
            "frontmatter: present but UNPARSEABLE — findings/conflicts cannot "
            "be read, so checks 3-5 did NOT run (fix the YAML; an unreadable "
            "evidence base is not an empty one)")
    if fm_damaged:
        fm = {}

    issues += _misspelled_keys(fm)

    # 1. judgment lint, at every place it occurs, with the file line
    body_line0 = text[:len(text) - len(body)].count("\n")
    locations = []
    for off, problem, said in analytic.judgment_locations(body):
        line = body_line0 + body.count("\n", 0, off) + 1
        column = off - (body.rfind("\n", 0, off) + 1) + 1
        locations.append({"line": line, "column": column, "problem": problem,
                          "text": " ".join(said.split())})
        issues.append(f"judgment: {problem} at line {line}: '{' '.join(said.split())}'")

    # 1b. identifiers: malformed CVE ids always; ATT&CK ids and exploited-in-the-wild claims
    # against the reference files given (attack / kev), else counted as NOT CHECKED
    def _at(off: int) -> int:
        return body_line0 + body.count("\n", 0, off) + 1
    for off, msg in identifiers.malformed_cves(body) + identifiers.check(body, attack, kev):
        issues.append(f"{msg} (line {_at(off)})")
    claims = sum(1 for s in identifiers._SENT.finditer(body)
                 if identifiers.EXPLOITED.search(s.group(0)) and identifiers.CVE_ID.search(s.group(0)))
    ids_info = {
        "attack": {"checked": attack is not None,
                   "ids": len(identifiers.ATTACK_ID.findall(body))},
        "kev": {"checked": kev is not None, "ids": claims},
    }
    if attack is not None:
        ids_info["attack"]["version"] = attack.version
    if kev is not None:
        ids_info["kev"]["version"] = kev.version

    # 2. 5W1H coverage
    cov = analytic.coverage_5w1h(body)
    if cov["score"] < min_5w1h:
        issues.append(f"coverage: 5W1H only {cov['score']}/6 "
                      f"(missing {', '.join(cov['missing'])})")

    # 3 + 4. finding grades and the likelihood ceiling.
    #
    # With no findings declared, checks 3-5 evaluate nothing and the report
    # would be graded on the lint and 5W1H alone. That blocks, unless a
    # ratchet date is set and the report predates it; such a report passes
    # and is marked as grandfathered, never silently exempted.
    rdate = report_date(path, fm)
    for key in ("scan_date", "date"):
        v = fm.get(key)
        m = _DATE_RE.search(str(v)) if v else None
        if v and not (m and _real_date(m.group(1))):
            issues.append(f"{key}: {v!r} is not a real YYYY-MM-DD date")
    raw_findings = fm.get("findings")
    if raw_findings is not None and not isinstance(raw_findings, list):
        issues.append(f"findings: must be a list, got {type(raw_findings).__name__}")
        raw_findings = None
    has_findings = bool(raw_findings)
    grandfathered = False
    if not has_findings:
        if findings_required_from is None:
            issues.append(_NO_FINDINGS)
            issues += _needs_evidence(text, body)
        elif rdate is None or rdate >= findings_required_from:
            issues.append(
                f"findings: none declared, and this report "
                f"({'undated' if rdate is None else rdate}) is on or after the "
                f"{findings_required_from} ratchet — checks 3-5 (evidence "
                f"grade, likelihood ceiling, conflict block) did not run; "
                f"`cti-report-lint skeleton FILE` prints a findings block to start from")
            issues += _needs_evidence(text, body)
        else:
            grandfathered = True

    # Declared sources: cited by id, counted by independent root (see sources.py).
    srcs = None
    if fm.get("sources") is not None:
        srcs, src_issues = source_model.parse(fm.get("sources"))
        issues += src_issues

    graded = []
    ceilings = []      # each graded finding's evidence ceiling, for the prose check
    by_id: dict = {}   # a finding's `id` -> its ceiling, for a sentence that cites it as [id]
    for i, f in enumerate(raw_findings or []):
        if not isinstance(f, dict):
            issues.append(f"findings[{i}]: not a mapping")
            continue
        if not any(k in f for k in schema.FIELDS):
            # An entry with no grading fields used to be skipped, so a report
            # whose only finding was {} passed checks 3-5 on nothing.
            issues.append(f"findings[{i}]: no grading fields "
                          f"({', '.join(schema.FIELDS[:3])} required)")
            continue
        errs = schema.validate_fields(f)
        lk = f.get("likelihood")
        if lk is not None and lk not in analytic.LIKELIHOOD_TERMS:
            errs.append(f"likelihood {lk!r} is not one of the seven band terms")
        if errs:
            issues += [f"findings[{i}]: {e}" for e in errs]
            continue
        cited = list(f.get("confirmed_by") or [])
        n_conf = len(cited)
        roots = None
        if srcs is not None:
            roots, unknown = source_model.independent(srcs, cited)
            for u in unknown:
                issues.append(f"findings[{i}]: confirmed_by '{u}' is not a declared source")
            n_conf = len(roots)
            if int(f["trust_score"]) >= 4 and len(roots) < 2:
                issues.append(
                    f"findings[{i}]: trust {f['trust_score']} needs at least 2 independent "
                    f"sources; confirmed_by resolves to {len(roots)} independent "
                    f"({', '.join(roots) or 'none'})")
        st = schema.strength(f["finding_type"], int(f["trust_score"]), n_conf)
        row = {"index": i, "type": f["finding_type"],
               "strength": st, "likelihood": f.get("likelihood")}
        if roots is not None:
            row["independent_sources"] = len(roots)
        # the likelihood ceiling: a stated term may not exceed the evidence
        if f.get("likelihood"):
            if analytic.exceeds_ceiling(f["likelihood"], f["finding_type"],
                                        int(f["trust_score"])):
                ceil = analytic.ceiling_for(f["finding_type"],
                                            int(f["trust_score"]))
                issues.append(
                    f"findings[{i}]: likelihood '{f['likelihood']}' exceeds "
                    f"evidence ceiling '{ceil}' "
                    f"({f['finding_type']}/trust{f['trust_score']})")
        graded.append(row)
        ceilings.append(analytic.ceiling_for(f["finding_type"], int(f["trust_score"])))
        fid = f.get("id")
        if fid is not None:
            if not isinstance(fid, str) or not _FINDING_ID_RE.fullmatch(fid):
                issues.append(f"findings[{i}]: id {fid!r} must be letters, digits or '-', starting with a letter")
            elif fid in by_id:
                issues.append(f"findings[{i}]: id '{fid}' is used twice")
            else:
                by_id[fid] = ceilings[-1]

    # 4b. the ceiling in the PROSE: a band term (or its ICD 203 synonym) in the body that is
    # stronger than every graded finding allows. Without a graded finding there is no
    # ceiling to read against, and the findings issue above already blocks.
    uncited: list = []
    if graded:
        ranks = [analytic.LIKELIHOOD_TERMS.index(c) for c in ceilings if c is not None]
        top = max(ranks) if ranks else -1
        top_name = analytic.LIKELIHOOD_TERMS[top] if top >= 0 else "no single judgment"
        worst: dict[int, tuple[int, str, str]] = {}  # line -> strongest offending term, and against what
        cited_by = analytic.citation_index(body)
        for off, said in analytic.confidence_terms(body):
            if not cited_by(off):
                uncited.append((body_line0 + body.count("\n", 0, off) + 1, said))
        for off, term, said in analytic.prose_terms(body):
            rank = analytic.LIKELIHOOD_TERMS.index(term)
            line = body_line0 + body.count("\n", 0, off) + 1
            cites = cited_by(off)
            for bad in cites:
                if bad not in by_id:
                    issues.append(f"judgment: '{said}' at line {line} cites [{bad}], which no finding declares")
            cited = [by_id[c] for c in cites if c in by_id]
            if not cites:
                uncited.append((line, said))
            limit, what = top, f"the strongest evidence ceiling among the declared findings ('{top_name}')"
            if cited:      # several cited findings together allow what the strongest of them allows
                cited_ranks = [analytic.LIKELIHOOD_TERMS.index(c) for c in cited if c is not None]
                limit = max(cited_ranks) if cited_ranks else -1
                name = analytic.LIKELIHOOD_TERMS[limit] if limit >= 0 else "no single judgment"
                what = f"the ceiling of the finding it cites ('{name}')"
            if rank > limit and rank > worst.get(line, (-1, "", ""))[0]:
                worst[line] = (rank, said, what)
        for line, (_, said, what) in sorted(worst.items()):
            issues.append(f"judgment: '{said}' at line {line} exceeds {what}")
        if require_citations:
            issues += [f"judgment: '{said}' at line {line} cites no finding" for line, said in sorted(uncited)]

    # 5. conflict block
    conflicts_blocking = False
    conflict_rows = []
    raw_conflicts = fm.get("conflicts")
    if raw_conflicts is not None and not isinstance(raw_conflicts, list):
        issues.append(f"conflicts: must be a list, got {type(raw_conflicts).__name__}")
        conflicts_blocking = True
        raw_conflicts = None
    for i, c in enumerate(raw_conflicts or []):
        try:
            obj = conflict.from_dict(c)
        except (KeyError, ValueError, TypeError) as e:
            issues.append(f"conflicts[{i}]: malformed ({e})")
            conflicts_blocking = True   # an unparseable conflict cannot clear
            continue
        conflict_rows.append({"index": i, "ctype": obj.ctype,
                              "severity": obj.severity,
                              "open": obj.is_open(), "subject": obj.subject,
                              "resolution": obj.resolution, "winner": obj.winner,
                              "decided_by": (obj.resolved_by or {}).get("by"),
                              "decision_note": (obj.resolved_by or {}).get("note")})
        if obj.is_open():
            conflicts_blocking = True
            issues.append(f"conflicts[{i}]: OPEN {obj.severity} "
                          f"{obj.ctype} on '{obj.subject}' — blocks VERIFIED")

    if has_findings and not graded:
        issues.append("findings: none of the declared findings is validly graded; "
                      "checks 3-4 evaluated nothing")

    verified_ok = not issues and not conflicts_blocking
    return {
        "file": str(path),
        "verified_ok": verified_ok,
        "issues": issues,
        "coverage_5w1h": cov["score"],
        "findings_graded": graded,
        "conflicts": conflict_rows,
        "report_date": rdate,
        # True = passed ONLY because it predates the findings ratchet. Kept in
        # the result so a sweep can count the backlog.
        "findings_grandfathered": grandfathered,
        # every judgment-lint occurrence: line and column in the file, problem, text
        "judgment_locations": locations,
        # identifiers found, whether a reference file checked them, and its version
        "identifiers": ids_info,
        # band terms in the prose that cite no finding: checked only against the strongest one
        "uncited_judgments": [{"line": line, "said": said} for line, said in uncited],
    }
