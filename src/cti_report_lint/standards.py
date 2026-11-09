"""Analytic-judgment rules for threat-intelligence and incident reports.

Adapts the ideas in cti-expert ``handbook/analytic-standards.md``
(https://github.com/7onez/cti-expert, MIT, see NOTICE). The likelihood band
table itself is ICD 203's; cti-expert is where it was read. All code in this
module is original to this project.

Without a judgment layer, a strong hunch reads exactly like a corroborated
fact. Three mechanisms address that:

1. Probability-anchored likelihood language. Seven terms, each a numeric
   band. Never 0 or 100: open-source evidence cannot establish either. One
   term per judgment ("likely to very likely" hedges across two bands). Never
   a bare percentage on your own judgment (false precision).
   ``likelihood_term(pct)`` maps a probability to its term, and
   ``lint_judgment()`` flags hedged, bare-percentage and absolute language.

2. Likelihood is separate from confidence, and both should be stated.
   Likelihood says how probable a claim is; confidence says how good the
   evidence base is. High likelihood on weak evidence is a legitimate thing
   to report. ``ceiling_for()`` caps the strongest defensible likelihood term
   at the evidence grade of the finding (see ``findings``), so a single
   unverified source cannot underwrite "almost certain".

3. A 5W1H coverage overlay. Effort measures (sources scanned, items
   collected) say nothing about whether a report answers anything.
   ``coverage_5w1h()`` reports which of who/what/when/where/why/how the report
   body actually addresses.
"""
from __future__ import annotations

import bisect
import re

# (term, low_pct, high_pct): ICD 203 estimative-language bands. The endpoints
# exclude 0 and 100.
LIKELIHOOD_BANDS = [
    ("almost no chance", 1, 5),
    ("very unlikely", 5, 20),
    ("unlikely", 20, 45),
    ("roughly even chance", 45, 55),
    ("likely", 55, 80),
    ("very likely", 80, 95),
    ("almost certain", 95, 99),
]
LIKELIHOOD_TERMS = [t for t, _, _ in LIKELIHOOD_BANDS]

# The strongest likelihood term a single finding of a given evidence grade may
# underwrite. Weak evidence caps how far up the ladder a judgment can go,
# however probable the analyst feels the claim is.
#
# The table is cti-expert's ("Mapping to the existing scales" in
# handbook/analytic-standards.md), keyed on the finding's trust score:
#   trust 5 -> "almost certain"      trust 4 -> "very likely"
#   trust 3 -> "likely"              trust 2 -> "roughly even chance"
#   trust 1 -> no single judgment (state the conflict instead)
# The finding TYPE can only lower the ceiling, never raise it: CONTESTED
# permits no single judgment, and ANECDOTAL permits at most "roughly even
# chance". A PRIMARY or CONFIRMED finding does not lift a low trust score.
_TRUST_CEILING = {5: "almost certain", 4: "very likely", 3: "likely",
                  2: "roughly even chance"}
_TYPE_CEILING = {"ANECDOTAL": "roughly even chance"}


def ceiling_for(finding_type: str, trust_score: int) -> str | None:
    """Strongest likelihood term the evidence allows, or None when the
    evidence cannot support any single judgment."""
    ft = finding_type.upper()
    trust_ceiling = _TRUST_CEILING.get(int(trust_score))
    if ft == "CONTESTED" or trust_ceiling is None:
        return None  # cannot render a single judgment: state the conflict
    type_ceiling = _TYPE_CEILING.get(ft)
    if type_ceiling is not None and _term_rank(type_ceiling) < _term_rank(trust_ceiling):
        return type_ceiling
    return trust_ceiling


def likelihood_term(pct: float) -> str:
    """Map a probability in percent to its band term."""
    if not (0 < pct < 100):
        raise ValueError("open-source likelihood cannot be 0 or 100")
    for term, lo, hi in LIKELIHOOD_BANDS:
        if lo <= pct < hi:
            return term
    return "almost certain" if pct >= 95 else "almost no chance"


def _term_rank(term: str) -> int:
    return LIKELIHOOD_TERMS.index(term) if term in LIKELIHOOD_TERMS else -1


def exceeds_ceiling(term: str, finding_type: str, trust_score: int) -> bool:
    """True when a stated likelihood is stronger than the evidence allows."""
    if term not in LIKELIHOOD_TERMS:
        # rank -1 read as "below every ceiling", so an unknown term passed
        raise ValueError(f"unknown likelihood term {term!r}")
    ceil = ceiling_for(finding_type, trust_score)
    if ceil is None:
        return True  # no single judgment is defensible: any term overshoots
    return _term_rank(term) > _term_rank(ceil)


# Characters that render as nothing (soft hyphen, zero-width and directional marks, word joiner,
# BOM). redact.py strips the full set for detection; here they may sit inside a band term.
_INVIS = "\u00ad\u034f\u061c\u180b-\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff"
_INVIS_RUN = "[" + _INVIS + "]*"
# Cyrillic and Greek letters drawn like Latin ones, one for one so offsets hold. The reader sees
# "almost certain", so the check must. Text in those scripts holds no English band term to find.
_LOOKALIKES = str.maketrans("\u0430\u0441\u0435\u0456\u0458\u043e\u0440\u0455\u0443\u0445\u04bb\u0501\u04cf"
                            "\u0410\u0412\u0421\u0415\u041d\u0406\u0408\u041a\u041c\u041e\u0420\u0405\u0422\u0425\u03bf\u03b1\u03b9\u03ba\u03bd\u03c1\u03c4\u03c5",
                            "aceijopsyxhdl" "ABCEHIJKMOPSTX" "oaikvpty")


def _spaced(term: str) -> str:
    """A term whose words may be separated by white space of any length, a line break
    included (report prose is hard-wrapped), or by hyphens ("almost-certain"). Invisible
    characters may sit anywhere inside it: the reader sees the term, so the check must."""
    word = lambda w: _INVIS_RUN.join(re.escape(c) for c in w)
    return ("[\\s" + _INVIS + "-]+").join(word(w) for w in term.split())


_TERMS_ALT = "|".join(_spaced(t) for t in sorted(LIKELIHOOD_TERMS, key=len, reverse=True))
# A hedge is two band terms joined DIRECTLY: "likely to very likely",
# "likely or very likely", "likely/very likely". An earlier form allowed any
# text between the terms, so "likely to continue; reinfection is likely" was
# read as a range, and the lazy scan was quadratic on long input.
_HEDGE_RE = re.compile(
    r"\b(?:" + _TERMS_ALT + r")(?:\s+(?:to|or)\s+|\s*[/\u2013\u2014-]\s*)(?:"
    + _TERMS_ALT + r")\b", re.IGNORECASE)
_BARE_PCT_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\s?%|\s(?:percent|per\s+cent)\b)",
                          re.IGNORECASE)
# 0% and 100% need no trailing \b: "%" is not a word character, so a \b
# after it only matched when a letter followed ("100%confirmed"), and the
# canonical "100% certain" never fired. A negated absolute ("not
# guaranteed", "isn't impossible") is the honest phrasing, not the claim.
_ABSOLUTE_RE = re.compile(
    r"(?<![\d.])(?:0|100)(?:\.0+)?(?:\s?%|\s(?:percent|per\s+cent)\b)|"
    r"\b(?:no\s+chance\s+whatsoever|absolutely\s+certain|virtually\s+certain|no\s+doubt|"
    r"impossible(?![\s-]+travel\b)|guaranteed|"
    # certainty adverbs with no band: "certainly TeamPCP" claims what "almost certainly" grades
    r"certainly|definitely|undoubtedly|unquestionably|conclusively|"
    r"without\s+(?:a|any)\s+doubt|beyond\s+(?:a|any)\s+doubt)\b",
    re.IGNORECASE)
# The negation is checked in Python, not by a lookbehind: report prose is
# hard-wrapped, so "not\nguaranteed" must read like "not guaranteed", and a
# lookbehind cannot match a run of whitespace of any length.
_NEG_WORDS = ("not", "never")
_NEG_CLITICS = ("n't", "n\u2019t", "n\u2018t")


def _negated(text: str, pos: int) -> bool:
    """True when the word just before text[pos] (whitespace between) is a
    negation. Looks back over the whitespace run and at most 5 characters, so
    the cost per match is bounded by the whitespace run it follows."""
    if pos <= 0 or not text[pos - 1].isspace():
        return False
    i = pos
    while i > 0 and text[i - 1].isspace():
        i -= 1
    tail = text[max(0, i - 5):i].lower()
    if tail.endswith(_NEG_CLITICS):
        return True
    for w in _NEG_WORDS:
        if tail.endswith(w) and not (len(tail) > len(w)
                                     and tail[-len(w) - 1].isalnum()):
            return True
    return False


def _banded(text: str, pos: int) -> bool:
    """True when "almost" or "nearly" comes just before text[pos]: "almost certainly" is the
    top ICD 203 band, not an absolute."""
    head = re.sub(r"\s+", " ", text[max(0, pos - 12):pos]).lower()
    return re.search(r"(?:^|[^a-z])(?:almost|nearly) $", head) is not None


def _excused(text: str, m: "re.Match") -> bool:
    return m.group(0)[0].isalpha() and (_negated(text, m.start()) or _banded(text, m.start()))


def _has_absolute(text: str) -> bool:
    return any(not _excused(text, m) for m in _ABSOLUTE_RE.finditer(text))

# The percentage rule is scoped to JUDGMENT sentences. Two different things
# share one surface form, and only one is the malpractice:
#   (a) "Vendor X reports 90% of incidents ..." is an attributed measurement:
#       sourced data that belongs in the report at its real value;
#   (b) "we assess with 90% confidence ..." is invented precision on the
#       author's own judgment, which is what this rule exists to stop.
# A whole-document rule blocks (a), and the only way to clear it would be to
# reword real data, which is worse than the false positive.
_JUDGMENT_CUE_RE = re.compile(
    r"\b(we (assess|judge|estimate)|assess(ed|ment|es)?|estimate[sd]?|"
    r"confidence|confident|sure|certain|probability|likelihood)\b", re.IGNORECASE)
# The document referring to itself ("in this report", "our report") is not a
# source, so it must not count as attribution.
_SELF_REFERENCE_RE = re.compile(r"\b(?:(?:this|our|the present)\s+report|we\s+attribute)\b",
                                re.IGNORECASE)
_ATTRIBUTED_RE = re.compile(
    r"\b(reports?|reported|reporting|according to|per\s+(?!(?:cent|year|annum|day|month|week|hour|minute|second|our|se)\b)\w+|cites?|cited|"
    r"telemetry|survey(ed)?|attributes?|attributed)\b", re.IGNORECASE)


# Band terms as they appear in prose, with ICD 203's synonyms and the common "highly likely".
# "remote" (ICD 203's synonym for "almost no chance") is left out: in an incident report it
# almost always means remote access, and a low term can never exceed a ceiling anyway.
PROSE_SYNONYMS = {
    "almost no chance": ("almost no chance",),
    "very unlikely": ("very unlikely", "highly improbable"),
    "unlikely": ("unlikely", "improbable", "improbably"),
    "roughly even chance": ("roughly even chance", "roughly even odds"),
    "likely": ("likely", "probable", "probably"),
    "very likely": ("very likely", "highly probable", "highly likely"),
    "almost certain": ("almost certain", "almost certainly", "nearly certain", "nearly certainly"),
}
_CANON = {surface: canon for canon, forms in PROSE_SYNONYMS.items() for surface in forms}
_PROSE_TERM_RE = re.compile(
    r"\b(?:" + "|".join(_spaced(t) for t in sorted(_CANON, key=len, reverse=True)) + r")\b",
    re.IGNORECASE)
# A sentence also ends at a blank line and before a heading or list item, which carry no full
# stop: a heading saying "Threat reports" must not read as attributing the sentence under it.
_SENTENCE_RE = re.compile(r"(?m:^[ \t]*#{1,6}[ \t][^\n]*(?:\n+|$))|(?:[^.!?\n]|[.!?]+(?=[^\s\[])|\n(?![ \t]*(?:\n|#{1,6}[ \t]|[-*+] |\d+\. )))*(?:[.!?]+|\n+|$)")
# A sentence about the scale itself ("the likelihood scale runs from ... to ...") is not a
# judgment.
# "scale", "band" and "term" alone are ordinary words ("in the long term", "large-scale"), so
# they count only beside the word that makes them talk about likelihood.
_METALANGUAGE_RE = re.compile(
    r"\b(?:icd\s*203|estimative|"
    r"(?:likelihood|probability|probabilistic|confidence|estimative|ranking)"
    r"[\s-]+(?:scale|bands?|terms?|language|vocabulary)|"
    r"(?:scale|bands?|terms?)\s+(?:of|for)\s+(?:likelihood|probability|confidence)|"
    r"(?:likelihood|probability)\s+(?:\w+\s+){0,2}(?:scale|bands?|terms?)|"
    r"band\s+terms?|(?:strongest|weakest)\s+terms?|(?:seven|7)\s+(?:band\s+)?(?:terms?|bands?))\b", re.IGNORECASE)
_QUOTES = "\"'\u201c\u2018"
_CLOSING = {"\"": "\"", "'": "'", "\u201c": "\u201d", "\u2018": "\u2019"}


def _closes(text: str, m: "re.Match") -> bool:
    """True when the quote just before the match is closed later in its paragraph: only then is
    the term quoted. A lone quote mark ('We judge "almost certain') quotes nothing."""
    close = _CLOSING[text[m.start() - 1]]
    tail = text[m.end():m.end() + 500]          # bounded: linear over many quoted terms
    end = tail.find("\n\n")
    return close in (tail if end < 0 else tail[:end])


_CITATION_RE = re.compile(r"\[([A-Za-z][A-Za-z0-9-]*)\](?![\[(:])")
_LEADING_CITATIONS = re.compile(r"[ \t]*(?:\[[A-Za-z][A-Za-z0-9-]*\](?![\[(:])[ \t]*)+")
_NOT_PROSE = re.compile(r"(?s:<!--.*?(?:-->|\Z))|(?ms:^[ \t]*```.*?(?:^[ \t]*```[^\n]*$|\Z))|`[^`\n]*`|(?m:^[ \t]*\[[^\]\n]*\]:[^\n]*$)")


def citation_index(text: str):
    """A function from an offset in `text` to the finding ids its sentence cites as [id]: inside
    the sentence, or on the same line right after its full stop. Code, HTML comments, link definitions, and
    [id][ref], [id](url) and [id]: forms are not citations. Linear: one pass over the text."""
    masked = _NOT_PROSE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    spans = [(m.start(), m.end()) for m in _SENTENCE_RE.finditer(masked) if m.end() > m.start()]
    cites: list = [[] for _ in spans]
    for k, (a, b) in enumerate(spans):
        lead = _LEADING_CITATIONS.match(masked, a, b)
        body_from = a
        if lead and k and "\n" not in masked[spans[k - 1][1] - 1:a + 1] and lead.end() > a:
            cites[k - 1] += [m.group(1) for m in _CITATION_RE.finditer(masked, a, lead.end())]
            body_from = lead.end()
        cites[k] += [m.group(1) for m in _CITATION_RE.finditer(masked, body_from, b)]
    starts = [a for a, _ in spans]

    def at(off: int) -> list:
        k = bisect.bisect_right(starts, off) - 1
        return cites[k] if k >= 0 else []
    return at


_CONFIDENCE_RE = re.compile(
    r"\b(?:high|moderate|medium)[-\s]+(?:level[-\s]+of[-\s]+|degree[-\s]+of[-\s]+)?confidence\b"
    r"|\b(?:highly|moderately)[-\s]+confident\b|\bwe\s+attribute\b", re.IGNORECASE)
_DENIED_RE = re.compile(r"\b(?:no|not|lack|lacks|lacked|lacking|without|never|nor)\b[^.!?\n]{0,30}$", re.IGNORECASE)


def confidence_terms(text: str) -> list:
    """(offset, words as written) for each judgment worded as confidence or as "we attribute".
    Confidence is not likelihood (see the top of this file), so these have no ceiling. They are how
    real reports word their strongest claims, and they need evidence just the same. Low confidence,
    a denied one and someone else's are left out."""
    text = text.translate(_LOOKALIKES)
    spans = [(m.start(), m.end()) for m in _SENTENCE_RE.finditer(text) if m.end() > m.start()]
    starts = [a for a, _ in spans]
    out = []
    for m in _CONFIDENCE_RE.finditer(text):
        k = bisect.bisect_right(starts, m.start()) - 1
        a, b = spans[k] if k >= 0 else (0, len(text))
        sent = re.sub(r"\s+", " ", text[a:b])
        if _DENIED_RE.search(text[max(a, m.start() - 40):m.start()]):
            continue
        if _METALANGUAGE_RE.search(sent) or _ATTRIBUTED_RE.search(_SELF_REFERENCE_RE.sub(" ", sent)):
            continue
        out.append((m.start(), " ".join(m.group(0).split())))
    return out


def prose_terms(text: str) -> list[tuple[int, str, str]]:
    """(offset, band term, words as written) for each likelihood judgment in the prose.

    Skipped: a negated term ("not likely"), a quoted one, and any term in a sentence that
    attributes the judgment to a source ("according to", "reports", "attributes") or talks
    about the scale itself. Linear: one pass for sentences, one for terms."""
    text = text.translate(_LOOKALIKES)
    spans = [(m.start(), m.end()) for m in _SENTENCE_RE.finditer(text) if m.end() > m.start()]
    starts = [a for a, _ in spans]
    skip: dict[int, bool] = {}
    out = []
    for m in _PROSE_TERM_RE.finditer(text):
        if _negated(text, m.start()):
            continue
        if m.start() > 0 and text[m.start() - 1] in _QUOTES and _closes(text, m):
            continue
        k = bisect.bisect_right(starts, m.start()) - 1
        if k not in skip:
            a, b = spans[k] if k >= 0 else (0, len(text))
            sent = re.sub(r"\s+", " ", text[a:b])
            skip[k] = bool(_METALANGUAGE_RE.search(sent)
                           or _ATTRIBUTED_RE.search(_SELF_REFERENCE_RE.sub(" ", sent)))
        if skip[k]:
            continue
        said = " ".join(m.group(0).split())
        # the canonical key: invisibles dropped, hyphens read as spaces
        key = " ".join(re.sub("[" + _INVIS + "]", "", said).replace("-", " ").lower().split())
        out.append((m.start(), _CANON[key], said))
    return out


def _sentences(text: str) -> list[str]:
    # Normalize whitespace first. Report prose is hard-wrapped mid-sentence,
    # and a per-line scope would separate the judgment cue from the number.
    flat = re.sub(r"\s+", " ", text)
    return re.split(r"(?<=[.!?])\s+", flat)


HEDGE = "hedged likelihood range (use ONE term per judgment)"
BARE_PCT = "bare percentage (false precision — use a band term)"
ABSOLUTE = "0/100 or absolute language (OSINT cannot establish)"
_BOUNDARY_RE = re.compile(r"(?<=[.!?])\s+")


def judgment_locations(text: str) -> list[tuple[int, str, str]]:
    """(offset, problem, matched text) for every occurrence of the three malpractices: a
    hedged range, a bare percentage in the author's own judgment sentence (not one attributed
    to a source), and 0/100 or absolute language that is not negated. Sentences end at
    `.`, `!` or `?` followed by white space, as before; offsets are into ``text``."""
    text = text.translate(_LOOKALIKES)
    out = [(m.start(), HEDGE, m.group(0)) for m in _HEDGE_RE.finditer(text)]
    a = 0
    bounds = [m.end() for m in _BOUNDARY_RE.finditer(text)] + [len(text)]
    for b in bounds:
        sent = text[a:b]
        flat = re.sub(r"\s+", " ", sent)
        if (_JUDGMENT_CUE_RE.search(flat)
                and not _ATTRIBUTED_RE.search(_SELF_REFERENCE_RE.sub(" ", flat))):
            out += [(a + m.start(), BARE_PCT, m.group(0)) for m in _BARE_PCT_RE.finditer(sent)]
        a = b
    for m in _ABSOLUTE_RE.finditer(text):
        if _excused(text, m):
            continue
        out.append((m.start(), ABSOLUTE, m.group(0)))
    out.sort()
    return out


def lint_judgment(text: str) -> list[str]:
    """The distinct problems `judgment_locations` finds, in a fixed order: hedge, bare
    percentage, absolute."""
    found = {p for _, p, _ in judgment_locations(text)}
    return [p for p in (HEDGE, BARE_PCT, ABSOLUTE) if p in found]


# 5W1H coverage: cue words per dimension. A cue is a coverage SIGNAL, not
# proof of a good answer; a missing dimension is the actionable gap.
_5W1H_CUES = {
    "who": (r"\b(actor|group|apt|adversary|operator|attribut|threat[- ]actor|"
            r"who\b)"),
    "what": r"\b(malware|ransomware|technique|tool|payload|cve|vulnerabilit|what\b)",
    "when": (r"\b(first[- ]seen|observed|timeline|dwell|since|as of|"
             r"20\d\d-\d\d|when\b)"),
    "where": (r"\b(sector|region|geograph|target(ed|ing)?|infrastructure|"
              r"country|where\b)"),
    "why": r"\b(motivation|objective|intent|financial|espionage|goal|why\b)",
    "how": (r"\b(vector|delivery|exploit|initial access|ttp|kill[- ]chain|"
            r"technique|how\b)"),
}


def coverage_5w1h(body: str) -> dict:
    """Which of who/what/when/where/why/how the text addresses, by cue word."""
    low = body.lower()
    answered = {dim: bool(re.search(pat, low))
                for dim, pat in _5W1H_CUES.items()}
    return {"answered": answered,
            "covered": [d for d, v in answered.items() if v],
            "missing": [d for d, v in answered.items() if not v],
            "score": sum(answered.values())}
