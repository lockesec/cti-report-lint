"""Reversible redaction of personal data in reports.

Adapts cti-expert ``scripts/redact.py`` (https://github.com/7onez/cti-expert,
MIT License, Copyright (c) 2026 Hieu Ngo - chongluadao.vn; the full notice is
in NOTICE).

Copied verbatim from that file:
  * the IPv4 octet expression and the two Bitcoin address alternatives in
    ``PATTERNS``. The boundaries around them are this project's: upstream's
    ``\b`` let Markdown ``_emphasis_`` hide a value, since ``_`` is a word
    character.
Adapted from it (same idea, different text):
  * numbered ``[KIND_N...]`` placeholders, one stable map per run, keyed on
    the literal string;
  * the EMAIL, IBAN, PHONE and URL kinds, whose regexes differ from
    upstream's.
Original to this project:
  * span-based detection with one overlap resolution, per-map placeholder
    nonces, and the single-pass non-recursive restore (upstream substitutes
    kind by kind and restores longest-first; this project did the same until
    a release review showed nested spans could not round-trip);
  * IPv6 detection by candidate plus ``ipaddress`` validation, in linear
    time (a regex with overlapping groups was cubic);
  * checksum validation (IBAN mod-97, base58check and bech32/bech32m), which
    keeps hashes and identifiers from being taken for accounts or wallets;
  * the fail-loud restore (upstream passes unmapped placeholders through),
    which also refuses placeholders from another map;
  * the KEEP pass that leaves dates and identifiers in clear and stops them
    from being taken for, or hiding, phone numbers;
  * detection through invisible format characters (see _INVISIBLE_RE).

Behavior: each detected span becomes a stable numbered placeholder such as
``[EMAIL_1#3fa9c2]``. The six hex digits after ``#`` are the map's NONCE: one
per map, chosen so it does not already occur in the text. Text that merely
looks like a placeholder (``[EMAIL_1]`` in a report about redaction) can
therefore never be mistaken for one. The map (placeholder -> original) is
plain JSON, so a redacted report stays readable for analysis, and the holder
of the map can restore the original byte for byte. Seed one map across a
whole run for consistent numbering.

Detection runs against the ORIGINAL text, never against partly redacted
text. Kinds are tried in priority order (PLACEHOLDER, URL, EMAIL, IPV6, IPV4,
IBAN, BTC, then the KEEP pass, then PHONE) and a later kind only searches the
gaps earlier kinds left. Placeholder-shaped text already in the input is
itself redacted, so a restored document never meets a bare placeholder of
another map. So a URL
holding an email address becomes one ``[URL_...]`` span, never a URL whose
stored original contains another placeholder.

A trade-off kept from upstream, on purpose: placeholders key on the LITERAL
string, so one address written two ways gets two placeholders. Byte-exact
restore requires this; normalizing would make restore lossy.

Fail-loud contract: restoring a placeholder that carries the map's nonce but
is not in the map RAISES, and so does a placeholder carrying another nonce. It never passes the bracket text through. A
redacted report with an incomplete map is corrupt, and corruption must not
read as clean.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import re
import secrets
from typing import Callable, Iterator

# Boundaries are "not next to a letter or digit". Not \b: "_" is a word
# character, so \b let Markdown emphasis (_203.0.113.7_) hide a value.
#
# Scripts written without spaces (Han, kana, Hangul, Thai) are not "letters" here: a value
# butted against CJK text ("<CJK>203.0.113.7") is still a value, and counting the CJK character
# as a neighbouring letter left it in clear.
_SPACELESS = ("\u0e00-\u0e7f\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff"
              "\uf900-\ufaff\uac00-\ud7af")
_LETTER = r"[^\W_" + _SPACELESS + r"]"     # a letter or digit that is not spaceless script
_NB = r"(?<!" + _LETTER + r")"     # not preceded by a letter or digit
_NA = r"(?!" + _LETTER + r")"      # not followed by a letter or digit

# (kind, pattern). Kinds with a custom finder (IPV6, IBAN, BTC, PHONE, KEEP)
# are proposed by these patterns and confirmed in Python; see _finder.
PATTERNS: list[tuple[str, str]] = [
    # Placeholder-shaped text already in the input (a report ABOUT redaction
    # quoting another map's placeholder). Redacting it too means restore can
    # refuse every foreign placeholder it meets without breaking a round trip.
    ("PLACEHOLDER", r"\[[A-Z0-9]+_\d+#[0-9a-f]{6}\]"),
    # An apostrophe is legal in a URL ("/o'brien/reset?token=..."), so it ends the URL only
    # when nothing URL-like follows it (a closing quote: 'https://x/y', ).
    ("URL", _NB + r"(?:(?i:https?|hxxps?|s?ftp)://|(?i:www)\.(?=[^\W_]))"
            r"(?:[^\s<>\"'`]|'(?=[\w%~/#?&=@-]))+"),
    # The domain is a name, or an address literal ("john@[192.0.2.1]",
    # "john@[IPv6:2001:db8::1]"); a literal left the local part in clear.
    # The local part takes every RFC 5322 "atext" character (o'brien, john!smith, ops/alice,
    # first=last); _email_spans drops any that lead the match (a quote or asterisk around it).
    ("EMAIL", r"(?<![\w.%+'!#$&*/=?^`{|}~-])[\w.%+'!#$&*/=?^`{|}~-]+@(?:(?:[\w-]+\.)+"
              r"(?:(?i:xn--)[\w-]+|[^\W\d_]{2,})(?![^\W_]|-[\w-]*\.[^\W\d_])|"
              r"\[(?:(?i:IPv6):[0-9A-Fa-f:.]+|\d{1,3}(?:\.\d{1,3}){3})\])"),
    ("IPV4", _NB + r"(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
             r"(?:25[0-5]|2[0-4]\d|1?\d?\d)" + _NA + r"(?!\.\d)"),
    ("IBAN", _NB + r"[A-Za-z]{2}\d{2}(?:[A-Za-z0-9]{11,30}|"
             r"(?: [A-Za-z0-9]{4}){2,7}(?: [A-Za-z0-9]{1,4})?|"
             r"(?:-[A-Za-z0-9]{4}){2,7}(?:-[A-Za-z0-9]{1,4})?)" + _NA),
    ("BTC", _NB + r"(?:bc1[a-z0-9]{25,90}|BC1[A-Z0-9]{25,90}|"
            r"[13][a-km-zA-HJ-NP-Z1-9]{25,34})" + _NA),
    # Analytic content that must never be taken for a phone number: ISO and
    # DD.MM.YYYY dates, CVE/CWE/... identifiers. Found, then left in clear.
    ("KEEP", _NB + r"(?:\d{4}-\d{2}-\d{2}|\d{2}\.\d{2}\.\d{4}|"
             r"(?i:CVE|CWE|CAPEC|GHSA|OSV|EDB-ID|KB)-?[0-9A-Za-z]+"
             r"(?:-[0-9A-Za-z]+)*)(?!\d)"),
    ("PHONE", _NB + r"\+?\d[\d\s().-]*"),
]
PRIORITY = ("PLACEHOLDER", "URL", "EMAIL", "IPV6", "IPV4", "IBAN", "BTC",
            "KEEP", "PHONE")
KINDS = frozenset(PRIORITY) - {"KEEP"}

# Invisible characters are absent from a rendered report but break every
# pattern ("bob<U+200B>@example.com"). Detection runs on a view without them;
# the span handed to the map still holds them, so restore stays byte-exact.
# The set, and why:
#   * every Unicode format character (category Cf) that renders as nothing:
#     soft hyphen U+00AD, Arabic letter mark U+061C, Mongolian vowel separator
#     U+180E, zero-width and directional marks U+200B-200F, bidi embeddings and
#     overrides U+202A-202E, word joiner and invisible operators U+2060-2064,
#     bidi isolates and the deprecated shaping controls U+2066-206F, BOM/ZWNBSP
#     U+FEFF, interlinear annotation anchors U+FFF9-FFFB, the egyptian
#     hieroglyph, shorthand and musical format controls, and the tag characters
#     U+E0001 and U+E0020-E007F;
#   * U+034F combining grapheme joiner, which is a nonspacing mark that
#     renders as nothing;
#   * variation selectors U+FE00-FE0F, U+E0100-E01EF and the Mongolian free
#     variation selectors U+180B-180D (no glyph of their own);
# NOT included: the Cf characters that print a visible sign before a number
# or word (Arabic number signs U+0600-0605, U+06DD, U+08E2, Syriac
# abbreviation mark U+070F, Arabic pound/piastre marks U+0890-0891, Kaithi
# number signs U+110BD and U+110CD). Hangul fillers are letters, not marks,
# and are left alone.
_INVISIBLE_RE = re.compile(
    "[\u00ad\u034f\u061c\u180b-\u180e\u200b-\u200f\u202a-\u202e"
    "\u2060-\u2064\u2066-\u206f\ufe00-\ufe0f\ufeff\ufff9-\ufffb"
    "\U00013430-\U0001343f\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    "\U000e0001\U000e0020-\U000e007f\U000e0100-\U000e01ef]")

# Backstop for a PHONE-shaped run that still holds a date or follows an
# identifier prefix (the KEEP pass handles the ordinary forms).
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_ID_PREFIX = re.compile(r"(?:CVE|CWE|CAPEC|GHSA|OSV|EDB-ID|KB)-?$", re.I)
_ID_DIGITS = re.compile(r"\d+(?:-\d+)*")
_PHONE_START = re.compile(_NB + r"\+?\d")

# IPv6: one maximal hex/colon/dot run, then a bounded set of windows at its
# end, each confirmed by ipaddress. No nested quantifiers, so time is linear.
_HEX_RUN = re.compile(r"[0-9A-Fa-f:.]+")
# A zone part is never followed by ':' or more alphanumerics, so it cannot
# swallow the first group of a following address ("%eth0-2001:db8::1").
_ZONE = re.compile(r"%[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+(?![A-Za-z0-9:]))*")
_IPV6_MAX = 45           # longest textual IPv6 (with an IPv4 tail)

_NONCE_RE = re.compile(r"[0-9a-f]{6}")
_KEY_RE = re.compile(r"\[([A-Z0-9]+)_(\d+)#([0-9a-f]{6})\]")


_LETTER_RE = re.compile(_LETTER)


def _isalnum(text: str, i: int) -> bool:
    return 0 <= i < len(text) and _LETTER_RE.match(text[i]) is not None


def _ipv6_spans(text: str, a: int, b: int) -> Iterator[tuple[int, int]]:
    for m in _HEX_RUN.finditer(text, a, b):
        rs, re_ = m.span()
        run = m.group(0)
        if run.count(":") < 2:
            continue
        # Ends: the run end, or with any trailing '.'/':' run dropped
        # (sentence punctuation, "addr 2001:db8::1: seen"). An address that
        # stopped mid-run would be part of a longer token, so no other end.
        # The trailing run may be any length ("addr....."): find where it
        # starts, then try only the first four ends from there, so the work
        # stays bounded however long the run is.
        base = re_
        while base - 1 > rs and text[base - 1] in ".:":
            base -= 1
        ends = list(range(min(re_, base + 3), base - 1, -1))
        # Starts: the run start when nothing alphanumeric precedes it, or
        # just after a '.' or the FIRST ':' ("IPv6:2001:db8::1",
        # "addr:fe80::1", "x.2001:db8::1"). Only windows that can be an
        # address (at most _IPV6_MAX long) are considered.
        first_colon = run.index(":")
        lo = max(0, (base - rs) - _IPV6_MAX)
        starts = [rs] if lo == 0 and not _isalnum(text, rs - 1) else []
        starts += [rs + i + 1 for i in range(lo, first_colon + 1) if run[i] in ".:"]
        found = _first_ipv6(text, starts, ends, b)
        if found:
            yield found


def _first_ipv6(text: str, starts: list[int], ends: list[int],
                b: int) -> tuple[int, int] | None:
    for st in starts:
        for en in ends:
            if not 0 < en - st <= _IPV6_MAX:
                continue
            cand = text[st:en]
            if cand.count(":") < 2 or cand.count("::") > 1 and ":::" not in cand:
                continue
            if cand == "::":
                # the bare unspecified address only as [::] or ::/N; "::"
                # in prose is punctuation
                if not ((st > 0 and text[st - 1] == "[" and text[en:en + 1] == "]")
                        or text[en:en + 1] == "/"):
                    continue
            elif not any(c in "0123456789abcdefABCDEF" for c in cand):
                continue
            end = en
            z = _ZONE.match(text, en, b) if text[en:en + 1] == "%" else None
            if z:
                end = z.end()
            if end < b and _isalnum(text, end):
                continue
            try:
                ipaddress.IPv6Address(cand)
            except ValueError:
                continue
            return st, end
    return None


def _iban_ok(s: str) -> bool:
    s = s.upper()
    if not 15 <= len(s) <= 34:
        return False
    digits = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(digits) % 97 == 1


def _iban_spans(text: str, a: int, b: int) -> Iterator[tuple[int, int]]:
    pat = _compiled("IBAN")
    for m in pat.finditer(text, a, b):
        groups = re.split("[ -]", m.group(0))
        # The spaced form may have swallowed a short word after the IBAN
        # ("... 7034 and"); drop trailing groups until the checksum holds.
        for k in range(len(groups), 0, -1):
            if _iban_ok("".join(groups[:k])):
                yield m.start(), m.start() + len(m.group(0)) - sum(
                    len(g) + 1 for g in groups[k:])
                break


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _base58check_ok(s: str) -> bool:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    raw = b"\0" * (len(s) - len(s.lstrip("1"))) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(raw) != 25:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def _bech32_ok(s: str) -> bool:
    s = s.lower()
    data = s[3:]
    if len(data) < 6 or any(c not in _BECH32 for c in data):
        return False
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in [3, 3, 0, 2, 3] + [_BECH32.index(c) for c in data]:   # hrp "bc" expanded
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk in (1, 0x2BC830A3)      # bech32 (BIP-173) or bech32m (BIP-350)


def _btc_spans(text: str, a: int, b: int) -> Iterator[tuple[int, int]]:
    for m in _compiled("BTC").finditer(text, a, b):
        s = m.group(0)
        ok = _bech32_ok(s) if s[:3].lower() == "bc1" else _base58check_ok(s)
        if ok:
            yield m.span()


def _keep_spans(text: str, a: int, b: int) -> Iterator[tuple[int, int]]:
    for m in _compiled("KEEP").finditer(text, a, b):
        s = m.group(0)
        if len(s) == 10 and s[2] == "." and s[5] == ".":
            try:
                datetime.date(int(s[6:]), int(s[3:5]), int(s[:2]))
            except ValueError:
                continue      # not a real DD.MM.YYYY date: may be a phone
        yield m.span()


def _extension(text: str, i: int) -> bool:
    """True at the "x" of a phone extension: "555-012-3456x123"."""
    return text[i] in "xX" and i + 1 < len(text) and text[i + 1].isdigit()


def _phone_spans(text: str, a: int, b: int) -> Iterator[tuple[int, int]]:
    """A phone is '+'? digit, then 7+ of [digits space ( ) . -], ending on a
    digit that no letter or digit follows, so 8 characters at least. Found as one maximal run per
    start, so the time is linear (a backtracking regex was not)."""
    for m in _compiled("PHONE").finditer(text, a, b):
        rs, run_end = m.span()
        # the latest digit in the run that is a valid end
        end = None
        for i in range(run_end - 1, rs - 1, -1):
            if text[i].isdigit():
                nxt = i + 1
                if (nxt < run_end or nxt >= b or not _isalnum(text, nxt)
                        or _extension(text, nxt)):
                    if nxt == run_end or not text[nxt].isdigit():
                        end = nxt
                        break
        if end is None:
            continue
        pos = rs
        while pos < end:
            sm = _PHONE_START.search(text, pos, end)
            if not sm:
                break
            s = sm.start()
            digit0 = s + 1 if text[s] == "+" else s
            if end - digit0 < 8:
                break
            d = _ISO_DATE.search(text, s, end)
            if d:
                pos = d.end()          # re-scan AFTER the date, never drop the rest
                continue
            if _ID_PREFIX.search(text, max(0, s - 8), s):
                pos = _ID_DIGITS.match(text, digit0, end).end()
                continue
            yield s, end
            break


_COMPILED: dict[str, re.Pattern] = {}


def _compiled(kind: str) -> re.Pattern:
    if kind not in _COMPILED:
        _COMPILED[kind] = re.compile(dict(PATTERNS)[kind])
    return _COMPILED[kind]


_URL_TRAILING = set(".,;:!?*_'\"")


def _url_spans(text: str, a: int, b: int) -> Iterator[tuple[int, int]]:
    for m in _compiled("URL").finditer(text, a, b):
        s, e = m.span()
        url = m.group(0)
        opens = {"(": url.count("("), "[": url.count("[")}
        closes = {")": url.count(")"), "]": url.count("]")}
        pair = {")": "(", "]": "["}
        # Trim sentence punctuation and Markdown markers, and a closing
        # bracket the URL did not open ("[a](https://x/y)").
        while e > s:
            c = text[e - 1]
            if c in _URL_TRAILING:
                e -= 1
            elif c in pair and closes[c] > opens[pair[c]]:
                closes[c] -= 1
                e -= 1
            else:
                break
        if e - s > len("www.") :
            yield s, e


def _email_spans(text: str, a: int, b: int) -> Iterator[tuple[int, int]]:
    for m in _compiled("EMAIL").finditer(text, a, b):
        s, e = m.span()
        while s < e and text[s] in _EMAIL_LEAD_STRIP:
            s += 1                   # a quote, asterisk or backtick wrapped around the address
        if "@" in text[s:e] and text[s] != "@":
            yield s, e


_EMAIL_LEAD_STRIP = "'!#$&*/=?^`{|}~"


def _finder(kind: str) -> Callable[[str, int, int], Iterator[tuple[int, int]]]:
    custom = {"IPV6": _ipv6_spans, "IBAN": _iban_spans, "BTC": _btc_spans,
              "KEEP": _keep_spans, "PHONE": _phone_spans, "URL": _url_spans,
              "EMAIL": _email_spans}
    if kind in custom:
        return custom[kind]
    pat = _compiled(kind)

    def find(text: str, a: int, b: int) -> Iterator[tuple[int, int]]:
        for m in pat.finditer(text, a, b):
            yield m.span()
    return find


def _find_view(text: str) -> list[tuple[int, int, str]]:
    taken: list[tuple[int, int, str]] = []
    for kind in PRIORITY:
        edges = sorted((s, e) for s, e, _ in taken)
        gaps, pos = [], 0
        for s, e in edges:
            if s > pos:
                gaps.append((pos, s))
            pos = max(pos, e)
        if pos < len(text):
            gaps.append((pos, len(text)))
        find = _finder(kind)
        for a, b in gaps:
            taken += _no_overlap([(s, e, kind) for s, e in find(text, a, b)
                                  if e > s])
    out = sorted(t for t in taken if t[2] != "KEEP")
    for (s1, e1, _), (s2, _e2, _k) in zip(out, out[1:]):
        if s2 < e1:                       # a bug, never an input: refuse loudly
            raise AssertionError(f"overlapping spans {s1}:{e1} and {s2}")
    return out


def _no_overlap(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Deterministic overlap resolution within one kind: leftmost start wins,
    the longer span on a tie; a span starting before the kept one ends is
    dropped."""
    kept: list[tuple[int, int, str]] = []
    for t in sorted(spans, key=lambda t: (t[0], -t[1])):
        if kept and t[0] < kept[-1][1]:
            continue
        kept.append(t)
    return kept


def find_spans(text: str) -> list[tuple[int, int, str]]:
    """Non-overlapping (start, end, kind) spans over the ORIGINAL text. Each
    kind, in PRIORITY order, searches only the gaps earlier kinds left.
    Invisible characters (see _INVISIBLE_RE) are ignored for detection and
    kept inside spans."""
    if not _INVISIBLE_RE.search(text):
        return _find_view(text)
    idx = [i for i, c in enumerate(text) if not _INVISIBLE_RE.match(c)]
    view = "".join(text[i] for i in idx)
    return [(idx[s], idx[e - 1] + 1, k) for s, e, k in _find_view(view)]


def map_nonce(mapping: dict) -> str | None:
    """The nonce shared by every key of a map, None for an empty map. Raises
    ValueError on a malformed map: a key that is not a placeholder, a value
    that is not a string, an unknown kind, or keys with different nonces."""
    nonces = set()
    for k, v in mapping.items():
        m = _KEY_RE.fullmatch(k) if isinstance(k, str) else None
        if not m or m.group(1) not in KINDS:
            raise ValueError(f"map key {k!r} is not a placeholder of this tool")
        if not isinstance(v, str) or not v:
            raise ValueError(f"map value for {k} must be a non-empty string")
        nonces.add(m.group(3))
    if len(nonces) > 1:
        raise ValueError(f"map mixes placeholder nonces {sorted(nonces)}")
    return nonces.pop() if nonces else None


def _placeholder_re(nonce: str) -> re.Pattern:
    return re.compile(r"\[[A-Z0-9]+_\d+#" + re.escape(nonce) + r"\]")


class RoundTripError(Exception):
    """redact() produced output that does not restore to its input."""


def redact(text: str, existing_map: dict | None = None) -> tuple[str, dict]:
    """Return (redacted_text, map), where map is placeholder -> original.

    ``existing_map`` seeds the numbering and the nonce so ONE map covers a
    whole run; the same literal string always gets the same placeholder within
    a run. Raises ValueError if the seed map is malformed, or if the text
    already holds a placeholder carrying the seed's nonce (redacting a
    document twice with one map would make restore ambiguous).
    """
    fwd = dict(existing_map or {})
    nonce = map_nonce(fwd)
    if nonce is None:
        nonce = secrets.token_hex(3)
        while f"#{nonce}]" in text:
            nonce = secrets.token_hex(3)
    elif _placeholder_re(nonce).search(text):
        raise ValueError("input already contains placeholders from this map; "
                         "restore it first or use a new map")
    rev = {v: k for k, v in fwd.items()}
    counters: dict[str, int] = {}
    for k in fwd:
        m = _KEY_RE.fullmatch(k)
        counters[m.group(1)] = max(counters.get(m.group(1), 0), int(m.group(2)))

    out: list[str] = []
    pos = 0
    for s, e, kind in find_spans(text):
        orig = text[s:e]
        ph = rev.get(orig)
        if ph is None:
            counters[kind] = counters.get(kind, 0) + 1
            ph = f"[{kind}_{counters[kind]}#{nonce}]"
            fwd[ph] = orig
            rev[orig] = ph
        out += [text[pos:s], ph]
        pos = e
    out.append(text[pos:])
    red = "".join(out)
    # The promise made structural: restore our own output with the new map
    # and compare bytes before anything leaves this function.
    try:
        back = restore(red, fwd)
    except (KeyError, ValueError) as e:
        raise RoundTripError(f"redaction would not restore byte-exact "
                             f"({e}); nothing written") from e
    if back != text:
        raise RoundTripError("redaction would not restore byte-exact; "
                             "nothing written")
    return red, fwd


def restore(text: str, mapping: dict) -> str:
    """Reconstitute the original in ONE non-recursive pass: a restored value is
    never scanned again, so an original that happens to contain placeholder
    text comes back verbatim. Raises KeyError on any placeholder that carries
    the map's nonce but is not in the map, or that carries another map's nonce
    (corruption or mixed documents, not a pass-through); ValueError on a
    malformed map."""
    nonce = map_nonce(mapping)
    if nonce is None:
        # An empty map restores nothing, so any placeholder in the text is one
        # it cannot account for: refuse rather than pass it through.
        stray = sorted({m.group(0) for m in _KEY_RE.finditer(text)})
        if stray:
            raise KeyError(f"restore: {len(stray)} placeholder(s) and an empty map "
                           f"({', '.join(stray[:5])}) — refusing to emit a "
                           "partially-restored document")
        return text
    foreign = sorted({m.group(3) for m in _KEY_RE.finditer(text)} - {nonce})
    if foreign:
        # redact() redacts placeholder-shaped text it finds, so a genuine
        # redacted document never shows a bare placeholder of another map.
        # One here means documents from different maps were mixed.
        raise KeyError(
            f"restore: placeholder(s) from another map (nonce "
            f"{', '.join(foreign[:5])}; this map is {nonce}) — refusing to "
            "emit a partially-restored document")
    pat = _placeholder_re(nonce)
    missing = sorted({m.group(0) for m in pat.finditer(text) if m.group(0) not in mapping})
    if missing:
        raise KeyError(
            f"restore: {len(missing)} placeholder(s) absent from map "
            f"({', '.join(missing[:5])}{', …' if len(missing) > 5 else ''}) "
            "— refusing to emit a partially-restored document")
    return pat.sub(lambda m: mapping[m.group(0)], text)
