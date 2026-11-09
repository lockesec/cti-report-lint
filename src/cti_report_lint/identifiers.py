"""ATT&CK technique ids and CVE ids in a report's prose, checked against reference files the
user supplies. Nothing is bundled: a stale snapshot shipped with the tool would read as current
truth. Without the files, the ids found are counted and reported NOT CHECKED.

ATT&CK (``--attack-json``: an enterprise-attack STIX bundle, as MITRE publishes it in
attack-stix-data): an id that is not in the bundle, a revoked technique (named with what
revoked it, from the bundle's ``revoked-by`` relationships), a deprecated one, and an id
followed directly by the NAME of a different technique ("T1059 Phishing"). A sub-technique may
be followed by its parent's name ("T1059.001 Command and Scripting Interpreter: PowerShell").
Every result names the bundle's ATT&CK version.

CVE: an id with fewer than four sequence digits or a year before 1999 is malformed (always
checked). With ``--kev-json`` (CISA's Known Exploited Vulnerabilities catalog), a sentence that
claims exploitation in the wild for a CVE the catalog does not list is flagged, unless the
sentence attributes the claim to a source ("according to", "reports", ...). Every result names
the catalog version.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .standards import _ATTRIBUTED_RE, _SELF_REFERENCE_RE

ATTACK_ID = re.compile(r"(?<![\w.])T\d{4}(?:\.\d{3})?(?![\w]|\.\d)")
# Any digit count: a year of five digits is malformed, and a sequence of eight or more is
# valid (the CVE syntax is "four or more digits"), so it must reach the KEV check.
CVE_ID = re.compile(r"\bCVE-(\d{2,})-(\d+)\b", re.I)
EXPLOITED = re.compile(r"\b(?:actively\s+exploited|exploited\s+in\s+the\s+wild|in[\s-]the[\s-]wild"
                       r"\s+exploitation|known\s+exploited|under\s+active\s+exploitation|"
                       r"exploitation\s+in\s+the\s+wild|being\s+exploited|exploited\s+in\s+attacks|"
                       # "could be weaponized" is a guess about the future, not a claim
                       r"(?<!could be )(?<!might be )(?<!may be )(?<!can be )weaponi[sz]ed)\b", re.I)
# a stop ends a sentence only before whitespace or the end: "FooServer 2.1", "(CVSS 9.8)"
_SENT = re.compile(r"(?:[^.!?]|[.!?](?=\S))*(?:[.!?]+|$)")
_NEGATION = re.compile(r"(?i)\b(?:no|not|never|without|neither|nor)\b|n't\b")


@dataclass
class AttackRef:
    version: str
    modified: str
    by_id: dict = field(default_factory=dict)        # id -> {name, revoked, deprecated, revoked_by}
    name_re: re.Pattern | None = None                # every technique name, longest first
    id_of_name: dict = field(default_factory=dict)   # lower name -> {ids}


@dataclass
class KevRef:
    version: str
    ids: set


def load_attack(path: Path) -> AttackRef:
    """Raises ValueError when the file is not an ATT&CK STIX bundle."""
    try:
        return _load_attack(path)
    except (AttributeError, TypeError, KeyError) as e:     # an object or reference of the wrong shape
        raise ValueError(f"{path} is not a well-formed STIX bundle ({e})") from e


def _load_attack(path: Path) -> AttackRef:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    objs = data.get("objects") if isinstance(data, dict) else None
    if not isinstance(objs, list):
        raise ValueError(f"{path} is not a STIX bundle (no objects list)")
    col = next((o for o in objs if o.get("type") == "x-mitre-collection"), {})
    ref = AttackRef(version=str(col.get("x_mitre_version", "unknown")),
                    modified=str(col.get("modified", "unknown")))
    stix_to_id = {}
    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        tid = next((r.get("external_id") for r in o.get("external_references") or []
                    if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        stix_to_id[o.get("id")] = tid
        entry = {"name": o.get("name", ""), "revoked": bool(o.get("revoked")),
                 "deprecated": bool(o.get("x_mitre_deprecated")), "revoked_by": None}
        old = ref.by_id.get(tid)
        if old is None or (old["revoked"] and not entry["revoked"]):
            ref.by_id[tid] = entry
        if entry["name"]:
            ref.id_of_name.setdefault(entry["name"].lower(), set()).add(tid)
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            src, dst = stix_to_id.get(o.get("source_ref")), stix_to_id.get(o.get("target_ref"))
            if src in ref.by_id and dst:
                ref.by_id[src]["revoked_by"] = dst
    if not ref.by_id:
        raise ValueError(f"{path} holds no ATT&CK techniques")
    names = sorted(ref.id_of_name, key=len, reverse=True)
    ref.name_re = re.compile(r"(?:" + "|".join(re.escape(n) for n in names if len(n) >= 4) + r")\b",
                             re.I)
    return ref


def load_kev(path: Path) -> KevRef:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        raise ValueError(f"{path} is not the CISA KEV catalog (no vulnerabilities list)")
    if not all(isinstance(v, dict) and isinstance(v.get("cveID"), str) for v in vulns):
        raise ValueError(f"{path} has a vulnerabilities entry with no cveID string")
    return KevRef(version=str(data.get("catalogVersion", "unknown")),
                  ids={v["cveID"].upper() for v in vulns})


def malformed_cves(text: str) -> list[tuple[int, str]]:
    out = []
    for m in CVE_ID.finditer(text):
        year, seq = m.group(1), m.group(2)
        if len(year) != 4 or int(year) < 1999 or len(seq) < 4:
            out.append((m.start(), f"cve: '{m.group(0)}' is not a well-formed CVE id "
                                   "(CVE-YYYY-NNNN, year 1999 or later, at least four digits)"))
    return out


def _name_after(text: str, end: int, ref: AttackRef) -> str | None:
    """The technique name written right after an id: "T1059 Phishing", "T1059 (Phishing)",
    "T1059: Phishing", "T1059 - Phishing"."""
    m = re.compile(r"[ \t]{0,3}(?:[(:\-–—][ \t]{0,3})?").match(text, end)
    pos = m.end() if m else end
    n = ref.name_re.match(text, pos) if ref.name_re else None
    return n.group(0).lower() if n else None


def check(text: str, attack: AttackRef | None, kev: KevRef | None) -> list[tuple[int, str]]:
    """(offset, issue) for the identifiers in ``text``."""
    out: list[tuple[int, str]] = []
    if attack is not None:
        tag = f"ATT&CK {attack.version}"
        for m in ATTACK_ID.finditer(text):
            tid = m.group(0)
            e = attack.by_id.get(tid)
            if e is None:
                out.append((m.start(), f"attack: {tid} is not a technique in {tag}"))
                continue
            if e["revoked"]:
                rb = f"; use {e['revoked_by']}" if e["revoked_by"] else ""
                out.append((m.start(), f"attack: {tid} was revoked in {tag}{rb}"))
                continue
            if e["deprecated"]:
                out.append((m.start(), f"attack: {tid} is deprecated in {tag}"))
                continue
            said = _name_after(text, m.end(), attack)
            if said is not None:
                ok = {e["name"].lower()}
                parent = attack.by_id.get(tid.split(".")[0])
                if parent:
                    ok.add(parent["name"].lower())
                if said not in ok:
                    other = ", ".join(sorted(attack.id_of_name.get(said, ())))
                    out.append((m.start(), f"attack: {tid} is '{e['name']}' in {tag}, but the "
                                           f"text names it '{said}' ({other})"))
    if kev is not None:
        for s in _SENT.finditer(text):
            sent = s.group(0)
            if not EXPLOITED.search(sent):
                continue
            flat = re.sub(r"\s+", " ", sent)
            if _ATTRIBUTED_RE.search(_SELF_REFERENCE_RE.sub(" ", flat)):
                continue
            # judged clause by clause: a clause that negates the claim ("no evidence ... is
            # exploited in the wild", "is not known to be exploited") makes no claim
            off = 0
            for clause in re.split(r"(;)", sent):
                start, off = off, off + len(clause)
                m = EXPLOITED.search(clause)
                if not m or _NEGATION.search(clause[:m.start()]):
                    continue
                for c in CVE_ID.finditer(clause):
                    cid = c.group(0).upper()
                    if cid in kev.ids:
                        continue
                    out.append((s.start() + start + c.start(),
                                f"cve: {cid} is said to be exploited in the wild, but CISA KEV "
                                f"{kev.version} does not list it; cite the source of the claim"))
    out.sort()
    return out
