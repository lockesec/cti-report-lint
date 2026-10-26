"""ATT&CK technique ids and CVE ids in the prose, checked against reference files the user
supplies (`--attack-json`, `--kev-json`); without them the ids are reported NOT CHECKED, never
clean. No reference data is bundled."""
import json
from pathlib import Path

import pytest
from cti_report_lint import cli, identifiers
from cti_report_lint.validate import validate_report


def tech(tid, name, sid, revoked=False, deprecated=False):
    return {"type": "attack-pattern", "id": sid, "name": name, "revoked": revoked,
            "x_mitre_deprecated": deprecated,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}]}


BUNDLE = {"type": "bundle", "objects": [
    {"type": "x-mitre-collection", "x_mitre_version": "20.0", "modified": "2026-10-13T00:00:00Z",
     "name": "Enterprise ATT&CK"},
    tech("T1059", "Command and Scripting Interpreter", "attack-pattern--1"),
    tech("T1059.001", "PowerShell", "attack-pattern--2"),
    tech("T1566", "Phishing", "attack-pattern--3"),
    tech("T1086", "PowerShell", "attack-pattern--4", revoked=True),
    tech("T1064", "Scripting", "attack-pattern--5", deprecated=True),
    {"type": "relationship", "relationship_type": "revoked-by",
     "source_ref": "attack-pattern--4", "target_ref": "attack-pattern--2"},
]}
KEV = {"catalogVersion": "2026.10.16", "dateReleased": "2026-10-16T00:00:00Z",
       "vulnerabilities": [{"cveID": "CVE-2023-4966"}]}


@pytest.fixture
def refs(tmp_path):
    a, k = tmp_path / "attack.json", tmp_path / "kev.json"
    a.write_text(json.dumps(BUNDLE))
    k.write_text(json.dumps(KEV))
    return identifiers.load_attack(a), identifiers.load_kev(k)


def found(text, refs):
    return [m for _, m in identifiers.check(text, *refs)]


def test_an_unknown_technique_is_named_with_the_version(refs):
    out = found("Initial access used T1999.", refs)
    assert any("T1999" in m and "20.0" in m for m in out)


def test_a_revoked_technique_names_its_replacement(refs):
    out = found("Execution via T1086.", refs)
    assert any("T1086" in m and "revoked" in m and "T1059.001" in m for m in out)


def test_a_deprecated_technique_is_named(refs):
    assert any("T1064" in m and "deprecated" in m for m in found("They used T1064.", refs))


@pytest.mark.parametrize("text", ["They used T1059 Phishing to get in.",
                                  "Technique: T1566 (PowerShell)."])
def test_an_id_paired_with_another_techniques_name_is_flagged(text, refs):
    assert any("name" in m for m in found(text, refs))


@pytest.mark.parametrize("text", [
    "They used T1059 (Command and Scripting Interpreter).",
    "T1059.001 PowerShell ran the loader.",
    "T1059.001 Command and Scripting Interpreter: PowerShell ran the loader.",
    "Phishing (T1566) delivered it.",
    "See T1059.",
])
def test_correct_and_plain_citations_are_quiet(text, refs):
    assert found(text, refs) == []


def test_an_exploitation_claim_for_a_cve_not_in_kev_is_flagged(refs):
    out = found("CVE-2026-1234 is being actively exploited in the wild.", refs)
    assert any("CVE-2026-1234" in m and "KEV" in m and "2026.10.16" in m for m in out)


@pytest.mark.parametrize("text", [
    "CVE-2023-4966 is being actively exploited in the wild.",
    "According to the vendor advisory, CVE-2026-1234 is exploited in the wild.",
    "CVE-2026-1234 was patched in the October release.",
])
def test_kev_listed_attributed_or_unclaimed_cves_are_quiet(text, refs):
    assert found(text, refs) == []


@pytest.mark.parametrize("text", ["CVE-2023-123 is listed.", "CVE-1987-12345 is listed."])
def test_a_malformed_cve_id_is_flagged_without_any_reference_file(text):
    assert identifiers.malformed_cves(text)


def test_without_reference_files_the_ids_are_not_checked_never_clean(tmp_path, capsys):
    p = tmp_path / "r.md"
    p.write_text("---\nfindings:\n  - {finding_type: PRIMARY, trust_score: 3, source_reliability: B, "
                 "confirmed_by: [edr]}\n---\nWho actor what malware when 2026-01-01 where sector "
                 "how T1059. CVE-2026-1234 is exploited in the wild.\n")
    res = validate_report(p)
    assert res["identifiers"]["attack"] == {"checked": False, "ids": 1}
    assert res["identifiers"]["kev"] == {"checked": False, "ids": 1}
    cli.main(["check", str(p)])
    assert "NOT CHECKED" in capsys.readouterr().out


def test_with_reference_files_the_check_runs_and_blocks(tmp_path, capsys):
    a, k = tmp_path / "attack.json", tmp_path / "kev.json"
    a.write_text(json.dumps(BUNDLE))
    k.write_text(json.dumps(KEV))
    p = tmp_path / "r.md"
    p.write_text("---\nfindings:\n  - {finding_type: PRIMARY, trust_score: 3, source_reliability: B, "
                 "confirmed_by: [edr]}\n---\nWho actor what malware when 2026-01-01 where sector "
                 "how T1086.\n")
    rc = cli.main(["check", str(p), "--attack-json", str(a), "--kev-json", str(k)])
    out = capsys.readouterr().out
    assert rc == 1 and "revoked" in out and "ATT&CK 20.0" in out


def test_an_unreadable_reference_file_is_not_evaluable(tmp_path, capsys):
    p = tmp_path / "r.md"
    p.write_text("x")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert cli.main(["check", str(p), "--attack-json", str(bad)]) == 2


# An exploited-in-the-wild claim that is negated is not a claim.
NOT_LISTED_KEV = identifiers.KevRef(version="t", ids={"CVE-2023-4966"})


@pytest.mark.parametrize("text", [
    "There is no evidence CVE-2023-99999 is exploited in the wild.",
    "CVE-2023-99999 is not known to be exploited in the wild.",
    "We have not seen CVE-2023-99999 exploited in the wild.",
    "CVE-2023-99999 isn't exploited in the wild yet.",
])
def test_a_negated_exploitation_claim_is_not_a_claim(text):
    assert identifiers.check(text, None, NOT_LISTED_KEV) == []


def test_in_a_mixed_sentence_only_the_claimed_cve_is_flagged():
    out = [m for _, m in identifiers.check(
        "CVE-2023-99999 is not exploited in the wild; CVE-2023-88888 is actively exploited in the wild.",
        None, NOT_LISTED_KEV)]
    assert len(out) == 1 and "CVE-2023-88888" in out[0]
