"""Behaviours no test held until seeded regressions got through the suite. Sample addresses
are assembled from fragments so secret scanners do not flag this file."""
from __future__ import annotations

import pytest

from cti_report_lint import identifiers as I
from cti_report_lint import redact as R

BASE58_OK = "1A1zP1eP5QGefi2" + "DMPTfTL5SLmv7DivfNa"       # the Bitcoin genesis address
BECH32M_OK = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7k" + "w508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y"  # BIP-350


def kinds(text):
    return [k for _, _, k in R.find_spans(text)]


def test_eight_character_phone_number_is_redacted():
    assert kinds("call 12345678 now") == ["PHONE"]
    assert kinds("call +12345678 now") == ["PHONE"]


def test_seven_digits_stay_in_clear():
    assert kinds("call 1234567 now") == []


def test_dates_and_cve_ids_are_still_not_phones():
    assert kinds("Seen 2026-09-24 today") == []
    assert "PHONE" not in kinds("Patch CVE-2024-12345 first")


def test_valid_base58check_address_is_redacted_and_a_corrupt_one_is_not_btc():
    assert "BTC" in kinds(f"pay {BASE58_OK} now")
    assert "BTC" not in kinds(f"pay {BASE58_OK[:-1]}b now")


def test_bech32m_taproot_address_is_redacted():
    assert "BTC" in kinds(f"pay {BECH32M_OK} now")


def test_cve_year_before_1999_is_malformed_and_1999_is_not():
    assert I.malformed_cves("CVE-1998-1234")
    assert I.malformed_cves("CVE-1995-1234")
    assert not I.malformed_cves("CVE-1999-1234")


# ---- second round: gaps an independent verification pass found --------------------------
import json
import time
from pathlib import Path

import pytest

from cti_report_lint import identifiers, sources, standards
from cti_report_lint.cli import main
from cti_report_lint.validate import validate_report

_FM = ("---\ndate: 2026-09-21\nfindings:\n  - finding_type: ANECDOTAL\n    trust_score: 2\n"
       "    source_reliability: D\n    confirmed_by: []\n    likelihood: roughly even chance\n")
_BODY = ("Who: the actor. What: ransomware. When: 2026-09-20. Where: finance sector.\n"
         "Why: financial. How: phishing attachment.\n\n")


def _check(tmp_path, prose, fm=_FM + "---\n", name="r.md"):
    p = tmp_path / name
    p.write_text(fm + _BODY + prose + "\n", encoding="utf-8")
    return validate_report(p)


def _ceiling(res):
    return [i for i in res["issues"] if "exceeds the strongest evidence ceiling" in i]


@pytest.mark.parametrize("key", ["conflict", "Conflicts", "CONFLICTS", "finding", "scan-date",
                                 "Sources"])
def test_a_misspelled_frontmatter_key_is_reported_not_ignored(tmp_path, key):
    fm = _FM + f"{key}: []\n---\n"
    res = _check(tmp_path, "Plain text.", fm)
    assert any(f"key {key!r} is not read" in i for i in res["issues"]), res["issues"]
    assert not res["verified_ok"]


def test_exact_keys_and_unrelated_keys_raise_no_key_issue(tmp_path):
    fm = _FM + "title: Weekly\ntags: [a]\nconflicts: []\n---\n"
    res = _check(tmp_path, "Plain text.", fm)
    assert not [i for i in res["issues"] if "is not read" in i]


@pytest.mark.parametrize("prose", [
    "In the long term, the actor is almost certain to return.",
    "Over a short term the actor is almost certain to return.",
    "A large-scale campaign makes the actor almost certain to return.",
    "The band played on and the actor is almost certain to return.",
])
def test_ordinary_words_term_scale_band_do_not_excuse_a_top_band_claim(tmp_path, prose):
    assert _ceiling(_check(tmp_path, prose))


@pytest.mark.parametrize("prose", [
    "The likelihood scale tops out at almost certain.",
    "ICD 203 ends its bands with almost certain.",
    "The seven band terms run up to almost certain.",
])
def test_a_sentence_about_the_scale_is_still_not_a_judgment(tmp_path, prose):
    assert not _ceiling(_check(tmp_path, prose))


@pytest.mark.parametrize("prose", [
    "The actor is almost-certain to return.",
    "The actor is almost​ certain to return.",
    "The actor is al​most certain to return.",
    "The actor is almost cer­tain to return.",
    "The actor is very-likely to return.",
])
def test_hyphen_and_invisible_characters_do_not_hide_a_band_term(tmp_path, prose):
    assert _ceiling(_check(tmp_path, prose))


def test_per_se_is_not_an_attribution(tmp_path):
    assert _ceiling(_check(tmp_path, "Per se, the actor is almost certain to return."))
    assert not _ceiling(_check(tmp_path, "Per Vendor X, the actor is almost certain to return."))


def test_a_lone_quote_mark_does_not_quote_a_term(tmp_path):
    assert _ceiling(_check(tmp_path, 'We judge "almost certain that the actor returns.'))
    assert not _ceiling(_check(tmp_path, 'The vendor wrote "almost certain" in its note.'))


def test_hedge_scan_is_linear_in_a_long_whitespace_run():
    text = "likely" + " " * 60000
    t0 = time.perf_counter()
    standards.judgment_locations(text)
    assert time.perf_counter() - t0 < 1.0


def test_hedges_still_found_after_the_separator_change():
    for s in ("likely to very likely", "likely or very likely", "likely/very likely",
              "likely - very likely", "likely–very likely"):
        assert standards.lint_judgment(s) == [standards.HEDGE], s
    assert standards.lint_judgment("likely to continue; reinfection is likely") == []


def test_cve_ids_with_long_sequences_or_five_digit_years_are_seen():
    assert identifiers.malformed_cves("CVE-20245-1234")
    assert not identifiers.malformed_cves("CVE-2024-12345678")
    assert identifiers.CVE_ID.search("CVE-2024-12345678").group(0) == "CVE-2024-12345678"
    kev = identifiers.KevRef(version="t", ids=set())
    out = identifiers.check("CVE-2024-12345678 is actively exploited in the wild.", None, kev)
    assert out and "CVE-2024-12345678" in out[0][1]


def test_unhashable_source_entries_are_issues_not_tracebacks(tmp_path):
    fm = (_FM.replace("confirmed_by: []", "confirmed_by: [[a, b], {k: v}]")
          + "sources:\n  - {id: a, reliability: B, derived_from: [x]}\n---\n")
    res = _check(tmp_path, "Plain text.", fm)
    assert not res["verified_ok"]
    assert any("derived_from must be a source id" in i for i in res["issues"])
    assert any("is not a declared source" in i for i in res["issues"])
    assert sources.independent({"a": {}}, [["a"]]) == ([], [["a"]])


def test_check_output_shows_control_characters_as_escapes(tmp_path, capsys):
    p = tmp_path / "r.md"
    subj = "x\\nfake.md: PASS (5W1H 6/6)\\u001b]0;pwned\\u0007"
    p.write_text(_FM + f'conflicts:\n  - {{ctype: TIME_IMPOSSIBLE, subject: "{subj}", '
                 "a: {source: s1, value: 1, trust_score: 3}, "
                 "b: {source: s2, value: 2, trust_score: 3}}\n---\n" + _BODY, encoding="utf-8")
    main(["check", str(p)])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert not [ln for ln in out.splitlines() if ln.startswith("fake.md")]
    assert "\\x1b" in out and "\\n" in out


# redaction -------------------------------------------------------------------------------

_IP = "203.0." + "113.7"


def test_values_butted_against_cjk_text_are_redacted():
    cjk = "住所"
    assert kinds(f"{cjk}{_IP}{cjk}") == ["IPV4"]
    assert kinds(f"{cjk}http://example.com/a?t=1{cjk}") == ["URL"]
    assert kinds(f"{cjk}555-012-3456{cjk}") == ["PHONE"]


def test_values_butted_against_latin_letters_are_still_left_alone():
    assert kinds(f"src{_IP}") == []


@pytest.mark.parametrize("addr", ["o'brien@example.com", "john!smith@example.com",
                                  "ops/alice@example.com", "first=last@example.com",
                                  "a&b@example.com"])
def test_email_local_parts_with_rfc_punctuation_are_redacted_whole(addr):
    text = f"mail {addr} now"
    spans = R.find_spans(text)
    assert [text[s:e] for s, e, k in spans if k == "EMAIL"] == [addr]


def test_a_quote_or_asterisk_around_an_email_stays_outside_the_span():
    for text, addr in (("'a@example.com'", "a@example.com"),
                       ("**a@example.com**", "a@example.com"),
                       ("`a@example.com`", "a@example.com")):
        assert [text[s:e] for s, e, _ in R.find_spans(text)] == [addr]


def test_email_scan_is_linear_over_a_long_punctuation_run():
    text = "a'" * 30000
    t0 = time.perf_counter()
    R.find_spans(text)
    assert time.perf_counter() - t0 < 2.0


def test_url_with_an_apostrophe_is_redacted_whole_and_a_closing_quote_is_not():
    text = "see https://portal.example/o'brien/reset?token=ZZTOP99 now"
    assert [text[s:e] for s, e, _ in R.find_spans(text)] == [
        "https://portal.example/o'brien/reset?token=ZZTOP99"]
    text = "see 'https://portal.example/a', then"
    assert [text[s:e] for s, e, _ in R.find_spans(text)] == ["https://portal.example/a"]


def test_phone_with_a_letter_extension_is_redacted():
    text = "call 555-012-3456x123 now"
    assert [text[s:e] for s, e, _ in R.find_spans(text)] == ["555-012-3456"]
    text = "call +1 (555) 012-3456x9 now"
    assert [text[s:e] for s, e, _ in R.find_spans(text)] == ["+1 (555) 012-3456"]


def test_resolution_like_runs_are_not_phones_after_the_extension_rule():
    assert kinds("size 1920x1080 and 640x480x32") == []


def test_redact_reports_the_placeholders_this_file_uses(tmp_path, capsys):
    seed_src, plain, m = tmp_path / "a.md", tmp_path / "b.md", tmp_path / "m.json"
    seed_src.write_text(f"host {_IP}\n", encoding="utf-8")
    plain.write_text("nothing personal here\n", encoding="utf-8")
    assert main(["redact", str(seed_src), "--map", str(m), "-o", str(tmp_path / "a.out")]) == 0
    capsys.readouterr()
    assert main(["redact", str(plain), "--map", str(m), "-o", str(tmp_path / "b.out")]) == 0
    assert "redacted 0 span(s) (0 new)" in capsys.readouterr().err


def test_redact_with_an_unusable_map_directory_exits_2_without_a_traceback(tmp_path, capsys):
    src = tmp_path / "a.md"
    src.write_text(f"host {_IP}\n", encoding="utf-8")
    rc = main(["redact", str(src), "--map", str(tmp_path / "missing_dir" / "m.json"),
               "-o", str(tmp_path / "o.md")])
    assert rc == 2
    assert "cannot lock or create the map" in capsys.readouterr().err
    assert not (tmp_path / "o.md").exists()


# --- rulings from the verification pass ------------------------------------------------------

def test_cyrillic_lookalikes_read_as_the_band_term():
    from cti_report_lint import standards as S
    said = "It is аlmost certain that the group did this."      # Cyrillic a
    assert [t for _, t, _ in S.prose_terms(said)] == ["almost certain"]


def test_cyrillic_lookalikes_do_not_shift_offsets():
    from cti_report_lint import standards as S
    said = "It is аlmost certain that the group did this."
    assert S.prose_terms(said)[0][0] == said.index("а")


def test_a_lookalike_absolute_is_read():
    from cti_report_lint import standards as S
    assert S.judgment_locations("This is dеfinitely the group.")


def test_real_cyrillic_prose_is_not_a_finding():
    from cti_report_lint import standards as S
    assert S.prose_terms("Группа активна.") == []


@pytest.mark.parametrize("said", ["It is virtually certain that they did it.", "There is no doubt they did it."])
def test_more_absolute_phrasings(said):
    from cti_report_lint import standards as S
    assert [p for _, p, _ in S.judgment_locations(said)] == [S.ABSOLUTE]


@pytest.mark.parametrize("said", ["It is almost certain that they did it.", "They are certain of the date.",
                                  "It is not virtually certain."])
def test_bare_certain_and_the_negated_form_stay_quiet(said):
    from cti_report_lint import standards as S
    assert not [p for _, p, _ in S.judgment_locations(said) if p == S.ABSOLUTE]


def _kev():
    return I.KevRef(ids=frozenset(), version="t")


@pytest.mark.parametrize("said", ["CVE-2024-1234 has been weaponized.", "CVE-2024-1234 was weaponised this week.",
                                  "CVE-2024-1234 is being exploited.", "CVE-2024-1234 was exploited in attacks."])
def test_more_kev_phrasings_when_the_cve_is_in_the_clause(said):
    assert [m for _, m in I.check(said, None, _kev()) if "exploited in the wild" in m]


@pytest.mark.parametrize("said", ["Exploits were weaponized; CVE-2024-1234 is unrelated.",
                                  "CVE-2024-1234 could be weaponized.", "CVE-2024-1234 might be weaponized."])
def test_kev_phrasings_stay_quiet_without_a_claim_on_that_cve(said):
    assert not [m for _, m in I.check(said, None, _kev()) if "exploited in the wild" in m]


def _report(tmp_path):
    p = tmp_path / "r.md"
    p.write_text("---\ntitle: t\n---\nBody.\n")
    return p


def test_require_references_refuses_without_the_files(tmp_path, capsys):
    from cti_report_lint.cli import main
    assert main(["check", str(_report(tmp_path)), "--require-references"]) == 2
    err = capsys.readouterr().err
    assert "--attack-json" in err and "--kev-json" in err and "NOT EVALUABLE" in err


def test_without_the_flag_a_report_is_judged_as_before(tmp_path):
    from cti_report_lint.cli import main
    assert main(["check", str(_report(tmp_path))]) != 2
