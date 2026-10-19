"""Reversible redaction, in both directions: redact -> restore is byte-exact,
and restoring an unmapped placeholder FAILS LOUD.

Secret-looking sample values (an IBAN, a Bitcoin address) are assembled from
fragments so that secret scanners do not flag this file.
"""
from __future__ import annotations

import pytest

from cti_report_lint import redact as R


def ph(mapping: dict, kind: str, n: int) -> str:
    """The placeholder for KIND_n in this map (placeholders carry the map's nonce)."""
    nonce = R.map_nonce(mapping)
    return f"[{kind}_{n}#{nonce}]"

IBAN = "GB29" + "NWBK" + "6016" + "1331" + "926819"
BTC = "bc1q" + "xy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
EMAIL = "soc" + "@" + "acme.example"

SAMPLE = (
    f"Contact {EMAIL} from 203.0.113.7 or call +1 (555) 234-5678.\n"
    f"Wallet {BTC} received funds via {IBAN}. "
    "Mirror at https://panel.example/login.\n"
)


def test_round_trip_is_byte_exact():
    red, mapping = R.redact(SAMPLE)
    assert red != SAMPLE
    assert R.restore(red, mapping) == SAMPLE


def test_pii_actually_removed_from_redacted_text():
    red, mapping = R.redact(SAMPLE)
    for secret in (EMAIL, "203.0.113.7", IBAN, BTC, "https://panel.example"):
        assert secret not in red, secret
    for kind in ("EMAIL", "IPV4", "IBAN", "BTC", "PHONE", "URL"):
        assert ph(mapping, kind, 1) in red, kind


@pytest.mark.parametrize("addr", ["2001:db8::1", "2001:db8:0:0:0:0:0:2", "fe80::1",
                                  "::1", "2001:db8::ffff:192.0.2.1"])
def test_each_ipv6_form_is_redacted(addr):
    """Each form on its own: the old test mixed a compressed and an expanded
    address and only proved ONE was caught (the compressed one was not)."""
    text = f"peer {addr} seen"
    red, mapping = R.redact(text)
    assert addr not in red and red == f"peer {ph(mapping, 'IPV6', 1)} seen"
    assert R.restore(red, mapping) == text


@pytest.mark.parametrize("text", ["at 12:30:45 UTC", "std::vector and Foo::bar",
                                  "MAC aa:bb:cc:dd:ee:ff", "ratio 3:2:1"])
def test_ipv6_candidates_that_are_not_addresses_survive(text):
    red, mapping = R.redact(text)
    assert red == text and not mapping


def test_ipv4_and_btc_bodies_are_upstreams_verbatim():
    """The IPv4 octet expression and the base58/bech32 alternatives are
    copied from cti-expert scripts/redact.py; the NOTICE file relies on that
    being true. The boundaries around them are this project's (upstream's
    \\b let Markdown _emphasis_ hide a value), and so is the uppercase
    bech32 alternative."""
    pats = dict(R.PATTERNS)
    assert (r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)") in pats["IPV4"]
    assert "bc1[a-z0-9]{25,90}|" in pats["BTC"]
    assert "[13][a-km-zA-HJ-NP-Z1-9]{25,34}" in pats["BTC"]


# ── restore FAILS LOUD on an unmapped placeholder ───────────────────────

def test_restore_unmapped_placeholder_raises():
    red, mapping = R.redact(SAMPLE)
    tampered = red + f"\nLeftover {ph(mapping, 'EMAIL', 99)} token."
    with pytest.raises(KeyError, match="absent from map"):
        R.restore(tampered, mapping)


def test_restore_never_silently_passes_through():
    _, mapping = R.redact("call +1 (555) 234-5678")
    with pytest.raises(KeyError):
        R.restore(f"see {ph(mapping, 'PHONE', 3)} now", mapping)


# ── literal-string keying (a trade-off kept from upstream) ──────────────

def test_same_string_reuses_one_placeholder():
    text = "mail a@example.com then a@example.com again"
    red, mapping = R.redact(text)
    assert red.count(ph(mapping, "EMAIL", 1)) == 2
    assert len([k for k in mapping if k.startswith("[EMAIL_")]) == 1


def test_two_literal_forms_get_two_placeholders():
    text = "Soc@Acme.example and soc@acme.example"
    red, mapping = R.redact(text)
    assert len([k for k in mapping if k.startswith("[EMAIL_")]) == 2
    assert R.restore(red, mapping) == text


def test_double_digit_placeholder_not_shadowed():
    mapping = {f"[EMAIL_{i}#a1b2c3]": f"user{i}@example.net" for i in range(1, 12)}
    out = R.restore(" ".join(mapping), mapping)
    assert "user10@example.net" in out and "user11@example.net" in out
    assert "[EMAIL_" not in out


def test_seed_map_continues_numbering():
    red1, map1 = R.redact("first a@example.com")
    red2, map2 = R.redact("second c@example.org", existing_map=map1)
    assert R.map_nonce(map2) == R.map_nonce(map1)
    assert ph(map1, "EMAIL", 1) in red1
    assert map2[ph(map2, "EMAIL", 1)] == "a@example.com"
    assert ph(map2, "EMAIL", 2) in red2
    assert map2[ph(map2, "EMAIL", 2)] == "c@example.org"


# ── dates and identifiers are analytic content, not personal data ───────

@pytest.mark.parametrize("text", [
    "Seen 2026-09-24 exploiting CVE-2024-12345 from host.",
    "Window 2026-09-01 - 2026-09-24 covered.",
    "Tracked as CWE-79 and cve-2021-44228; patched by KB5034441.",
    "Advisory GHSA-2024-12345678 and EDB-ID-12345678 apply.",
])
def test_dates_and_identifiers_are_not_redacted_as_phones(text):
    red, mapping = R.redact(text)
    assert red == text and not mapping


def test_attack_technique_ids_survive():
    text = "Observed T1059.001 and T1566.001 on 2026-09-20."
    red, mapping = R.redact(text)
    assert red == text and not mapping


def test_real_phone_numbers_are_still_redacted():
    text = "Call +1 (555) 123-4567 or 555-123-4567 now."
    red, mapping = R.redact(text)
    assert "555" not in red and len(mapping) == 2
    assert R.restore(red, mapping) == text


# ── nested spans and collisions ────────────────────────────────────────
# Each case below failed to round-trip on the first local commit.

@pytest.mark.parametrize("text", [
    "see https://" + "a@b" + ".example.com/path now",   # email inside a URL
    "fetch http://198.51.100.7/x now",                    # IPv4 inside a URL
    "mail " + "x@198.51.100.7" + ".example.org ok",       # IPv4 inside an email
    "literal [EMAIL_1] beside " + "x@y" + ".example.org",  # placeholder-shaped input
    "[URL_1] https://panel.example/a [EMAIL_2]",
])
def test_nested_and_colliding_spans_round_trip(text):
    red, mapping = R.redact(text)
    assert R.restore(red, mapping) == text
    for original in mapping.values():
        assert "#" + R.map_nonce(mapping) + "]" not in original


def test_a_url_holding_an_email_is_one_span():
    red, mapping = R.redact("see https://" + "a@b" + ".example.com/path")
    assert list(mapping.values()) == ["https://" + "a@b" + ".example.com/path"]


def test_the_nonce_never_occurs_in_the_input(monkeypatch):
    """If the first nonce drawn already appears in the text, draw again."""
    draws = iter(["aaaaaa", "bbbbbb"])
    monkeypatch.setattr(R.secrets, "token_hex", lambda n: next(draws))
    red, mapping = R.redact("odd text [X_1#aaaaaa] and " + "q@r" + ".example.net")
    assert R.map_nonce(mapping) == "bbbbbb"
    assert R.restore(red, mapping) == "odd text [X_1#aaaaaa] and " + "q@r" + ".example.net"


def test_redacting_already_redacted_text_with_its_own_map_is_refused():
    red, mapping = R.redact("mail " + "a@b" + ".example.com")
    with pytest.raises(ValueError, match="already contains placeholders"):
        R.redact(red, mapping)


@pytest.mark.parametrize("bad", [
    {"[EMAIL_1]": "a@example.com"},                      # no nonce
    {"[EMAIL_1#a1b2c3]": 5},                             # value not a string
    {"[NOPE_1#a1b2c3]": "x"},                            # unknown kind
    {"[EMAIL_1#a1b2c3]": "a", "[EMAIL_2#ffffff]": "b"},  # mixed nonces
    {"hello": "x"},
])
def test_a_malformed_map_is_refused(bad):
    with pytest.raises(ValueError):
        R.restore("text", bad)
    with pytest.raises(ValueError):
        R.redact("text", bad)


def test_an_empty_map_refuses_a_nonce_placeholder():
    with pytest.raises(KeyError, match="empty map"):
        R.restore("see [PHONE_3#a1b2c3] now", {})


def test_an_empty_map_leaves_ordinary_bracket_text_alone():
    assert R.restore("see [PHONE_3] now", {}) == "see [PHONE_3] now"


# ── an address-literal domain is part of the email ─────────────────────

@pytest.mark.parametrize("addr", [
    "john.doe@[192.0.2.1]",
    "user@[IPv6:2001:db8::1]",
    "user@[ipv6:2001:db8::1]",
    "user@[IPv6:::ffff:192.0.2.1]",
])
@pytest.mark.parametrize("nl", ["\n", "\r\n", "\r"])
def test_email_with_address_literal_domain_is_one_email_span(addr, nl):
    from cti_report_lint.redact import redact, restore
    text = f"Contact {addr}, then ({addr}).{nl}Next{nl}"
    out, mapping = redact(text)
    assert "[EMAIL_1#" in out and "EMAIL_2" not in out
    assert mapping and list(mapping.values()) == [addr]
    local = addr.split("@")[0]
    assert local not in out and "192.0.2" not in out and "2001:db8" not in out
    assert "IPV4" not in out and "IPV6" not in out
    assert restore(out, mapping) == text


def test_bracketed_ip_without_a_local_part_is_still_an_ip():
    from cti_report_lint.redact import redact
    out, _ = redact("seen at [192.0.2.1] and x @ [192.0.2.2]")
    assert "[IPV4_1#" in out
