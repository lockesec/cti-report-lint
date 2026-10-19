"""Redaction in the contexts reports actually use.

Property-style: every sensitive value, wrapped in every Markdown and log
context, at every line position and with every newline convention, must be
absent from the redacted text AND come back byte for byte on restore. Each
leak found in adversarial review was a single cell of this grid.

Secret-looking sample values are assembled from fragments so that secret
scanners do not flag this file.
"""
from __future__ import annotations

import time

import pytest

from cti_report_lint import redact as R
from cti_report_lint.redact import redact, restore

IBAN_DE = "DE89" + "3704" + "0044" + "0532" + "0130" + "00"
IBAN_GB = "GB29" + "NWBK" + "6016" + "1331" + "926819"
BECH32 = "bc1q" + "ar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
B58_P2PKH = "1BvBM" + "SEYstWetqTFn5Au4m4GFg7xJaNVN2"
B58_P2SH = "3J98t1" + "WpEZ73CNmQviecrnyiWrnqRhWNLy"

VALUES = {
    "EMAIL": ["soc" + "@acme.example", "first.last+tag" + "@mail.example.org"],
    "IPV4": ["203.0.113.7", "198.51.100.254"],
    "IPV6": ["2001:db8::7", "fe80::1", "2001:db8::", "2001:db8:1:2:3:4:5:6",
             "::ffff:192.0.2.1", "fe80::7%eth0"],
    "IBAN": [IBAN_DE, IBAN_GB, "DE89 3704 0044 0532 0130 00", IBAN_DE.lower()],
    "BTC": [BECH32, BECH32.upper(), B58_P2PKH, B58_P2SH],
    "PHONE": ["+1 (555) 234-5678", "202-555-0143"],
    "URL": ["https://panel.example/login", "HTTPS://evil.example/secret",
            "hxxps://evil[.]example/p", "ftp://files.example/x",
            "https://evil.example/a_(b)/c", "www.evil.example/login"],
}

CONTEXTS = [
    "{}", "_{}_", "*{}*", "**{}**", "`{}`", "[{}]", "({})", "<{}>",
    "| {} |", "> {}", "key:{}", "key: {}", "key={}", "path/{}", "x.{}",
    "host_{}", "\"{}\"", "'{}'", "{}.", "{},",
]

LINES = ["seen {} here", "{}\n", "\n{}", "{}\r\n", "a\r\n{}\r\nb", "\r{}\r",
         "a\n{}\r\nb\rc"]


def _cells():
    for kind, vals in VALUES.items():
        for v in vals:
            for ctx in CONTEXTS:
                for line in LINES:
                    yield kind, v, line.replace("{}", ctx.replace("{}", v))


@pytest.mark.parametrize("kind,value,text", list(_cells()))
def test_value_is_redacted_and_round_trips(kind, value, text):
    red, mapping = R.redact(text)
    assert value not in red, f"{kind} leaked in {text!r}: {red!r}"
    assert R.restore(red, mapping) == text


@pytest.mark.parametrize("text", [
    "addr:2001:db8::1", "IPv6:2001:db8:1:2:3:4:5:6", "x.2001:db8::1",
    "Received: from mx ([IPv6:2001:db8::1])", "addr:fe80::1",
    "src_2001:db8::1", "_fe80::7%eth0_",
])
def test_ipv6_after_a_colon_dot_or_tag(text):
    red, mapping = R.redact(text)
    assert "IPV6" in red
    for core in ("2001:db8", "fe80::"):
        assert core not in red
    assert R.restore(red, mapping) == text


@pytest.mark.parametrize("text,kept", [
    ("host 2001:db8:: up", "host "), ("fe80:: x", " x"),
    ("route 2001:db8::/32", "/32"), ("route fe80::/10", "/10"),
    ("default ::/0", "/0"), ("bind [::]", "bind ["),
])
def test_ipv6_trailing_compression_and_cidr(text, kept):
    red, mapping = R.redact(text)
    assert "IPV6" in red and kept in red
    assert "2001:db8" not in red and "fe80" not in red
    assert R.restore(red, mapping) == text


@pytest.mark.parametrize("text", [
    "at 12:30:45 UTC", "std::vector and Foo::bar", "MAC aa:bb:cc:dd:ee:ff",
    "ratio 3:2:1", "Namespace :: Thing", "deadbeef::cafe::1", "Foo::Bar::baz",
])
def test_ipv6_look_alikes_survive(text):
    red, mapping = R.redact(text)
    assert red == text and not mapping


@pytest.mark.parametrize("text,kept,phone", [
    ("2026-09-24 202-555-0143 called", "2026-09-24", "202-555-0143"),
    ("CVE-2024-12345 202 555 0143", "CVE-2024-12345", "202 555 0143"),
    ("CVE-2024-1234\n202-555-0143", "CVE-2024-1234", "202-555-0143"),
    ("2026-09-24T10:00Z 202-555-0143", "2026-09-24", "202-555-0143"),
])
def test_a_date_or_identifier_does_not_hide_the_phone_after_it(text, kept, phone):
    red, mapping = R.redact(text)
    assert kept in red
    assert phone not in red and "PHONE" in red
    assert R.restore(red, mapping) == text


@pytest.mark.parametrize("text", [
    "on 2026-09-24", "CVE-2024-12345", "see KB5031234", "on 25.09.2026",
    "EDB-ID-51234 and GHSA-abcd-1234-efgh",
])
def test_dates_and_identifiers_are_kept(text):
    red, mapping = R.redact(text)
    assert red == text and not mapping


@pytest.mark.parametrize("text", [
    "md5 1b2c3d4e5f6a7b8c9d1e2f3a4b5c6d7e",       # base58-shaped, bad checksum
    "id DE00370400440532013000",                   # IBAN-shaped, bad mod-97
    "hash ab12cdef34567890abcdef12",               # lowercase, bad mod-97
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx",  # bech32, bad checksum
])
def test_checksummed_kinds_need_a_valid_checksum(text):
    red, mapping = R.redact(text)
    assert red == text and not mapping


def test_iban_spaced_form_is_one_iban_span():
    text = "IBAN DE89 3704 0044 0532 0130 00 then"
    red, mapping = R.redact(text)
    assert red.startswith("IBAN [IBAN_1#") and red.endswith("] then")
    assert R.restore(red, mapping) == text


@pytest.mark.parametrize("text,leak", [
    ("bob​@example.com", "example.com"),
    ("2001:db8::​1", "2001:db8"),
    ("josé@example.com", "example.com"),
    ("bob@bücher.example", "bücher"),
    ("bob" + "@example." + "xn--p1ai", "xn--p1ai"),  # IDN TLD, assembled
])
def test_unicode_and_zero_width_forms(text, leak):
    red, mapping = R.redact(text)
    assert leak not in red, red
    assert R.restore(red, mapping) == text


def test_markdown_link_keeps_its_brackets():
    text = "[panel](https://panel.example/login) and **https://b.example/x**."
    red, mapping = R.redact(text)
    assert red.startswith("[panel]([URL_1#") and ") and **[URL_2#" in red
    assert red.endswith("]**.")
    assert R.restore(red, mapping) == text


# --- foreign placeholders ------------------------------------------------

def test_restore_refuses_placeholders_from_another_map():
    red_a, map_a = R.redact("mail a" + "@x.example")
    red_b, map_b = R.redact("mail b" + "@y.example")
    assert R.map_nonce(map_a) != R.map_nonce(map_b)
    with pytest.raises(KeyError, match=R.map_nonce(map_b)):
        R.restore(red_a + red_b, map_a)


def test_a_placeholder_quoted_in_the_original_still_round_trips():
    """A report ABOUT redaction may quote a placeholder of another map. It is
    itself redacted, so restore never meets a bare foreign placeholder."""
    text = "the tool writes [EMAIL_1#abcdef] for c" + "@z.example"
    red, mapping = R.redact(text)
    assert "#abcdef]" not in red
    assert R.restore(red, mapping) == text


# --- linear time ---------------------------------------------------------

_N = 65536
ADVERSARIAL = {
    "colons": ":" * _N + "g",
    "hex-colon": "a:" * (_N // 2) + "g",
    "hex-colon-dot": "a:1." * (_N // 4) + "g",
    "double-colon": "1::" * (_N // 3),
    "digits-spaces": "1 " * (_N // 2) + "a",
    "digits-dashes": "1-" * (_N // 2) + "a",
    "digits": "1" * _N + "a",
    "dotted": "1." * (_N // 2) + "x",
    "letters": "a" * _N,
    "email-local": "a." * (_N // 2) + "@",
    "email-domain": "a@" + "b." * (_N // 2),
    "url": "http://" + "(" * _N,
    "iban-groups": "DE89" + " ABCD" * (_N // 5),
    "base58": "1" + "a" * _N,
    "underscores": "_" * _N,
    "zero-width": "​" * _N,
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_redaction_is_linear_on_adversarial_input(name):
    text = ADVERSARIAL[name]
    t0 = time.perf_counter()
    red, mapping = R.redact(text)
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.5, f"{name}: {elapsed:.2f}s for {len(text)} chars"
    assert R.restore(red, mapping) == text


# --- hyphen-grouped IBAN ---------------------------------------------------

@pytest.mark.parametrize("nl", ["\n", "\r\n", "\r"])
def test_hyphen_grouped_iban_is_one_span(nl):
    t = f"acct DE89-3704-0044-0532-0130-00 ok{nl}"
    red, m = R.redact(t)
    assert "DE89" not in red and "3704" not in red
    assert list(m.values()) == ["DE89-3704-0044-0532-0130-00"]
    assert list(m)[0].startswith("[IBAN_")
    assert R.restore(red, m) == t


def test_hyphen_iban_checksum_still_required():
    t = "ref DE89-3704-0044-0532-0130-01 x"
    assert not [k for k in R.redact(t)[1] if k.startswith("[IBAN_")]



# --- trailing punctuation after IPv6 ---------------------------------------


@pytest.mark.parametrize("dots", [0, 1, 3, 4, 5, 50, 500])
@pytest.mark.parametrize("addr", ["2001:db8::1", "fe80::1", "2001:db8:0:0:0:0:0:1",
                                  "::ffff:192.0.2.1"])
def test_ipv6_found_under_any_trailing_period_run(addr, dots):
    text = f"Address: {addr}{'.' * dots}"
    red, mapping = redact(text)
    assert addr not in red
    assert restore(red, mapping) == text


def test_bare_double_colon_still_prose():
    for text in ("see:: this....", "a :: b", "x::...."):
        red, _ = redact(text)
        assert "IPV6" not in red or text.startswith("x")


def test_long_punctuation_run_is_bounded():
    import time
    t = time.time()
    redact("2001:db8::1" + "." * 20000)
    assert time.time() - t < 2
