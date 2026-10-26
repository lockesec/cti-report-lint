"""Invisible format and bidi characters inside a sensitive value must not hide
it from redaction, and the round trip must stay byte-exact."""
from __future__ import annotations

import random

import pytest

from cti_report_lint import redact as R

# One character per listed class, plus the ones a reviewer named.
INVISIBLES = [
    "­", "͏", "؜", "᠋", "᠎", "​", "‌",
    "‍", "‎", "‏", "‪", "‫", "‬", "‭",
    "‮", "⁠", "⁡", "⁢", "⁣", "⁤", "⁦",
    "⁧", "⁨", "⁩", "⁪", "︀", "️", "﻿",
    "￹", "\U000e0001", "\U000e0020", "\U000e0100",
]

# (kind, value with a '|' marking the place the invisible goes)
HOSTS = [
    ("EMAIL", "bob@exam|ple.com"),
    ("EMAIL", "bo|b@example.com"),
    ("IPV4", "192.0.|2.1"),
    ("IPV4", "198.51|.100.9"),
    ("IPV6", "2001:db8|::1"),
    ("IPV6", "fe80::|1"),
    ("URL", "https://exa|mple.com/a?b=1"),
    ("PHONE", "+1 (555) 23|4-5678"),
    ("PHONE", "+44 20 7946 |0958"),
]


@pytest.mark.parametrize("nl", ["\n", "\r\n", "\r"])
@pytest.mark.parametrize("c", INVISIBLES, ids=lambda c: f"U+{ord(c):04X}")
@pytest.mark.parametrize("kind,host", HOSTS)
def test_invisible_char_inside_value_is_redacted_and_restored(kind, host, c, nl):
    value = host.replace("|", c)
    text = f"first{nl}see {value} end{nl}"
    red, m = R.redact(text)
    assert value not in red
    assert [k for k in m if k.startswith(f"[{kind}_")], (kind, red)
    assert any(v == value for v in m.values())
    assert R.restore(red, m) == text


def test_invisible_set_is_documented_classes():
    import unicodedata
    for c in INVISIBLES:
        assert R._INVISIBLE_RE.match(c), hex(ord(c))
    # visible prefix marks are NOT treated as invisible
    for c in ("؀", "۝", "܏", "࣢"):
        assert unicodedata.category(c) == "Cf" and not R._INVISIBLE_RE.match(c)


def fuzz_inv(rng: random.Random) -> str:
    kinds = ["2001:db8::1", "203.0.113.7", "soc@acme.example", "https://x.example/a",
             "+1 (555) 234-5678", "198.51.100.9", "word", "DE89370400440532013000"]
    seps = ["-", ",", " ", "\n", "\r\n", "\r", "; "]
    out = []
    for _ in range(rng.randint(1, 6)):
        k = rng.choice(kinds)
        if rng.random() < 0.6:
            i = rng.randrange(len(k) + 1)
            k = k[:i] + rng.choice(INVISIBLES) + k[i:]
        out.append(k + rng.choice(seps))
    return "".join(out)


def test_fuzz_invisible_round_trip_seeded():
    rng = random.Random(20261016)
    for _ in range(1500):
        t = fuzz_inv(rng)
        red, m = R.redact(t)
        assert R.restore(red, m) == t


