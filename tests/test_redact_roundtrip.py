"""Redaction round trips under adjacency (zone ids, mixed separators), and the
CLI refusing to write when the round trip or the span invariant fails."""
from __future__ import annotations

import random

import pytest

from cti_report_lint import cli
from cti_report_lint import redact as R

ZONE_CASES = [
    "range fe80::1%eth0-2001:db8::1 end\n",
    "fe80::1%eth0-fe80::1%eth0",
    "fe80::1%eth0.2001:db8::1",
    "fe80::1%a-fe80::1%b-fe80::1%c",
]


@pytest.mark.parametrize("text", ZONE_CASES)
def test_zone_round_trip(text):
    red, m = R.redact(text)
    assert R.restore(red, m) == text
    spans = R.find_spans(text)
    assert all(a[1] <= b[0] for a, b in zip(spans, spans[1:]))


def test_zone_keeps_hyphenated_name():
    t = "addr fe80::1%eth0-1 here"
    assert R.find_spans(t)[0][:2] == (5, 19)


def test_cli_refuses_when_roundtrip_fails(tmp_path, monkeypatch, capsys):
    src = tmp_path / "a.md"
    src.write_text("hello 203.0.113.7\n")
    monkeypatch.setattr(R, "restore", lambda t, m: "wrong")
    rc = cli.main(["redact", str(src), "--map", str(tmp_path / "m.json"),
                   "-o", str(tmp_path / "o.md")])
    assert rc == 2
    assert "would not restore byte-exact; nothing written" in capsys.readouterr().err
    assert not (tmp_path / "o.md").exists() and not (tmp_path / "m.json").exists()


def fuzz_case(rng: random.Random) -> str:
    kinds = ["fe80::1%eth0", "fe80::1%a", "2001:db8::1", "::1", "203.0.113.7",
             "soc@acme.example", "https://x.example/a?b=1", "+1 (555) 234-5678",
             "john@[192.0.2.1]", "[2001:db8::1]:443", "198.51.100.9/24", "word", "2026-01-02",
             "CVE-2024-1234", "a1b2", "eth0", "::", "1:2:3:4:5:6:7:8"]
    seps = ["-", ".", "%", ",", "/", "", " ", ":", "\n", "\r\n", "\r", "; "]
    return "".join(rng.choice(kinds) + rng.choice(seps)
                   for _ in range(rng.randint(1, 8)))


def test_fuzz_round_trip_seeded():
    rng = random.Random(20261015)
    for _ in range(1500):
        t = fuzz_case(rng)
        red, m = R.redact(t)
        assert R.restore(red, m) == t, repr(t)



def test_cli_overlap_assertion_is_a_refusal(tmp_path, monkeypatch, capsys):
    src = tmp_path / "a.md"
    src.write_text("hello 203.0.113.7\n")

    def boom(text):
        raise AssertionError("overlapping spans 0:5 and 3")
    monkeypatch.setattr(R, "find_spans", boom)
    rc = cli.main(["redact", str(src), "--map", str(tmp_path / "m.json"),
                   "-o", str(tmp_path / "o.md")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "would not restore byte-exact; nothing written" in err
    assert "Traceback" not in err
    assert not (tmp_path / "o.md").exists() and not (tmp_path / "m.json").exists()
